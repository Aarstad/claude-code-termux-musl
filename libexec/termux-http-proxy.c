// High-performance, zero-copy HTTP/CONNECT proxy for Android/musl environments.
//
// Background:
// musl libc resolves names via /etc/resolv.conf, which Android environments lack.
// Consequently, DNS resolution inside musl-linked processes fails (timing out
// rather than failing immediately). This daemon is compiled against Android's
// native Bionic libc where system DNS resolution is fully functional, enabling
// musl processes to route outbound network traffic through a local tunnel.
//
// Lifecycle:
// Without a port, binds a dynamic loopback port, prints it to stdout and runs until
// the parent process exits. With a port it runs as a shared daemon (-f keeps it in
// the foreground for a supervisor such as runit).
//
// Architecture & Concurrency:
// Designed as an efficient C replacement for runtime-heavy proxy scripts:
// - Single-threaded event loop driven by epoll(7). Nothing in the loop blocks:
//   names are resolved with Android's asynchronous resolver (resNetworkQuery),
//   whose answers arrive on file descriptors polled like any socket, and upstream
//   connects are non-blocking with per-address deadlines.
// - Zero-copy kernel-space data forwarding between sockets using splice(2) and pipes.
// - Minimal userspace memory overhead: dynamic allocations are restricted to
//   ephemeral header parsing buffers and lightweight connection descriptors.
//
// Security:
// Android's loopback interface is shared by every app on the device, so any app can
// reach this port. --auth-file makes the proxy require the token in that file
// (Proxy-Authorization: Basic, any username) before it resolves or dials anything.
//
// Compilation:
//   cc -O2 -o termux-http-proxy termux-http-proxy.c
//
// Built entirely on standard Linux/Bionic interfaces without third-party dependencies.

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

// Maximum request header buffer size. Requests exceeding this threshold
// before completing the header block are rejected to prevent memory exhaustion.
#define REQ_MAX 16384
// Maximum duration a connection may spend sending its request line and headers,
// mitigating slowloris-style idle stalls.
#ifndef HEADER_TIMEOUT_MS
#define HEADER_TIMEOUT_MS 30000
#endif
// Budget for resolving a name. If one address family has answered by then, the
// proxy dials what it has rather than failing.
#ifndef DNS_TIMEOUT_MS
#define DNS_TIMEOUT_MS 10000
#endif
// Once one address family has answered with addresses, how long to wait for the
// other before dialing what we have (RFC 8305's Resolution Delay). A slow or
// dropped AAAA query then costs 50ms rather than the whole DNS budget.
#ifndef RESOLUTION_DELAY_MS
#define RESOLUTION_DELAY_MS 50
#endif
// Budget for connecting upstream, shared across all resolved addresses.
#ifndef CONNECT_TIMEOUT_MS
#define CONNECT_TIMEOUT_MS 5000
#endif
#ifndef WRITE_TIMEOUT_MS
#define WRITE_TIMEOUT_MS 5000
#endif
// Pipe capacity for splice(). 64KB aligns with Linux default unprivileged pipe capacity.
#define PIPE_CAP 65536
// Maximum file descriptor ceiling for connection tracking.
// Each bidirectional tunnel consumes 6 fds (client socket, upstream socket, and
// two unidirectional pipes). Accounting for fixed infrastructure descriptors
// (epoll, stdin, timerfd, listener), this supports ~85 concurrent tunnels.
#define MAX_FDS 512
// Addresses kept per name; more than enough for any real A + AAAA answer.
#define MAX_ADDRS 16
#define TOKEN_MAX 256

// DNS wire-format constants used with resNetworkQuery.
#define NS_C_IN 1
#define NS_T_A 1
#define NS_T_AAAA 28
#define NS_RCODE_NXDOMAIN 3

enum { ST_HEADER, ST_RESOLVE, ST_DIAL, ST_TUNNEL };

// Everything needed to get from a parsed request to a connected upstream socket.
// Allocated after the headers are parsed and freed once the tunnel starts, so an
// established tunnel carries none of it.
struct setup {
  char host[256];
  uint16_t port;
  int is_connect;
  char *out;          // Bytes to send upstream once connected (rewritten request / early payload)
  int out_len;
  int dns_fd[2];      // Outstanding A and AAAA queries (-1 when answered or not issued)
  int dns_left;
  struct sockaddr_storage addr[MAX_ADDRS];
  socklen_t addr_len[MAX_ADDRS];
  int naddr;
  int next;           // Index of the next address to try
  int dial_fd;        // Non-blocking connect in progress (-1 when none)
  int64_t dial_deadline; // Overall connect budget across addresses
  int dial_timed_out; // An attempt ran out of time (504 rather than 502 if all fail)
};

// State tracking for an individual connection and its upstream peer.
// An active tunnel consists of two cross-referenced struct conn instances,
// each owning a pipe handling unidirectional data transfer.
struct conn {
  int fd;             // Connection socket descriptor
  int peer;           // Paired upstream or downstream fd (-1 if unlinked)
  int state;          // Current protocol state (ST_*)
  int pipe_r, pipe_w; // Intermediate pipe for zero-copy splice() routing (fd -> peer)
  int inflight;       // Bytes queued in pipe awaiting consumption by peer socket
  int fd_eof;         // Inbound EOF received; pending pipe data must be drained
  int want_out;       // Backpressure flag: peer socket buffer is saturated
  char *req;          // Ephemeral request header buffer (allocated during ST_HEADER only)
  int req_len;        // Bytes currently buffered in req
  int in_setup;       // Client connection not yet tunnelling; counted in n_setup
  int64_t deadline;   // When the current setup phase (or attempt) expires
  struct setup *su;   // Resolve/dial state; NULL outside ST_RESOLVE and ST_DIAL
};

static struct conn *conns[MAX_FDS];
// Resolver and dialing descriptors, mapped to the client connection that owns them.
static struct conn *owner[MAX_FDS];
static int epfd;
static int n_setup; // Connections with a pending deadline; 0 lets epoll sleep indefinitely

static char auth_token[TOKEN_MAX];
static size_t auth_len; // 0 when authentication is disabled

// ---- small helpers -------------------------------------------------------------------

static void set_nonblock(int fd) {
  int f = fcntl(fd, F_GETFL, 0);
  if (f >= 0) fcntl(fd, F_SETFL, f | O_NONBLOCK);
}

static int64_t monotonic_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int wait_writable(int fd, int64_t deadline) {
  for (;;) {
    int64_t remaining = deadline - monotonic_ms();
    if (remaining <= 0) { errno = ETIMEDOUT; return 0; }
    struct pollfd pf = { .fd = fd, .events = POLLOUT };
    int rc = poll(&pf, 1, (int)remaining);
    if (rc > 0) return !(pf.revents & POLLNVAL);
    if (rc == 0) { errno = ETIMEDOUT; return 0; }
    if (errno != EINTR) return 0;
  }
}

// Handles partial writes on non-blocking sockets. Because these writes occur
// exclusively during handshake/setup prior to zero-copy splicing, a brief synchronous
// poll is cleaner and safer than allocating per-connection write queues.
// Returns 1 on success, 0 on peer disconnect or timeout.
static int write_all(int fd, const char *buf, size_t len) {
  size_t off = 0;
  int64_t deadline = monotonic_ms() + WRITE_TIMEOUT_MS;
  while (off < len) {
    if (monotonic_ms() >= deadline) { errno = ETIMEDOUT; return 0; }
    ssize_t w = write(fd, buf + off, len - off);
    if (w > 0) { off += (size_t)w; continue; }
    if (w < 0 && errno == EINTR) continue;
    if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      if (!wait_writable(fd, deadline)) return 0;
      continue;
    }
    return 0;
  }
  return 1;
}

// A zero-timeout readiness check. Guards handlers against stale epoll events for a
// descriptor number that was closed and reused earlier in the same batch.
static int ready(int fd, short events) {
  struct pollfd pf = { .fd = fd, .events = events };
  return poll(&pf, 1, 0) > 0 && !(pf.revents & POLLNVAL);
}

static void ep_add(int fd, uint32_t events) {
  struct epoll_event ev = {0};
  ev.events = events;
  ev.data.fd = fd;
  epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
}

static struct conn *conn_get(int fd) {
  return (fd >= 0 && fd < MAX_FDS) ? conns[fd] : NULL;
}

static struct conn *conn_new(int fd) {
  if (fd < 0 || fd >= MAX_FDS) return NULL;
  struct conn *c = calloc(1, sizeof *c);
  if (!c) return NULL;
  c->fd = fd;
  c->peer = -1;
  c->pipe_r = c->pipe_w = -1;
  c->state = ST_HEADER;
  conns[fd] = c;
  return c;
}

// ---- Asynchronous resolver -----------------------------------------------------------

// Android's asynchronous DNS API (API 29+). It goes through the system resolver like
// getaddrinfo does, so it honours Private DNS and per-network servers, but it returns
// a file descriptor that becomes readable when the answer arrives.
//
// The public entry point is android_res_nquery in libandroid.so, but that is only a
// 40-byte wrapper around resNetworkQuery in libnetd_client.so, and loading libandroid
// drags in its whole dependency tree: ~1,200 mappings and 45MB RSS against 3MB. libc
// already has libnetd_client loaded for getaddrinfo, so dlopen'ing it costs nothing.
// (A bare dlopen("libandroid.so") would also find Termux's libandroid-stub first.)
typedef int (*res_nquery_fn)(unsigned netid, const char *dname, int ns_class, int ns_type,
                             uint32_t flags);
typedef int (*res_nresult_fn)(int fd, int *rcode, uint8_t *answer, size_t anslen);
typedef void (*res_cancel_fn)(int fd);

// Resolved at startup with dlsym, so the binary still builds for (and runs on) API
// levels without them; the loop then falls back to blocking getaddrinfo. Tests may
// install their own implementations before the loop starts.
static res_nquery_fn res_nquery;
static res_nresult_fn res_nresult;
static res_cancel_fn res_cancel;

static void resolver_init(void) {
  if (res_nquery) return;
  void *h = dlopen("libnetd_client.so", RTLD_NOW | RTLD_LOCAL);
  if (!h) return;
  // Assigned through void ** as POSIX recommends: ISO C has no cast from an object
  // pointer to a function pointer.
  res_nquery_fn q;
  res_nresult_fn r;
  res_cancel_fn x;
  *(void **)&q = dlsym(h, "resNetworkQuery");
  *(void **)&r = dlsym(h, "resNetworkResult");
  *(void **)&x = dlsym(h, "resNetworkCancel");
  if (q && r && x) {
    res_nquery = q;
    res_nresult = r;
    res_cancel = x;
    return;
  }
  dlclose(h);
}

static void add_addr(struct setup *su, const struct sockaddr *sa, socklen_t len) {
  if (su->naddr >= MAX_ADDRS || len > sizeof su->addr[0]) return;
  memcpy(&su->addr[su->naddr], sa, len);
  su->addr_len[su->naddr] = len;
  su->naddr++;
}

static void add_ipv4(struct setup *su, const void *bytes) {
  struct sockaddr_in sin = {0};
  sin.sin_family = AF_INET;
  sin.sin_port = htons(su->port);
  memcpy(&sin.sin_addr, bytes, 4);
  add_addr(su, (struct sockaddr *)&sin, sizeof sin);
}

static void add_ipv6(struct setup *su, const void *bytes) {
  struct sockaddr_in6 sin6 = {0};
  sin6.sin6_family = AF_INET6;
  sin6.sin6_port = htons(su->port);
  memcpy(&sin6.sin6_addr, bytes, 16);
  add_addr(su, (struct sockaddr *)&sin6, sizeof sin6);
}

// Advances past a (possibly compressed) domain name. Returns the offset after it,
// or -1 if the name runs off the end of the message.
static int skip_name(const uint8_t *msg, int len, int off) {
  while (off < len) {
    uint8_t b = msg[off];
    if (b == 0) return off + 1;
    if ((b & 0xC0) == 0xC0) return off + 2 <= len ? off + 2 : -1;
    if (b & 0xC0) return -1; // Reserved label types
    off += 1 + b;
  }
  return -1;
}

// Collects the A or AAAA records from a DNS response. CNAME records are skipped:
// a recursive resolver returns the chain and its final addresses in one answer.
// Returns the number of addresses added.
static int parse_answer(const uint8_t *msg, int len, int type, struct setup *su) {
  if (len < 12) return 0;
  int qd = msg[4] << 8 | msg[5];
  int an = msg[6] << 8 | msg[7];
  int off = 12, added = 0;
  for (int i = 0; i < qd; i++) {
    off = skip_name(msg, len, off);
    if (off < 0 || off + 4 > len) return added;
    off += 4;
  }
  for (int i = 0; i < an; i++) {
    off = skip_name(msg, len, off);
    if (off < 0 || off + 10 > len) return added;
    int rtype = msg[off] << 8 | msg[off + 1];
    int rclass = msg[off + 2] << 8 | msg[off + 3];
    int rdlen = msg[off + 8] << 8 | msg[off + 9];
    off += 10;
    if (off + rdlen > len) return added;
    if (rclass == NS_C_IN && rtype == type) {
      int before = su->naddr;
      if (type == NS_T_A && rdlen == 4) add_ipv4(su, msg + off);
      if (type == NS_T_AAAA && rdlen == 16) add_ipv6(su, msg + off);
      added += su->naddr - before;
    }
    off += rdlen;
  }
  return added;
}

// Literal addresses and "localhost" need no lookup. Returns 1 if handled.
static int add_literal(struct setup *su) {
  uint8_t buf[16];
  if (inet_pton(AF_INET, su->host, buf) == 1) { add_ipv4(su, buf); return 1; }
  if (inet_pton(AF_INET6, su->host, buf) == 1) { add_ipv6(su, buf); return 1; }
  if (strcasecmp(su->host, "localhost") == 0) {
    inet_pton(AF_INET, "127.0.0.1", buf);
    add_ipv4(su, buf);
    inet_pton(AF_INET6, "::1", buf);
    add_ipv6(su, buf);
    return 1;
  }
  return 0;
}

// Used only where resNetworkQuery is unavailable (API < 29, or not Android).
static void resolve_blocking(struct setup *su) {
  struct addrinfo hints, *res, *ai;
  char port[8];
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  snprintf(port, sizeof port, "%u", su->port);
  if (getaddrinfo(su->host, port, &hints, &res) != 0) return;
  for (ai = res; ai; ai = ai->ai_next) add_addr(su, ai->ai_addr, ai->ai_addrlen);
  freeaddrinfo(res);
}

// Releases the resolve/dial state, cancelling any query or connect still in flight.
static void setup_free(struct setup *su) {
  if (!su) return;
  for (int i = 0; i < 2; i++) {
    int fd = su->dns_fd[i];
    if (fd < 0) continue;
    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
    owner[fd] = NULL;
    res_cancel(fd); // Closes the descriptor
  }
  if (su->dial_fd >= 0) {
    epoll_ctl(epfd, EPOLL_CTL_DEL, su->dial_fd, NULL);
    owner[su->dial_fd] = NULL;
    close(su->dial_fd);
  }
  free(su->out);
  free(su);
}

static void leave_setup(struct conn *c) {
  if (!c->in_setup) return;
  c->in_setup = 0;
  n_setup--;
}

// Teardown routine: closes descriptors and frees associated resources for both
// endpoints of a tunnel. Orderly half-close states are handled in pump().
static void conn_close(struct conn *c) {
  if (!c) return;
  int fd = c->fd;
  struct conn *p = conn_get(c->peer);
  if (p) p->peer = -1;
  leave_setup(c);
  setup_free(c->su);
  c->su = NULL;
  epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
  if (c->pipe_r >= 0) close(c->pipe_r);
  if (c->pipe_w >= 0) close(c->pipe_w);
  free(c->req);
  close(fd);
  conns[fd] = NULL;
  free(c);
  if (p) conn_close(p);
}

static void ep_update(struct conn *c) {
  struct conn *p = conn_get(c->peer);
  struct epoll_event ev = {0};
  ev.data.fd = c->fd;
  // Suspend read and half-close monitoring while outbound pipe backpressure exists.
  // Level-triggered epoll will resume notifications once outbound capacity clears.
  if (!c->fd_eof && !c->want_out) ev.events |= EPOLLIN | EPOLLRDHUP;
  if (p && p->want_out) ev.events |= EPOLLOUT;
  epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev);
}

static void ep_mod(struct conn *c) {
  ep_update(c);
  struct conn *p = conn_get(c->peer);
  if (p) ep_update(p);
}

// ---- Tunnel Pipeline -----------------------------------------------------------------

// Zero-copy transfer from c->fd to c->peer via Linux splice(2).
// Data streams directly through kernel pipe buffers without traversing userspace memory.
// Returns 0 if the connection should be terminated, 1 if operational.
static int pump(struct conn *c) {
  struct conn *p = conn_get(c->peer);
  if (!p) return 0;

  for (;;) {
    // Flush remaining bytes buffered in the intermediate pipe from earlier partial splices.
    while (c->inflight > 0) {
      ssize_t w = splice(c->pipe_r, NULL, p->fd, NULL, c->inflight,
                         SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
      if (w > 0) { c->inflight -= (int)w; continue; }
      if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        // Upstream/downstream socket buffer saturated; apply backpressure to inbound side.
        c->want_out = 1;
        ep_mod(c);
        return 1;
      }
      if (w < 0 && errno == EINTR) continue;
      return 0; // Socket closed or reset (e.g. EPIPE)
    }
    if (c->want_out) { c->want_out = 0; ep_mod(c); }

    // Pipe drained. If inbound side signaled EOF, perform half-close on peer socket.
    // Terminate connection if both directions have completed.
    if (c->fd_eof) {
      shutdown(p->fd, SHUT_WR);
      return (p->fd_eof && p->inflight == 0) ? 0 : 1;
    }

    // Splice inbound data from socket into pipe.
    ssize_t r = splice(c->fd, NULL, c->pipe_w, NULL, PIPE_CAP,
                       SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    if (r > 0) { c->inflight += (int)r; continue; }
    if (r == 0) { c->fd_eof = 1; ep_mod(c); continue; } // EOF received; flush pipe above
    if (errno == EAGAIN || errno == EWOULDBLOCK) return 1;
    if (errno == EINTR) continue;
    return 0;
  }
}

// ---- Connection Setup ----------------------------------------------------------------

static void fail_with(struct conn *c, const char *status, const char *extra) {
  char buf[256];
  int n = snprintf(buf, sizeof buf, "HTTP/1.1 %s\r\n%sConnection: close\r\n\r\n", status,
                   extra ? extra : "");
  (void)write_all(c->fd, buf, (size_t)n); // Best effort notification prior to teardown
  conn_close(c);
}

static void fail(struct conn *c, const char *status) {
  fail_with(c, status, NULL);
}

// Allocates and attaches an intermediate pipe to enable splice(2) operations on this connection.
static int arm(struct conn *c) {
  int pfd[2];
  if (pipe2(pfd, O_NONBLOCK | O_CLOEXEC) < 0) return -1;
  fcntl(pfd[0], F_SETPIPE_SZ, PIPE_CAP);
  c->pipe_r = pfd[0];
  c->pipe_w = pfd[1];
  c->state = ST_TUNNEL;
  return 0;
}

static void start_tunnel(struct conn *c, int ufd, const char *reply, const char *head,
                         int head_len) {
  struct conn *u = conn_new(ufd);
  if (!u) { close(ufd); fail(c, "500 Internal Server Error"); return; }

  if (arm(c) < 0 || arm(u) < 0) {
    c->peer = -1;
    conn_close(u);
    fail(c, "500 Internal Server Error");
    return;
  }
  c->peer = ufd;
  u->peer = c->fd;

  if (reply && !write_all(c->fd, reply, strlen(reply))) { conn_close(c); return; }
  // Forward any early body/pipelined payload buffered alongside the initial request headers.
  if (head_len > 0 && !write_all(ufd, head, (size_t)head_len)) { conn_close(c); return; }

  ep_add(ufd, EPOLLIN | EPOLLRDHUP);
  ep_mod(c);

  // Pump any pending traffic already available on either descriptor.
  if (!pump(c)) { conn_close(c); return; }
  struct conn *uu = conn_get(ufd);
  if (uu && !pump(uu)) conn_close(uu);
}

// The upstream socket is connected: hand the buffered request over and start splicing.
static void connected(struct conn *c, int ufd) {
  int one = 1;
  setsockopt(ufd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
  struct setup *su = c->su;
  c->su = NULL;
  leave_setup(c);
  start_tunnel(c, ufd, su->is_connect ? "HTTP/1.1 200 Connection Established\r\n\r\n" : NULL,
               su->out, su->out_len);
  setup_free(su);
}

// Starts a non-blocking connect to the next address. Each attempt gets an equal share
// of what remains of the connect budget, so one blackholed address (say, IPv6 on a
// network without it) cannot use up the time the others need.
static void try_next(struct conn *c) {
  struct setup *su = c->su;
  int timed_out = 0;
  while (su->next < su->naddr) {
    int64_t now = monotonic_ms();
    int64_t remaining = su->dial_deadline - now;
    if (remaining <= 0) { timed_out = 1; break; }
    int left = su->naddr - su->next;
    struct sockaddr *sa = (struct sockaddr *)&su->addr[su->next];
    socklen_t len = su->addr_len[su->next];
    su->next++;

    int fd = socket(sa->sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) continue;
    if (fd >= MAX_FDS) { close(fd); continue; }
    if (connect(fd, sa, len) == 0) { connected(c, fd); return; }
    if (errno != EINPROGRESS) { close(fd); continue; }
    su->dial_fd = fd;
    owner[fd] = c;
    ep_add(fd, EPOLLOUT);
    c->deadline = now + remaining / left;
    return;
  }
  fail(c, timed_out || su->dial_timed_out ? "504 Gateway Timeout" : "502 Bad Gateway");
}

static void begin_dial(struct conn *c) {
  struct setup *su = c->su;
  // IPv4 first: it works on IPv4-only networks and, through 464XLAT, on IPv6-only
  // ones, so it rarely costs an attempt. Stable, so resolver order is kept within
  // each family.
  struct sockaddr_storage addr[MAX_ADDRS];
  socklen_t alen[MAX_ADDRS];
  int n = 0;
  for (int pass = 0; pass < 2; pass++)
    for (int i = 0; i < su->naddr; i++)
      if ((su->addr[i].ss_family == AF_INET) == (pass == 0)) {
        addr[n] = su->addr[i];
        alen[n++] = su->addr_len[i];
      }
  memcpy(su->addr, addr, sizeof addr[0] * (size_t)n);
  memcpy(su->addr_len, alen, sizeof alen[0] * (size_t)n);

  c->state = ST_DIAL;
  su->next = 0;
  su->dial_deadline = monotonic_ms() + CONNECT_TIMEOUT_MS;
  try_next(c);
}

static void on_dial_ready(struct conn *c, int fd) {
  if (!ready(fd, POLLOUT)) return;
  struct setup *su = c->su;
  epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
  owner[fd] = NULL;
  su->dial_fd = -1;
  int error = 0;
  socklen_t len = sizeof error;
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
    connected(c, fd);
    return;
  }
  close(fd);
  try_next(c);
}

static void begin_resolve(struct conn *c) {
  struct setup *su = c->su;
  if (add_literal(su)) { begin_dial(c); return; }
  if (res_nquery) {
    static const int types[2] = { NS_T_A, NS_T_AAAA };
    for (int i = 0; i < 2; i++) {
      int fd = res_nquery(0 /* NETID_UNSET: the default network */, su->host, NS_C_IN,
                          types[i], 0);
      if (fd < 0) continue;
      if (fd >= MAX_FDS) { res_cancel(fd); continue; }
      su->dns_fd[i] = fd;
      su->dns_left++;
      owner[fd] = c;
      ep_add(fd, EPOLLIN);
    }
    if (su->dns_left) {
      c->state = ST_RESOLVE;
      c->deadline = monotonic_ms() + DNS_TIMEOUT_MS;
      return;
    }
  }
  resolve_blocking(su);
  if (su->naddr) begin_dial(c);
  else fail(c, "502 Bad Gateway");
}

static void on_dns(struct conn *c, int fd) {
  if (!ready(fd, POLLIN)) return;
  struct setup *su = c->su;
  int idx = su->dns_fd[0] == fd ? 0 : 1;
  epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
  owner[fd] = NULL;
  su->dns_fd[idx] = -1;
  su->dns_left--;

  uint8_t answer[8192];
  int rcode = 0;
  int n = res_nresult(fd, &rcode, answer, sizeof answer); // Consumes and closes fd
  if (n > 0 && rcode == 0) parse_answer(answer, n, idx ? NS_T_AAAA : NS_T_A, su);

  if (su->dns_left > 0) {
    // The other family has RESOLUTION_DELAY_MS to catch up; expire() then dials.
    if (su->naddr) {
      int64_t grace = monotonic_ms() + RESOLUTION_DELAY_MS;
      if (grace < c->deadline) c->deadline = grace;
    }
    return;
  }
  if (su->naddr) begin_dial(c);
  else fail(c, "502 Bad Gateway");
}

// Called when a setup phase outlives its deadline.
static void expire(struct conn *c) {
  struct setup *su = c->su;
  switch (c->state) {
  case ST_HEADER:
    conn_close(c);
    break;
  case ST_RESOLVE:
    for (int i = 0; i < 2; i++) {
      int fd = su->dns_fd[i];
      if (fd < 0) continue;
      epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
      owner[fd] = NULL;
      res_cancel(fd);
      su->dns_fd[i] = -1;
    }
    su->dns_left = 0;
    // One family answering is enough: reached RESOLUTION_DELAY_MS after it did, or
    // at DNS_TIMEOUT_MS if an answer arrived without addresses.
    if (su->naddr) begin_dial(c);
    else fail(c, "504 Gateway Timeout");
    break;
  case ST_DIAL:
    if (su->dial_fd >= 0) {
      epoll_ctl(epfd, EPOLL_CTL_DEL, su->dial_fd, NULL);
      owner[su->dial_fd] = NULL;
      close(su->dial_fd);
      su->dial_fd = -1;
    }
    su->dial_timed_out = 1;
    try_next(c);
    break;
  }
}

// ---- Authentication ------------------------------------------------------------------

static int b64_value(unsigned char ch) {
  if (ch >= 'A' && ch <= 'Z') return ch - 'A';
  if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
  if (ch >= '0' && ch <= '9') return ch - '0' + 52;
  if (ch == '+') return 62;
  if (ch == '/') return 63;
  return -1;
}

// Decodes standard base64 (padding optional). Returns the decoded length, or -1.
static int b64_decode(const char *in, size_t len, char *out, size_t cap) {
  while (len > 0 && in[len - 1] == '=') len--;
  uint32_t acc = 0;
  int bits = 0;
  size_t n = 0;
  for (size_t i = 0; i < len; i++) {
    int v = b64_value((unsigned char)in[i]);
    if (v < 0) return -1;
    acc = acc << 6 | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (n >= cap) return -1;
      out[n++] = (char)(acc >> bits & 0xFF);
    }
  }
  return (int)n;
}

// Compares without an early exit, so response timing does not reveal how much of
// a guess was right.
static int token_matches(const char *s, size_t len) {
  unsigned char diff = len != auth_len;
  for (size_t i = 0; i < auth_len; i++)
    diff |= (unsigned char)(i < len ? s[i] : 0) ^ (unsigned char)auth_token[i];
  return diff == 0;
}

// Accepts "Basic base64(user:token)" with any username, which is what clients send
// for a proxy URL of the form http://user:token@127.0.0.1:port.
static int credentials_ok(const char *value, size_t len) {
  if (len < 6 || strncasecmp(value, "basic ", 6) != 0) return 0;
  value += 6;
  len -= 6;
  while (len > 0 && (*value == ' ' || *value == '\t')) { value++; len--; }
  while (len > 0 && (value[len - 1] == ' ' || value[len - 1] == '\t' || value[len - 1] == '\r'))
    len--;
  char decoded[TOKEN_MAX * 2];
  int n = b64_decode(value, len, decoded, sizeof decoded);
  if (n < 0) return 0;
  char *colon = memchr(decoded, ':', (size_t)n);
  if (!colon) return 0;
  size_t pass_len = (size_t)(decoded + n - (colon + 1));
  return token_matches(colon + 1, pass_len);
}

// Finds a header in the block [hdrs, hdrs+len) by name (including the colon).
// Returns a pointer to the value with leading whitespace skipped, or NULL.
static const char *find_header(const char *hdrs, int len, const char *name, size_t *vlen) {
  size_t nlen = strlen(name);
  for (const char *q = hdrs, *stop = hdrs + len; q < stop;) {
    const char *nl = memchr(q, '\n', (size_t)(stop - q));
    size_t llen = nl ? (size_t)(nl - q) : (size_t)(stop - q);
    if (llen >= nlen && strncasecmp(q, name, nlen) == 0) {
      const char *v = q + nlen;
      size_t vl = llen - nlen;
      while (vl > 0 && (*v == ' ' || *v == '\t')) { v++; vl--; }
      if (vl > 0 && v[vl - 1] == '\r') vl--;
      *vlen = vl;
      return v;
    }
    q += llen + (nl ? 1 : 0);
  }
  return NULL;
}

// Reads the token, creating it (random, mode 0600) if the file does not exist yet.
// Refuses a file that other users could read, as ssh does with private keys.
// Returns 0 on success, or -1 after printing why.
static int load_token(const char *path) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0 && errno == ENOENT) {
    unsigned char raw[16];
    int rnd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (rnd < 0 || read(rnd, raw, sizeof raw) != (ssize_t)sizeof raw) {
      fprintf(stderr, "termux-http-proxy: cannot read /dev/urandom\n");
      if (rnd >= 0) close(rnd);
      return -1;
    }
    close(rnd);
    char hex[sizeof raw * 2 + 2];
    for (size_t i = 0; i < sizeof raw; i++) snprintf(hex + i * 2, 3, "%02x", raw[i]);
    strcat(hex, "\n");
    int w = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (w < 0 && errno != EEXIST) {
      fprintf(stderr, "termux-http-proxy: cannot create %s: %s\n", path, strerror(errno));
      return -1;
    }
    if (w >= 0) {
      fchmod(w, 0600);
      int ok = write(w, hex, strlen(hex)) == (ssize_t)strlen(hex);
      close(w);
      if (!ok) {
        fprintf(stderr, "termux-http-proxy: cannot write %s\n", path);
        unlink(path);
        return -1;
      }
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
  }
  if (fd < 0) {
    fprintf(stderr, "termux-http-proxy: cannot open %s: %s\n", path, strerror(errno));
    return -1;
  }
  struct stat st;
  if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
    fprintf(stderr, "termux-http-proxy: %s is not a regular file\n", path);
    close(fd);
    return -1;
  }
  if (st.st_mode & 077) {
    fprintf(stderr, "termux-http-proxy: %s is accessible by other users (mode %03o); "
                    "chmod 600 it\n", path, (unsigned)(st.st_mode & 0777));
    close(fd);
    return -1;
  }
  ssize_t n = read(fd, auth_token, sizeof auth_token - 1);
  close(fd);
  if (n < 0) n = 0;
  while (n > 0 && (auth_token[n - 1] == '\n' || auth_token[n - 1] == '\r' ||
                   auth_token[n - 1] == ' ' || auth_token[n - 1] == '\t'))
    n--;
  auth_token[n] = 0;
  for (ssize_t i = 0; i < n; i++) {
    if ((unsigned char)auth_token[i] <= ' ' || auth_token[i] == 0x7F) {
      fprintf(stderr, "termux-http-proxy: token in %s contains whitespace or control "
                      "characters\n", path);
      return -1;
    }
  }
  if (n < 16) {
    fprintf(stderr, "termux-http-proxy: token in %s is shorter than 16 characters\n", path);
    return -1;
  }
  auth_len = (size_t)n;
  return 0;
}

// ---- Request parsing -----------------------------------------------------------------

// Splits "host", "host:port", "[v6]" or "[v6]:port" into its parts. Returns 0 on
// success, -1 if malformed.
static int split_host_port(char *authority, uint16_t defport, char *host, size_t hostsz,
                           uint16_t *port) {
  char *portstr = NULL;
  if (*authority == '[') {
    char *end = strchr(authority, ']');
    if (!end) return -1;
    *end = 0;
    authority++;
    if (end[1] == ':') portstr = end + 2;
    else if (end[1]) return -1;
  } else {
    char *colon = strrchr(authority, ':');
    // More than one colon without brackets is a bare IPv6 address, not host:port.
    if (colon && strchr(authority, ':') == colon) {
      *colon = 0;
      portstr = colon + 1;
    }
  }
  if (!*authority || strlen(authority) >= hostsz) return -1;
  strcpy(host, authority);
  *port = defport;
  if (portstr) {
    char *endp;
    long p = strtol(portstr, &endp, 10);
    if (endp == portstr || *endp || p < 1 || p > 65535) return -1;
    *port = (uint16_t)p;
  }
  return 0;
}

static struct setup *setup_new(void) {
  struct setup *su = calloc(1, sizeof *su);
  if (!su) return NULL;
  su->dns_fd[0] = su->dns_fd[1] = -1;
  su->dial_fd = -1;
  return su;
}

// Evaluates whether a header is hop-by-hop per RFC 9110 and must not be forwarded.
static int hop_by_hop(const char *line, size_t len) {
  static const char *drop[] = {
    "connection:", "proxy-connection:", "proxy-authorization:", "proxy-authenticate:",
    "keep-alive:", "te:", "trailer:", "transfer-encoding:", "upgrade:", NULL
  };
  for (int i = 0; drop[i]; i++) {
    size_t n = strlen(drop[i]);
    if (len >= n && strncasecmp(line, drop[i], n) == 0) return 1;
  }
  return 0;
}

// Handles HTTP CONNECT requests (standard for HTTPS tunneling). The reply waits until
// the upstream connection exists; any early payload is held and forwarded after it.
static int prepare_connect(struct setup *su, char *target, const char *body, int body_len) {
  if (split_host_port(target, 443, su->host, sizeof su->host, &su->port) < 0) return -1;
  su->is_connect = 1;
  if (body_len > 0) {
    su->out = malloc((size_t)body_len);
    if (!su->out) return -1;
    memcpy(su->out, body, (size_t)body_len);
    su->out_len = body_len;
  }
  return 0;
}

// Handles plain HTTP proxy requests (absolute-URI format).
// Strips hop-by-hop headers, rewrites the request line to origin-form and appends
// 'Connection: close' to ensure clean transaction framing. The rewritten request is
// held until the upstream connection exists.
static int prepare_http(struct setup *su, const char *method, char *url, const char *hdrs,
                        int hdrs_len, const char *body, int body_len) {
  if (strncasecmp(url, "http://", 7) != 0) return -1;
  char *hostpart = url + 7;
  char *slash = strchr(hostpart, '/');
  char path[1024];
  if (slash) {
    if (strlen(slash) >= sizeof path) return -1;
    strcpy(path, slash);
    *slash = 0;
  } else {
    strcpy(path, "/");
  }
  // Strip userinfo from authority component if present (user:pass@host)
  char *at = strrchr(hostpart, '@');
  if (at) hostpart = at + 1;
  if (split_host_port(hostpart, 80, su->host, sizeof su->host, &su->port) < 0) return -1;

  size_t cap = strlen(method) + strlen(path) + 16 + (size_t)hdrs_len + 2 + 21 + (size_t)body_len;
  char *out = malloc(cap);
  if (!out) return -1;
  size_t n = (size_t)snprintf(out, cap, "%s %s HTTP/1.1\r\n", method, path);
  if (n >= 1024) { free(out); return -1; }

  // Then the client's headers, minus the ones meant for us.
  for (const char *q = hdrs, *stop = hdrs + hdrs_len; q < stop;) {
    const char *nl = memchr(q, '\n', (size_t)(stop - q));
    size_t llen = nl ? (size_t)(nl - q + 1) : (size_t)(stop - q);
    if (!hop_by_hop(q, llen)) {
      memcpy(out + n, q, llen);
      n += llen;
      // The parser excludes the separator, including the final header newline.
      if (!nl) { memcpy(out + n, "\r\n", 2); n += 2; }
    }
    q += llen;
  }
  memcpy(out + n, "Connection: close\r\n\r\n", 21);
  n += 21;
  if (body_len > 0) {
    memcpy(out + n, body, (size_t)body_len);
    n += (size_t)body_len;
  }
  su->out = out;
  su->out_len = (int)n;
  return 0;
}

// Ingests and processes incoming request bytes during ST_HEADER phase.
// Returns 1 if connection remains active, 0 if closed or errored.
static int on_header(struct conn *c) {
  if (!c->req) {
    c->req = malloc(REQ_MAX);
    if (!c->req) { conn_close(c); return 0; }
  }
  ssize_t r = read(c->fd, c->req + c->req_len, (size_t)(REQ_MAX - c->req_len));
  if (r == 0) { conn_close(c); return 0; }
  if (r < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 1;
    conn_close(c);
    return 0;
  }
  c->req_len += (int)r;

  // Search for the end of the HTTP header block (CRLF CRLF or LF LF).
  char *end = memmem(c->req, (size_t)c->req_len, "\r\n\r\n", 4);
  int sep = 4;
  if (!end) { end = memmem(c->req, (size_t)c->req_len, "\n\n", 2); sep = 2; }
  if (!end) {
    if (c->req_len >= REQ_MAX) { fail(c, "431 Request Header Fields Too Large"); return 0; }
    return 1;
  }

  char *body = end + sep;
  int body_len = c->req_len - (int)(body - c->req);
  *end = 0; // Terminate header string; body payload tracked by pointer and length

  char *sp1 = strchr(c->req, ' ');
  if (!sp1) { fail(c, "400 Bad Request"); return 0; }
  *sp1 = 0;
  char *method = c->req;
  char *url = sp1 + 1;
  char *sp2 = strchr(url, ' ');
  if (!sp2) { fail(c, "400 Bad Request"); return 0; }
  *sp2 = 0;
  // Locate the start of headers following the request line.
  char *hdrs = strchr(sp2 + 1, '\n');
  hdrs = hdrs ? hdrs + 1 : end;
  int hdrs_len = (int)(end - hdrs);

  // Nothing is resolved or dialed for a client that has not authenticated.
  if (auth_len) {
    size_t vlen = 0;
    const char *v = find_header(hdrs, hdrs_len, "proxy-authorization:", &vlen);
    if (!v || !credentials_ok(v, vlen)) {
      fail_with(c, "407 Proxy Authentication Required",
                "Proxy-Authenticate: Basic realm=\"termux-http-proxy\"\r\n");
      return 0;
    }
  }

  int is_connect = strcmp(method, "CONNECT") == 0;
  // Reject chunked requests to avoid parsing ambiguities during zero-copy forwarding.
  if (!is_connect) {
    size_t vlen;
    if (find_header(hdrs, hdrs_len, "transfer-encoding:", &vlen)) {
      fail(c, "501 Not Implemented");
      return 0;
    }
  }

  struct setup *su = setup_new();
  if (!su) { fail(c, "500 Internal Server Error"); return 0; }
  c->su = su;
  int rc = is_connect ? prepare_connect(su, url, body, body_len)
                      : prepare_http(su, method, url, hdrs, hdrs_len, body, body_len);
  if (rc < 0) { fail(c, "400 Bad Request"); return 0; }
  free(c->req);
  c->req = NULL;

  // Until the tunnel exists, only errors and hangups matter on the client socket.
  // Anything more it sends stays in the kernel buffer for the tunnel to pick up.
  struct epoll_event ev = {0};
  ev.data.fd = c->fd;
  epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev);
  begin_resolve(c);
  return 1;
}

// ---- Main Event Loop & Lifecycle -----------------------------------------------------

// How long epoll may sleep: until the nearest setup deadline, or forever if none.
static int next_timeout(void) {
  if (!n_setup) return -1;
  int64_t now = monotonic_ms(), soonest = INT64_MAX;
  for (int f = 0; f < MAX_FDS; f++) {
    struct conn *s = conns[f];
    if (s && s->in_setup && s->deadline < soonest) soonest = s->deadline;
  }
  if (soonest == INT64_MAX) return -1;
  int64_t wait = soonest - now;
  return wait <= 0 ? 0 : wait > INT_MAX ? INT_MAX : (int)wait;
}

static void expire_due(void) {
  if (!n_setup) return;
  int64_t now = monotonic_ms();
  for (int f = 0; f < MAX_FDS; f++) {
    struct conn *s = conns[f];
    if (s && s->in_setup && now >= s->deadline) expire(s);
  }
}

static void usage(void) {
  fprintf(stderr,
          "usage: termux-http-proxy [--port PORT | PORT] [-f | -d] [--auth-file PATH]\n"
          "  (no port)          bind a free loopback port, print it, exit with the parent\n"
          "  --port PORT, PORT  bind PORT and detach as a daemon\n"
          "  -f                 with a port: stay in the foreground (for runit)\n"
          "  -d                 detach even without a port\n"
          "  --auth-file PATH   require Proxy-Authorization with the token in PATH\n"
          "                     (created with a random token, mode 0600, if missing)\n");
}

static int parse_port(const char *s) {
  char *end;
  long p = strtol(s, &end, 10);
  return (end != s && !*end && p >= 1 && p <= 65535) ? (int)p : -1;
}

int main(int argc, char **argv) {
  // Ignore SIGPIPE to handle broken connections safely via standard socket error codes.
  signal(SIGPIPE, SIG_IGN);

  int fixed_port = 0;
  int daemon_mode = 0;
  int foreground = 0; // -f: fixed port but stay attached, for a supervisor such as runit
  const char *auth_file = NULL;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-d") == 0) {
      daemon_mode = 1;
    } else if (strcmp(argv[i], "-f") == 0) {
      foreground = 1;
      daemon_mode = 1;
    } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      if ((fixed_port = parse_port(argv[++i])) < 0) { usage(); return 2; }
      daemon_mode = 1;
    } else if (strcmp(argv[i], "--auth-file") == 0 && i + 1 < argc) {
      auth_file = argv[++i];
    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      usage();
      return 0;
    } else if ((fixed_port = parse_port(argv[i])) > 0) {
      daemon_mode = 1;
    } else {
      usage();
      return 2;
    }
  }

  // Before daemon(): a daemon's stderr is /dev/null, and a bad token file should be
  // reported, not silently turned into an unauthenticated proxy.
  if (auth_file && load_token(auth_file) < 0) return 1;
  resolver_init();

  if (daemon_mode && !foreground) {
    if (daemon(1, 0) < 0) return 1;
  }

  epfd = epoll_create1(EPOLL_CLOEXEC);
  if (epfd < 0) return 1;

  int lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (lfd < 0) return 1;
  int one = 1;
  setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // Bind to loopback interface only
  addr.sin_port = htons((uint16_t)fixed_port);   // User-specified fixed port or 0 for kernel allocation
  if (bind(lfd, (struct sockaddr *)&addr, sizeof addr) < 0) return 1;
  if (listen(lfd, 64) < 0) return 1;

  socklen_t alen = sizeof addr;
  if (getsockname(lfd, (struct sockaddr *)&addr, &alen) < 0) return 1;
  int port = ntohs(addr.sin_port);
  set_nonblock(lfd);
  ep_add(lfd, EPOLLIN);

  pid_t started_under = getppid();
  int tfd = -1;

  if (!daemon_mode) {
    // Coprocess mode: monitor stdin pipe for EOF from parent launcher process.
    // Provides instantaneous, zero-overhead shutdown when the parent process exits.
    set_nonblock(STDIN_FILENO);
    ep_add(STDIN_FILENO, EPOLLIN | EPOLLRDHUP);

    // Periodic watchdog timer as a fallback for abnormal parent termination.
    // Setup deadlines do not depend on it; they drive the epoll timeout in every mode.
    tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (tfd >= 0) {
      struct itimerspec its = {{2, 0}, {2, 0}};
      timerfd_settime(tfd, 0, &its, NULL);
      ep_add(tfd, EPOLLIN);
    }
  }

  // Report the port, then close stdout for good.
  // In coprocess mode, the parent reads this one line.
  if (!daemon_mode) {
    char buf[16];
    int n = snprintf(buf, sizeof buf, "%d\n", port);
    ssize_t off = 0;
    while (off < n) {
      ssize_t w = write(STDOUT_FILENO, buf + off, (size_t)(n - off));
      if (w > 0) { off += w; continue; }
      if (errno == EINTR) continue;
      break;
    }
    close(STDOUT_FILENO);
  }

  struct epoll_event evs[64];
  for (;;) {
    int n = epoll_wait(epfd, evs, 64, next_timeout());
    if (n < 0) {
      if (errno == EINTR) continue;
      return 1;
    }
    for (int i = 0; i < n; i++) {
      int fd = evs[i].data.fd;
      uint32_t e = evs[i].events;

      if (fd == lfd) {
        for (;;) {
          int cfd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
          if (cfd < 0) break;
          struct conn *c = conn_new(cfd);
          if (!c) { close(cfd); continue; }
          c->in_setup = 1;
          n_setup++;
          c->deadline = monotonic_ms() + HEADER_TIMEOUT_MS;
          setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
          ep_add(cfd, EPOLLIN | EPOLLRDHUP);
        }
        continue;
      }

      if (!daemon_mode && fd == STDIN_FILENO) _exit(0); // Parent process closed communication pipe

      if (tfd >= 0 && fd == tfd) {
        uint64_t ticks;
        (void)!read(tfd, &ticks, sizeof ticks);
        if (started_under > 1) {
          if (kill(started_under, 0) != 0 && errno == ESRCH) _exit(0);
          if (getppid() != started_under) _exit(0);
        }
        continue;
      }

      // A resolver answer or a connect completing, on behalf of a client connection.
      struct conn *o = (fd >= 0 && fd < MAX_FDS) ? owner[fd] : NULL;
      if (o) {
        if (o->state == ST_RESOLVE) on_dns(o, fd);
        else if (o->state == ST_DIAL) on_dial_ready(o, fd);
        continue;
      }

      struct conn *c = conn_get(fd);
      if (!c) continue;

      if (c->state == ST_HEADER) {
        if (e & (EPOLLERR | EPOLLHUP)) { conn_close(c); continue; }
        if (e & (EPOLLIN | EPOLLRDHUP)) on_header(c);
        continue;
      }
      if (c->state == ST_RESOLVE || c->state == ST_DIAL) {
        if (e & (EPOLLERR | EPOLLHUP)) conn_close(c); // Client gave up; cancel the setup
        continue;
      }

      // Active tunnel: EPOLLOUT indicates peer pipe buffer has cleared backpressure.
      if (e & EPOLLOUT) {
        struct conn *p = conn_get(c->peer);
        if (p && !pump(p)) conn_close(p);
        // conn_close(p) cascades to terminate c; re-verify descriptor before proceeding.
        c = conn_get(fd);
        if (!c) continue;
      }
      if (e & (EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP)) {
        if (!pump(c)) { conn_close(c); continue; }
      }
    }
    expire_due();
  }
}
