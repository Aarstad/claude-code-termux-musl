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
// Outputs its dynamically bound loopback port to stdout and runs until the
// parent process exits or terminates.
//
// Architecture & Concurrency:
// Designed as an efficient C replacement for runtime-heavy proxy scripts:
// - Single-threaded event loop driven by epoll(7) and timerfd(2).
// - Zero-copy kernel-space data forwarding between sockets using splice(2) and pipes.
// - Minimal userspace memory overhead: dynamic allocations are restricted to
//   ephemeral header parsing buffers and lightweight connection descriptors.
//
// Compilation:
//   cc -O2 -o dns-proxy dns-proxy.c
//
// Built entirely on standard Linux/Bionic interfaces without third-party dependencies.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

// Maximum request header buffer size. Requests exceeding this threshold
// before completing the header block are rejected to prevent memory exhaustion.
#define REQ_MAX 16384
// Maximum duration (seconds) a connection may remain in ST_HEADER awaiting
// a complete request line and headers, mitigating slowloris-style idle stalls.
#define HEADER_TIMEOUT 30
// Connection timeout shared across resolved addresses during upstream dial.
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

enum { ST_HEADER, ST_TUNNEL };

// State tracking for an individual connection and its upstream peer.
// An active tunnel consists of two cross-referenced struct conn instances,
// each owning a pipe handling unidirectional data transfer.
struct conn {
  int fd;             // Connection socket descriptor
  int peer;           // Paired upstream or downstream fd (-1 if unlinked)
  int state;          // Current protocol state (ST_HEADER or ST_TUNNEL)
  int pipe_r, pipe_w; // Intermediate pipe for zero-copy splice() routing (fd -> peer)
  int inflight;       // Bytes queued in pipe awaiting consumption by peer socket
  int fd_eof;         // Inbound EOF received; pending pipe data must be drained
  int want_out;       // Backpressure flag: peer socket buffer is saturated
  char *req;          // Ephemeral request header buffer (allocated during ST_HEADER only)
  int req_len;        // Bytes currently buffered in req
  int64_t born;       // Timestamp (ms) of connection acceptance for idle timeout sweeps
};

static struct conn *conns[MAX_FDS];
static int epfd;

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
  c->born = monotonic_ms();
  conns[fd] = c;
  return c;
}

// Teardown routine: closes descriptors and frees associated resources for both
// endpoints of a tunnel. Orderly half-close states are handled in pump().
static void conn_close(struct conn *c) {
  if (!c) return;
  int fd = c->fd;
  struct conn *p = conn_get(c->peer);
  if (p) p->peer = -1;
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

static void fail(struct conn *c, const char *status) {
  char buf[128];
  int n = snprintf(buf, sizeof buf, "HTTP/1.1 %s\r\nConnection: close\r\n\r\n", status);
  (void)write_all(c->fd, buf, (size_t)n); // Best effort notification prior to teardown
  conn_close(c);
}

// Synchronously resolves hostnames via Bionic's getaddrinfo() and establishes
// an outbound TCP connection within CONNECT_TIMEOUT_MS across candidate addresses.
static int dial(const char *host, const char *port) {
  struct addrinfo hints, *res, *ai;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

  int fd = -1;
  int64_t deadline = monotonic_ms() + CONNECT_TIMEOUT_MS;
  for (ai = res; ai && monotonic_ms() < deadline; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK,
                ai->ai_protocol);
    if (fd < 0) continue;
    int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc == 0) break;
    if (errno == EINPROGRESS && wait_writable(fd, deadline)) {
      int error = 0;
      socklen_t len = sizeof error;
      if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) break;
    }
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd >= 0) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
  }
  return fd;
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

  // Retain request buffer until initial payload forwarding completes, then release.
  free(c->req);
  c->req = NULL;

  struct epoll_event ev = {0};
  ev.events = EPOLLIN | EPOLLRDHUP;
  ev.data.fd = ufd;
  epoll_ctl(epfd, EPOLL_CTL_ADD, ufd, &ev);
  ep_mod(c);

  // Pump any pending traffic already available on either descriptor.
  if (!pump(c)) { conn_close(c); return; }
  struct conn *uu = conn_get(ufd);
  if (uu && !pump(uu)) conn_close(uu);
}

// Handles HTTP CONNECT requests (standard for HTTPS tunneling).
// Resolves destination host, connects upstream, acknowledges 200 Connection Established,
// and transitions into bidirectional zero-copy forwarding.
static void do_connect(struct conn *c, char *target, char *head, int head_len) {
  char *colon = strrchr(target, ':');
  const char *port = "443";
  if (colon) { *colon = 0; port = colon + 1; }
  int ufd = dial(target, port);
  if (ufd < 0) { fail(c, "502 Bad Gateway"); return; }
  start_tunnel(c, ufd, "HTTP/1.1 200 Connection Established\r\n\r\n", head, head_len);
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

// Handles plain HTTP proxy requests (absolute-URI format).
// Strips hop-by-hop headers, rewrites the request line to origin-form, appends
// 'Connection: close' to ensure clean transaction framing, and establishes the tunnel.
static void do_http(struct conn *c, char *method, char *url, char *hdrs, int hdrs_len,
                    char *body, int body_len) {
  // Reject chunked requests to avoid parsing ambiguities during zero-copy forwarding.
  for (char *q = hdrs, *stop = hdrs + hdrs_len; q < stop;) {
    char *nl = memchr(q, '\n', (size_t)(stop - q));
    size_t len = nl ? (size_t)(nl - q + 1) : (size_t)(stop - q);
    if (len >= 18 && strncasecmp(q, "transfer-encoding:", 18) == 0) {
      fail(c, "501 Not Implemented");
      return;
    }
    q += len;
  }
  if (strncasecmp(url, "http://", 7) != 0) { fail(c, "400 Bad Request"); return; }
  char *hostpart = url + 7;
  char *slash = strchr(hostpart, '/');
  const char *path = slash ? slash : "/";
  if (slash) *slash = 0;

  // Strip userinfo from authority component if present (user:pass@host)
  char *at = strrchr(hostpart, '@');
  if (at) hostpart = at + 1;

  char host[256];
  char portbuf[32];
  const char *port = "80";
  // Handle bracketed IPv6 addresses [2001:db8::1]:port
  if (*hostpart == '[') {
    char *end = strchr(hostpart, ']');
    if (!end) { fail(c, "400 Bad Request"); return; }
    size_t n = (size_t)(end - hostpart - 1);
    if (n >= sizeof host) { fail(c, "400 Bad Request"); return; }
    memcpy(host, hostpart + 1, n);
    host[n] = 0;
    if (end[1] == ':') {
      if (strlen(end + 2) >= sizeof portbuf) { fail(c, "400 Bad Request"); return; }
      strcpy(portbuf, end + 2);
      port = portbuf;
    }
  } else {
    char *colon = strrchr(hostpart, ':');
    if (colon) {
      *colon = 0;
      if (strlen(colon + 1) >= sizeof portbuf) { fail(c, "400 Bad Request"); return; }
      strcpy(portbuf, colon + 1);
      port = portbuf;
    }
    if (strlen(hostpart) >= sizeof host) { fail(c, "400 Bad Request"); return; }
    strcpy(host, hostpart);
  }

  if (slash) *slash = '/'; // restore: path points into this buffer

  int ufd = dial(host, port);
  if (ufd < 0) { fail(c, "502 Bad Gateway"); return; }

  // Rebuild the request line in origin form.
  char line[1024];
  int n = snprintf(line, sizeof line, "%s %s HTTP/1.1\r\n", method, path);
  if (n < 0 || n >= (int)sizeof line) { close(ufd); fail(c, "400 Bad Request"); return; }
  if (!write_all(ufd, line, (size_t)n)) { close(ufd); fail(c, "502 Bad Gateway"); return; }

  // Then the client's headers, minus the ones meant for us.
  char *q = hdrs;
  char *stop = hdrs + hdrs_len;
  while (q < stop) {
    char *nl = memchr(q, '\n', (size_t)(stop - q));
    size_t llen = nl ? (size_t)(nl - q + 1) : (size_t)(stop - q);
    if (!hop_by_hop(q, llen) && !write_all(ufd, q, llen)) {
      close(ufd);
      fail(c, "502 Bad Gateway");
      return;
    }
    // The parser excludes the separator, including the final header newline.
    if (!nl && !hop_by_hop(q, llen) && !write_all(ufd, "\r\n", 2)) {
      close(ufd);
      fail(c, "502 Bad Gateway");
      return;
    }
    q += llen;
  }
  if (!write_all(ufd, "Connection: close\r\n\r\n", 21)) {
    close(ufd);
    fail(c, "502 Bad Gateway");
    return;
  }
  start_tunnel(c, ufd, NULL, body, body_len);
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

  if (strcmp(method, "CONNECT") == 0) {
    do_connect(c, url, body, body_len);
  } else {
    // Locate the start of headers following the request line.
    char *hdrs = strchr(sp2 + 1, '\n');
    hdrs = hdrs ? hdrs + 1 : end;
    char *body2 = end + sep;
    int body2_len = c->req_len - (int)(body2 - c->req);
    do_http(c, method, url, hdrs, (int)(end - hdrs), body2, body2_len);
  }
  return 1;
}

// ---- Main Event Loop & Lifecycle -----------------------------------------------------

int main(int argc, char **argv) {
  // Ignore SIGPIPE to handle broken connections safely via standard socket error codes.
  signal(SIGPIPE, SIG_IGN);

  int fixed_port = 0;
  int daemon_mode = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-d") == 0) {
      daemon_mode = 1;
    } else {
      int p = atoi(argv[i]);
      if (p > 0) {
        fixed_port = p;
        daemon_mode = 1;
      }
    }
  }

  if (daemon_mode) {
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

  struct epoll_event ev = {0};
  ev.events = EPOLLIN;
  ev.data.fd = lfd;
  epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &ev);

  pid_t started_under = getppid();
  int tfd = -1;

  if (!daemon_mode) {
    // Coprocess mode: monitor stdin pipe for EOF from parent launcher process.
    // Provides instantaneous, zero-overhead shutdown when the parent process exits.
    set_nonblock(STDIN_FILENO);
    ev.events = EPOLLIN | EPOLLRDHUP;
    ev.data.fd = STDIN_FILENO;
    epoll_ctl(epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev);

    // Periodic watchdog timer as a fallback for abnormal parent termination.
    tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (tfd >= 0) {
      struct itimerspec its = {{2, 0}, {2, 0}};
      timerfd_settime(tfd, 0, &its, NULL);
      ev.events = EPOLLIN;
      ev.data.fd = tfd;
      epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev);
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
    int n = epoll_wait(epfd, evs, 64, -1);
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
          int no = 1;
          setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &no, sizeof no);
          struct epoll_event cev = {0};
          cev.events = EPOLLIN | EPOLLRDHUP;
          cev.data.fd = cfd;
          epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &cev);
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
        // Periodic cleanup: expire idle connections stalled in ST_HEADER state.
        int64_t now = monotonic_ms();
        for (int f = 0; f < MAX_FDS; f++) {
          struct conn *s = conns[f];
          if (s && s->state == ST_HEADER && now - s->born >= HEADER_TIMEOUT * 1000)
            conn_close(s);
        }
        continue;
      }

      struct conn *c = conn_get(fd);
      if (!c) continue;

      if (c->state == ST_HEADER) {
        if (e & (EPOLLERR | EPOLLHUP)) { conn_close(c); continue; }
        if (e & (EPOLLIN | EPOLLRDHUP)) on_header(c);
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
  }
}
