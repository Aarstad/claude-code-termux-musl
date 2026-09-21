// A tiny HTTP/CONNECT proxy so musl CLI builds can reach the network.
//
// musl resolves names through /etc/resolv.conf, which Android does not have, so DNS
// inside the musl process is dead (it times out rather than failing fast). This binary
// is linked against bionic, where DNS works, so the musl process tunnels through it.
// Same trick the glibc claude-termux launcher uses.
//
// Prints its port on stdout, then serves until the process that started it is gone.
//
// This is the C replacement for dns-proxy.js. It avoids a JavaScript runtime per
// session and uses one event-loop thread. Tunnel data travels through kernel pipes;
// headers and connection metadata are the main userspace allocations. Socket and
// pipe buffers still cost kernel memory, which process RSS does not include.
//
//   cc -O2 -o dns-proxy dns-proxy.c
//
// Everything below is bionic/Linux: epoll, splice, timerfd. No third-party anything.

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

// Request headers we buffer before deciding what to do. Anything past this without a
// complete header block is a client we do not want to serve.
#define REQ_MAX 16384
// How long a connection may sit in ST_HEADER without completing its request line and
// headers. A client that connects and then says nothing otherwise holds a slot and a
// 16KB buffer forever; the watchdog timer is already ticking, so the sweep is free.
#define HEADER_TIMEOUT 30
// Shared across resolved addresses; DNS itself still uses bionic's timeout.
#ifndef CONNECT_TIMEOUT_MS
#define CONNECT_TIMEOUT_MS 5000
#endif
#ifndef WRITE_TIMEOUT_MS
#define WRITE_TIMEOUT_MS 5000
#endif
// Pipe capacity for splice(). 64K matches the default Linux pipe size; asking for more
// needs privileges we do not have.
#define PIPE_CAP 65536
// The connection table is indexed by fd, so this is an fd ceiling, not a connection
// ceiling. A tunnel costs six fds: a socket and a pipe pair on each side. With the four
// fixed fds (epoll, stdin, timerfd, listener) that is roughly 85 concurrent tunnels
// before accepted sockets may be rejected. Sized for one CLI session, which opens a
// handful; raising it is a one-line change if that ever stops being true.
#define MAX_FDS 512

enum { ST_HEADER, ST_TUNNEL };

// One client connection, and (once established) its upstream peer. A tunnel is two of
// these pointing at each other, each owning the pipe that carries bytes in its direction.
struct conn {
  int fd;             // our socket
  int peer;           // the other end of the tunnel, or -1
  int state;
  int pipe_r, pipe_w; // splice() needs a pipe as an intermediary; this one is fd -> peer
  int inflight;       // bytes sitting in the pipe, not yet written to peer
  int fd_eof;         // our side has closed; drain the pipe, then shut the peer down
  int want_out;       // peer's socket buffer was full; we are waiting for it to drain
  char *req;          // header buffer, allocated only while state == ST_HEADER
  int req_len;
  int64_t born;        // for the ST_HEADER idle sweep; unused once tunnelled
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

// A short write on a non-blocking socket is not an error, it is a partial send -- and
// dropping the remainder corrupts the stream with no diagnostic. These writes happen
// before the connection is spliced, so blocking briefly here is safe and simpler than
// carrying a pending-write buffer. Returns 0 if the peer is gone.
static int write_all(int fd, const char *buf, size_t len) {
  size_t off = 0;
  int64_t deadline = monotonic_ms() + WRITE_TIMEOUT_MS;
  while (off < len) {
    if (monotonic_ms() >= deadline) { errno = ETIMEDOUT; return 0; }
    ssize_t w = write(fd, buf + off, len - off);
    if (w > 0) { off += (size_t)w; continue; }
    if (w < 0 && errno == EINTR) continue;
    if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      // Wait for room rather than spinning; this is a handful of bytes at setup time.
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
  // Same bounds as conn_get: a negative fd would index behind the table.
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

// A fatal close ends both directions: buffered peer bytes have no destination.
// Orderly half-closes are handled by pump() before reaching this function.
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
  // Pause reads and half-close notifications while our pipe is blocked.
  // Level-triggered epoll reports remaining data/EOF when reads resume.
  if (!c->fd_eof && !c->want_out) ev.events |= EPOLLIN | EPOLLRDHUP;
  if (p && p->want_out) ev.events |= EPOLLOUT;
  epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev);
}

static void ep_mod(struct conn *c) {
  ep_update(c);
  struct conn *p = conn_get(c->peer);
  if (p) ep_update(p);
}

// ---- the tunnel ----------------------------------------------------------------------

// Move bytes from c->fd to c->peer without them ever entering userspace: splice() into a
// pipe, splice() out of it. Returns 0 if the connection should be closed.
//
// The pipe is what makes this different from a read/write loop -- there is no buffer to
// allocate per connection and no copy through our address space. The cost is that a
// partial write leaves bytes *in the pipe*, so c->inflight has to be tracked and drained
// before the connection can be considered finished.
static int pump(struct conn *c) {
  struct conn *p = conn_get(c->peer);
  if (!p) return 0;

  for (;;) {
    // First push out anything already buffered from a previous partial write.
    while (c->inflight > 0) {
      ssize_t w = splice(c->pipe_r, NULL, p->fd, NULL, c->inflight,
                         SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
      if (w > 0) { c->inflight -= (int)w; continue; }
      if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        // Peer is full. Stop reading from our side until it drains, otherwise we would
        // spin filling a pipe that has nowhere to go.
        c->want_out = 1;
        ep_mod(c);
        return 1;
      }
      if (w < 0 && errno == EINTR) continue;
      return 0; // EPIPE or similar: peer is gone
    }
    if (c->want_out) { c->want_out = 0; ep_mod(c); }

    // Pipe is empty. If our side already hit EOF, the direction is finished: let the peer
    // see it, and close if the other direction is done too.
    if (c->fd_eof) {
      shutdown(p->fd, SHUT_WR);
      return (p->fd_eof && p->inflight == 0) ? 0 : 1;
    }

    ssize_t r = splice(c->fd, NULL, c->pipe_w, NULL, PIPE_CAP,
                       SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    if (r > 0) { c->inflight += (int)r; continue; }
    if (r == 0) { c->fd_eof = 1; ep_mod(c); continue; } // drain, then shutdown above
    if (errno == EAGAIN || errno == EWOULDBLOCK) return 1; // nothing more right now
    if (errno == EINTR) continue;
    return 0;
  }
}

// ---- connection setup ----------------------------------------------------------------

static void fail(struct conn *c, const char *status) {
  char buf[128];
  int n = snprintf(buf, sizeof buf, "HTTP/1.1 %s\r\nConnection: close\r\n\r\n", status);
  (void)write_all(c->fd, buf, (size_t)n); // best effort; we are closing regardless
  conn_close(c);
}

// DNS remains synchronous through bionic. TCP attempts share a finite deadline,
// rather than waiting for kernel TCP timeouts. Other tunnels still pause during
// setup; this is not asynchronous DNS/connect.
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

// Give a connection its pipe and register it. Both directions get their own.
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
    // arm(c) may have succeeded, leaving c in ST_TUNNEL but
    // no peer. Say so explicitly rather than relying on the field still holding -1.
    c->peer = -1;
    conn_close(u);
    fail(c, "500 Internal Server Error");
    return;
  }
  c->peer = ufd;
  u->peer = c->fd;

  if (reply && !write_all(c->fd, reply, strlen(reply))) { conn_close(c); return; }
  // Anything the client already sent past the header goes upstream before we start
  // splicing, or it would be lost.
  if (head_len > 0 && !write_all(ufd, head, (size_t)head_len)) { conn_close(c); return; }

  // head points into the request buffer; retain it until forwarding completes.
  free(c->req);
  c->req = NULL;

  struct epoll_event ev = {0};
  ev.events = EPOLLIN | EPOLLRDHUP;
  ev.data.fd = ufd;
  epoll_ctl(epfd, EPOLL_CTL_ADD, ufd, &ev);
  ep_mod(c);

  // Either side may already have data waiting.
  if (!pump(c)) { conn_close(c); return; }
  struct conn *uu = conn_get(ufd);
  if (uu && !pump(uu)) conn_close(uu);
}

// HTTPS goes through CONNECT: we resolve and open the socket, then just shuttle bytes.
static void do_connect(struct conn *c, char *target, char *head, int head_len) {
  char *colon = strrchr(target, ':');
  const char *port = "443";
  if (colon) { *colon = 0; port = colon + 1; }
  int ufd = dial(target, port);
  if (ufd < 0) { fail(c, "502 Bad Gateway"); return; }
  start_tunnel(c, ufd, "HTTP/1.1 200 Connection Established\r\n\r\n", head, head_len);
}

// Plain HTTP (the absolute-URI form a proxy receives). The main CLI traffic uses
// HTTPS, but ordinary fixed-length HTTP requests are supported too.
//
// We rewrite the request line to origin form, drop the hop-by-hop headers that are
// addressed to us rather than to the server, and add `Connection: close`. That last part
// matters: the response is spliced back without parsing its framing, so this connection
// asks the origin to close after its response. This is not a framing parser and
// does not enforce one request against clients that ignore Connection: close. RFC 9110 calls these headers connection-specific for the same
// reason -- they must not be forwarded.
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
static void do_http(struct conn *c, char *method, char *url, char *hdrs, int hdrs_len,
                    char *body, int body_len) {
  // Chunked bodies are not decoded here. Reject rather than removing framing
  // and forwarding ambiguous bytes. CONNECT tunnels are unaffected.
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

  // userinfo@host is legal in a URI and must not be treated as a hostname.
  char *at = strrchr(hostpart, '@');
  if (at) hostpart = at + 1;

  char host[256];
  // host and port are copied out of c->req rather than pointed into it. The buffer
  // outlives this function today (start_tunnel frees it after forwarding), but that
  // is an ordering accident, and a stack copy costs nothing.
  char portbuf[32];
  const char *port = "80";
  // A bracketed IPv6 literal contains colons that are not the port separator.
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

// Parse what we have so far. Returns 1 if the connection is still alive.
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

  // Wait for the end of the header block before deciding anything.
  char *end = memmem(c->req, (size_t)c->req_len, "\r\n\r\n", 4);
  int sep = 4;
  if (!end) { end = memmem(c->req, (size_t)c->req_len, "\n\n", 2); sep = 2; }
  if (!end) {
    if (c->req_len >= REQ_MAX) { fail(c, "431 Request Header Fields Too Large"); return 0; }
    return 1;
  }

  char *body = end + sep;
  int body_len = c->req_len - (int)(body - c->req);
  *end = 0; // the header block is now a C string; body is tracked separately

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
    // Everything after the request line. The header block is still NUL-terminated at
    // `end`; the body (if any) sits past the separator and is forwarded untouched.
    char *hdrs = strchr(sp2 + 1, '\n');
    hdrs = hdrs ? hdrs + 1 : end;
    char *body2 = end + sep;
    int body2_len = c->req_len - (int)(body2 - c->req);
    do_http(c, method, url, hdrs, (int)(end - hdrs), body2, body2_len);
  }
  return 1;
}

// ---- main ----------------------------------------------------------------------------

int main(void) {
  // A dead peer must not kill us; every write already handles EPIPE.
  signal(SIGPIPE, SIG_IGN);

  epfd = epoll_create1(EPOLL_CLOEXEC);
  if (epfd < 0) return 1;

  int lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (lfd < 0) return 1;
  int one = 1;
  setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // loopback only; this is not a public proxy
  addr.sin_port = 0;                            // kernel picks the port
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

  // The wrapper starts us as a coprocess, so our stdin is a pipe it holds open. When it
  // exits — however it exits — the write end closes and we read EOF. That is immediate and
  // involves no pid arithmetic, unlike the watchdog below, which can be fooled by pid reuse.
  set_nonblock(STDIN_FILENO);
  ev.events = EPOLLIN | EPOLLRDHUP;
  ev.data.fd = STDIN_FILENO;
  epoll_ctl(epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev);

  // The wrapper kills us on exit; this is the backstop for when it is killed outright.
  // Watching getppid() alone assumes reparenting is visible and promptly reported, which
  // is not guaranteed. Signal 0 against the original parent asks the kernel directly.
  // A timerfd rather than a sleeping thread: it is just another fd in the same loop.
  pid_t started_under = getppid();
  int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  if (tfd >= 0) {
    struct itimerspec its = {{2, 0}, {2, 0}};
    timerfd_settime(tfd, 0, &its, NULL);
    ev.events = EPOLLIN;
    ev.data.fd = tfd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev);
  }

  // Report the port, then close stdout for good. The wrapper reads this one line and never
  // reads again, so anything written afterwards would sit in a 64KB pipe and then block
  // this process forever — alive, unkillable-looking, with DNS silently dead. Closing the
  // stream makes that impossible rather than a convention to remember. Logs go to stderr.
  {
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

      if (fd == STDIN_FILENO) _exit(0); // the wrapper is gone

      if (tfd >= 0 && fd == tfd) {
        uint64_t ticks;
        (void)!read(tfd, &ticks, sizeof ticks);
        if (started_under > 1) {
          // 0 would signal the whole process group, which always succeeds.
          if (kill(started_under, 0) != 0 && errno == ESRCH) _exit(0);
          if (getppid() != started_under) _exit(0);
        }
        // Same tick: drop connections that opened and then never sent a request.
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

      // Tunnel. EPOLLOUT means our peer's pipe can move again, so pump that side.
      if (e & EPOLLOUT) {
        struct conn *p = conn_get(c->peer);
        if (p && !pump(p)) conn_close(p);
        // conn_close(p) cascades: it can close us too, freeing c. Re-fetch rather than
        // trusting the pointer we still hold. pump() itself never closes anything, so
        // this is the only place in the loop where c can die underneath us -- which is
        // exactly why the check belongs here and not inside the branch above.
        c = conn_get(fd);
        if (!c) continue;
      }
      if (e & (EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP)) {
        if (!pump(c)) { conn_close(c); continue; }
      }
    }
  }
}
