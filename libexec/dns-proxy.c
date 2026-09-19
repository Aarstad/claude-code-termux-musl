// A tiny HTTP/CONNECT proxy so the musl build of Claude Code can reach the network.
//
// musl resolves names through /etc/resolv.conf, which Android does not have, so DNS
// inside the musl process is dead (it times out rather than failing fast). This binary
// is linked against bionic, where DNS works, so the musl process tunnels through it.
// Same trick the glibc claude-termux launcher uses.
//
// Prints its port on stdout, then serves until the process that started it is gone.
//
// This is the C replacement for the bun/node dns-proxy.js. Same contract, same stdout
// line, same lifecycle. It exists because the JS version drags an entire JavaScript
// runtime (JSC, mimalloc, a GC thread pool, an 18GB address space) into a process whose
// real work is copying bytes between two sockets: ~21MB RSS and 9.7MB of private dirty
// pages per session, of which a quarter of all CPU ever burned went to the allocator's
// background scavenger. This does the same job in one thread with no allocator to speak
// of and no garbage to collect.
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
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

// Request headers we buffer before deciding what to do. Anything past this without a
// complete header block is a client we do not want to serve.
#define REQ_MAX 16384
// Pipe capacity for splice(). 64K matches the default Linux pipe size; asking for more
// needs privileges we do not have.
#define PIPE_CAP 65536
#define MAX_CONNS 512

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
};

static struct conn *conns[MAX_CONNS];
static int epfd;

// ---- small helpers -------------------------------------------------------------------

static void set_nonblock(int fd) {
  int f = fcntl(fd, F_GETFL, 0);
  if (f >= 0) fcntl(fd, F_SETFL, f | O_NONBLOCK);
}

static struct conn *conn_get(int fd) {
  return (fd >= 0 && fd < MAX_CONNS) ? conns[fd] : NULL;
}

static struct conn *conn_new(int fd) {
  if (fd >= MAX_CONNS) return NULL; // refuse rather than index out of bounds
  struct conn *c = calloc(1, sizeof *c);
  if (!c) return NULL;
  c->fd = fd;
  c->peer = -1;
  c->pipe_r = c->pipe_w = -1;
  c->state = ST_HEADER;
  conns[fd] = c;
  return c;
}

// Tear down one side. The peer is detached first so it can finish draining whatever is
// already in its pipe; it closes itself once that is done.
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
  // The peer has nothing left to write into: finish it too, once its pipe is empty.
  if (p && p->inflight == 0) conn_close(p);
  else if (p) p->fd_eof = 1;
}

static void ep_mod(struct conn *c) {
  struct epoll_event ev = {0};
  ev.data.fd = c->fd;
  ev.events = EPOLLIN | EPOLLRDHUP;
  if (c->fd_eof) ev.events &= ~EPOLLIN; // nothing more will arrive
  // If our peer's socket is backed up we must hear about it becoming writable. That
  // event belongs to the peer's fd, not ours.
  struct conn *p = conn_get(c->peer);
  if (p && c->want_out) {
    struct epoll_event pv = {0};
    pv.data.fd = p->fd;
    pv.events = EPOLLIN | EPOLLRDHUP | EPOLLOUT;
    if (p->fd_eof) pv.events &= ~EPOLLIN;
    epoll_ctl(epfd, EPOLL_CTL_MOD, p->fd, &pv);
  }
  epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev);
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
  (void)!write(c->fd, buf, (size_t)n); // best effort; we are closing regardless
  conn_close(c);
}

// Resolve and connect, blocking. Measured on this device: 4-32ms warm, ~121ms worst case
// for a name that does not resolve. That is a real stall of the event loop, but it is
// bounded and rare -- bionic fails fast rather than timing out, which is the entire
// reason this proxy exists. Making it async would mean either threads (the overhead we
// are removing) or a hand-written resolver (hundreds of lines reimplementing what Android
// already gets right, including reading nameservers from system properties). Neither is
// worth it for a proxy serving one client.
static int dial(const char *host, const char *port) {
  struct addrinfo hints, *res, *ai;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // v4 or v6, whichever the network offers
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

  int fd = -1;
  for (ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd >= 0) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one); // it is a tunnel; do not batch
    set_nonblock(fd);
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
  free(c->req);
  c->req = NULL;
  return 0;
}

static void start_tunnel(struct conn *c, int ufd, const char *reply, const char *head,
                         int head_len) {
  struct conn *u = conn_new(ufd);
  if (!u) { close(ufd); fail(c, "500 Internal Server Error"); return; }

  if (arm(c) < 0 || arm(u) < 0) { conn_close(u); fail(c, "500 Internal Server Error"); return; }
  c->peer = ufd;
  u->peer = c->fd;

  if (reply) (void)!write(c->fd, reply, strlen(reply));
  // Anything the client already sent past the header goes upstream before we start
  // splicing, or it would be lost.
  if (head_len > 0) (void)!write(ufd, head, (size_t)head_len);

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

// Plain HTTP (the absolute-URI form a proxy receives). In practice everything Claude Code
// talks to is HTTPS, so this path is close to dead -- but a proxy that silently fails on
// port 80 is a bad proxy. We rewrite the request line to origin form and forward the
// header block untouched, then splice the rest like any other tunnel. No response parsing:
// whatever the server sends goes straight back, including its framing.
static void do_http(struct conn *c, char *method, char *url, char *rest, int rest_len) {
  if (strncasecmp(url, "http://", 7) != 0) { fail(c, "400 Bad Request"); return; }
  char *hostpart = url + 7;
  char *slash = strchr(hostpart, '/');
  const char *path = slash ? slash : "/";
  if (slash) *slash = 0;

  // userinfo@host is legal in a URI and must not be treated as a hostname.
  char *at = strrchr(hostpart, '@');
  if (at) hostpart = at + 1;

  char host[256];
  const char *port = "80";
  // A bracketed IPv6 literal contains colons that are not the port separator.
  if (*hostpart == '[') {
    char *end = strchr(hostpart, ']');
    if (!end) { fail(c, "400 Bad Request"); return; }
    size_t n = (size_t)(end - hostpart - 1);
    if (n >= sizeof host) { fail(c, "400 Bad Request"); return; }
    memcpy(host, hostpart + 1, n);
    host[n] = 0;
    if (end[1] == ':') port = end + 2;
  } else {
    char *colon = strrchr(hostpart, ':');
    if (colon) { *colon = 0; port = colon + 1; }
    if (strlen(hostpart) >= sizeof host) { fail(c, "400 Bad Request"); return; }
    strcpy(host, hostpart);
  }

  if (slash) *slash = '/'; // restore: path points into this buffer

  int ufd = dial(host, port);
  if (ufd < 0) { fail(c, "502 Bad Gateway"); return; }

  // Rebuild the request line in origin form, then hand over the original headers.
  char line[1024];
  int n = snprintf(line, sizeof line, "%s %s HTTP/1.1\r\n", method, path);
  if (n < 0 || n >= (int)sizeof line) { close(ufd); fail(c, "400 Bad Request"); return; }
  (void)!write(ufd, line, (size_t)n);
  start_tunnel(c, ufd, NULL, rest, rest_len);
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
    // Everything after the request line, still in its original form.
    char *hdrs = strchr(sp2 + 1, '\n');
    hdrs = hdrs ? hdrs + 1 : end;
    // The header block and the body are contiguous in the buffer; forward both. We
    // restore the separator we nulled so the upstream sees a well-formed request.
    memcpy(end, sep == 4 ? "\r\n\r\n" : "\n\n", (size_t)sep);
    int len = c->req_len - (int)(hdrs - c->req);
    do_http(c, method, url, hdrs, len);
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
        if (p && !pump(p)) { conn_close(p); continue; }
        if (!conn_get(fd)) continue; // closing the peer may have closed us
      }
      if (e & (EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP)) {
        if (!pump(c)) { conn_close(c); continue; }
      }
    }
  }
}
