// A tiny HTTP/CONNECT proxy so the musl build of Claude Code can reach the network.
//
// musl resolves names through /etc/resolv.conf, which Android does not have, so DNS
// inside the musl process is dead (it times out rather than failing fast). Node runs
// against bionic, where DNS works, so the musl process tunnels through this instead.
// Same trick the glibc claude-termux launcher uses.
//
// Prints its port on stdout, then serves until the process that started it is gone.

const http = require("http");
const net = require("net");

const server = http.createServer((req, res) => {
  // Plain HTTP (the absolute-URI form a proxy receives).
  let target;
  try {
    target = new URL(req.url);
  } catch {
    res.writeHead(400);
    return res.end();
  }
  const upstream = http.request(
    {
      host: target.hostname,
      port: target.port || 80,
      path: target.pathname + target.search,
      method: req.method,
      headers: req.headers,
    },
    (r) => {
      res.writeHead(r.statusCode, r.headers);
      r.pipe(res);
    },
  );
  upstream.on("error", () => {
    try {
      res.writeHead(502);
      res.end();
    } catch {}
  });
  req.pipe(upstream);
});

// HTTPS goes through CONNECT: we resolve and open the socket, then just shuttle bytes.
server.on("connect", (req, client, head) => {
  const i = req.url.lastIndexOf(":");
  const host = req.url.slice(0, i);
  const port = Number(req.url.slice(i + 1)) || 443;
  const upstream = net.connect(port, host, () => {
    client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head && head.length) upstream.write(head);
    upstream.pipe(client);
    client.pipe(upstream);
  });
  const bail = () => {
    upstream.destroy();
    client.destroy();
  };
  upstream.on("error", bail);
  client.on("error", bail);
});

server.on("clientError", (_err, socket) => socket.destroy());

server.listen(0, "127.0.0.1", () => {
  console.log(server.address().port);
});

// The wrapper starts us as a coprocess, so our stdin is a pipe it holds open. When it
// exits — however it exits — the write end closes and we read EOF. That is immediate and
// involves no pid arithmetic, unlike the watchdog below, which can be fooled by pid reuse.
process.stdin.on("end", () => process.exit(0));
process.stdin.on("error", () => process.exit(0));
process.stdin.resume();

// The wrapper kills us on exit; this is the backstop for when it is killed outright.
// Watching process.ppid alone assumes it is re-read rather than cached, and that
// reparenting is visible — neither is guaranteed across runtimes. Signal 0 against the
// original parent asks the kernel directly and is the same question in every runtime.
const startedUnder = process.ppid;
const watch = setInterval(() => {
  if (!startedUnder) return; // 0 would signal the whole process group, which always succeeds
  try {
    process.kill(startedUnder, 0);
  } catch {
    process.exit(0); // the wrapper is gone, and so is anything it launched
  }
  if (process.ppid !== startedUnder) process.exit(0);
}, 2000);
watch.unref();
