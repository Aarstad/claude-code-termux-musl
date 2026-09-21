# claude-code-termux-musl

Run **Claude Code natively on Android**, in Termux, with no glibc, no proot and no VM.

It uses Anthropic's own `linux-arm64-musl` build — the one published for Alpine — and
solves the three Android-specific problems that stop it running as-is. The result launches
in about **150ms** and needs a **723KB** musl loader instead of a 449MB glibc runtime.

Nothing here reimplements or repackages Claude Code: `install.sh` fetches Anthropic's
published binary from npm, verifies its `sha512`, and changes exactly one field in its ELF
header — the interpreter path. Logging in works as it does on any supported platform.

(Timings and sizes throughout are measured on one device — a Snapdragon-class Android
phone running Termux. Your numbers will differ; the ratios should not.)

```
$ claude-musl --version
2.1.274 (Claude Code)
```

## Why this exists

Android isn't a supported platform. [Anthropic's setup
docs](https://code.claude.com/docs/en/setup) list macOS, Windows, Ubuntu, Debian and
Alpine, and the npm package ships binaries for `linux-arm64`, `linux-arm64-musl` and
friends — nothing for Android. So `npm install -g @anthropic-ai/claude-code` has no binary
to fetch, and the native installer's glibc binary can't run on bionic.

The usual answers are a proot container (a supported distro, but syscall translation makes
it sluggish) or a glibc runtime inside Termux —
[wallentx/claude-code-termux](https://github.com/wallentx/claude-code-termux) does the
latter well, and this project is a direct descendant of that idea.

The observation here is that **Alpine support means a musl binary already exists**, and
musl needs almost nothing underneath it. Swap 449MB of glibc for a 723KB loader and the
same official binary runs directly on bionic.

## Requirements

- Termux on aarch64
- `curl`, `tar`, `patchelf` (installed automatically if missing)
- A DNS proxy, which is one of:
  - `clang` (`pkg install clang`) — builds the C proxy: ~3MB resident, one thread. Preferred.
  - `bun` (`pkg install bun`) or `node` — runs the JS fallback instead (~25–45MB resident)
- ~250MB of storage, ~95MB of download
- A Claude Pro, Max, Team, Enterprise or Console account

## Install

```bash
git clone https://github.com/Aarstad/claude-code-termux-musl
cd claude-code-termux-musl
./install.sh              # installs `claude-musl`
./install.sh --promote    # …and makes it the default `claude`
```

`--promote` moves any existing `claude` aside to `claude-glibc` first, so an existing
install stays available and nothing is destroyed.

Then run `claude-musl` and follow the browser prompts to log in.

## How it works

Three Android facts break the stock binary. Each has a one-line answer:

**1. The interpreter path.** The musl build asks for `/lib/ld-musl-aarch64.so.1`. Android
has no `/lib`, and you can't create one without root. So the loader (from Alpine's `musl`
package) goes in `$PREFIX/lib`, and `patchelf --set-interpreter` repoints the binary at it.
That single field is the only edit: no rpath is set, and none is needed — the binary's one
`DT_NEEDED` is `libc.musl-aarch64.so.1`, and musl's loader *is* libc, registering itself
under that name. One 723KB file satisfies both roles.

This is more than cosmetic: because the binary is then executed *directly* rather than as
an argument to a loader, `/proc/self/exe` is correct. Claude Code derives
`CLAUDE_CODE_EXECPATH` from it, and its own `grep`/`find`/`pkill` shell shims re-exec that
path. Under a loader-based launcher those shims exec the loader and die with
`-G: cannot open shared object file`. Here they work.

**2. DNS.** musl resolves through `/etc/resolv.conf`, which Android doesn't have — DNS
inside the process *hangs* rather than failing. Only a bionic process can ask Android for
resolvers, so a small proxy runs on the bionic side and the binary tunnels through it via
`HTTPS_PROXY`. The proxy is loopback-only, starts with the session and exits with it.

There are two of them, with the same contract — print a port on stdout, serve until the
wrapper is gone. `dns-proxy.c` is preferred: a single-threaded `epoll` + `splice(2)` tunnel
that never copies payload bytes into userspace. `dns-proxy.js` is the fallback for installs
without a compiler. Measured on the same workload (8 concurrent requests plus a 5MB
transfer), the C proxy holds ~2.8MB resident against bun's ~45MB, 656KB of private dirty
against 11.2MB, and one thread against four — the JS runtime spends about a quarter of its
CPU on allocator upkeep for a process whose real work is moving bytes between two sockets.

`install.sh` builds the C proxy when `cc` is present and falls back quietly when it isn't.
`CLAUDE_MUSL_RUNTIME=bun` (or `node`) forces the JS path for a session.

**3. `LD_PRELOAD`.** Termux preloads `libtermux-exec-ld-preload.so`, a *bionic* library
that a musl process cannot relocate — it fails on `__register_atfork`, `__errno` and the
`__*_chk` fortify family before Claude Code even starts. The wrapper drops it for the
binary only.

Anthropic builds and signs the binary; only the loader placement and the DNS shim are ours.

## Updating

The built-in updater is disabled, because it would fetch the **glibc** `linux-arm64` build
over this install. Use:

```bash
claude-musl-update                  # follows the `latest` npm dist-tag
claude-musl-update --check          # report versions, change nothing
claude-musl-update --channel next   # stable | latest | next
claude-musl-update --version 2.1.273
claude-musl-update --rollback       # swap back to the previous binary
```

It downloads into the install directory so the final move is an atomic rename, verifies the
npm `sha512` integrity hash, repoints the interpreter, and **runs the new binary to confirm
it reports the expected version** before replacing anything. Any failure leaves the old
binary untouched.

`--no-backup` skips keeping `claude.prev` and saves ~212MB. Rollback then means naming a
version instead — all published versions are a ~7s re-fetch away.

## Caveats

- **The two launchers both want the name `claude`.** If you also run wallentx's,
  `claude-termux-update` installs `(claude.glibc, claude-termux-update, claude)` into
  `$PREFIX/bin`, which replaces the promoted symlink and puts you back on glibc without
  announcing it. Recover with `ln -sf claude-musl $PREFIX/bin/claude`.
- **In-session `grep` is not GNU grep.** Claude Code's shim routes it to its bundled ugrep
  with `--ignore-files --hidden -I -G`, so gitignored files are skipped — an empty result
  can mean "ignored", not "absent". Use `command grep` when a negative result matters.
- **Shells started by Claude Code have no `LD_PRELOAD`**, so `termux-exec` is not active in
  them and scripts with foreign shebangs (`#!/usr/bin/env python3`) fail — Android has no
  `/usr/bin/env`. The glibc launcher behaves the same way.
- If search ever misbehaves, Anthropic's Alpine guidance is to set `USE_BUILTIN_RIPGREP=0`
  and install system ripgrep (`pkg install ripgrep`).
- **Long sessions, background tasks, subagents and MCP servers all work.** This README's
  own updates came out of a multi-hour `claude-musl` session that spawned background jobs
  and subagents and had them report back. A local stdio MCP server (bun, over JSON-RPC)
  connects and is spawned as a child process, and the remote `claude.ai` servers — Docs,
  Drive, Gmail, Calendar — connect over HTTPS through the DNS proxy.

## Uninstall

```bash
./uninstall.sh            # restores the previous `claude` if this replaced it
./uninstall.sh --loader   # …and removes the shared musl loader
```

`~/.claude` — settings, credentials, session history — is never touched.

## Related

The same musl approach works for other AI CLIs on Android:

- **[agy-termux-musl](https://github.com/Aarstad/agy-termux-musl)** — Google's Antigravity
  CLI. Harder: its glibc-only binary needs 24 bytes of patches to fix two hard-coded glibc
  layout assumptions, plus a symbol shim and a CA-bundle path. Reuses this repo's musl
  loader and `dns-proxy.c`.
- **OpenAI's Codex CLI** needs none of this — it ships a *statically linked*
  `aarch64-unknown-linux-musl` build that bionic runs as-is. Take the GitHub release
  asset, not the npm package: `@openai/codex` declares no musl dependency, so `npm i -g`
  fetches a glibc binary that cannot run.

## Credits

- [wallentx/claude-code-termux](https://github.com/wallentx/claude-code-termux) for the
  glibc launcher that proved Claude Code could run in Termux at all, and for the in-process
  DNS proxy design this borrows.
- Anthropic, for publishing musl builds.

## License

MIT
