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
- `bun` — strongly recommended (`pkg install bun`); `node` works but starts ~9× slower
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
resolvers, so `dns-proxy.js` runs on bun (or node) and the binary tunnels through it via
`HTTPS_PROXY`. The proxy is loopback-only, starts with the session and exits with it.

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

- **If you also have wallentx's launcher, its updater will clobber `claude`.**
  `claude-termux-update` installs `(claude.glibc, claude-termux-update, claude)` into
  `$PREFIX/bin`, overwriting the promoted symlink and putting you silently back on glibc.
  Recover with `ln -sf claude-musl $PREFIX/bin/claude`.
- **In-session `grep` is not GNU grep.** Claude Code's shim routes it to its bundled ugrep
  with `--ignore-files --hidden -I -G`, so gitignored files are skipped — an empty result
  can mean "ignored", not "absent". Use `command grep` when a negative result matters.
- **Shells started by Claude Code have no `LD_PRELOAD`**, so `termux-exec` is not active in
  them and scripts with foreign shebangs (`#!/usr/bin/env python3`) fail — Android has no
  `/usr/bin/env`. The glibc launcher behaves the same way.
- If search ever misbehaves, Anthropic's Alpine guidance is to set `USE_BUILTIN_RIPGREP=0`
  and install system ripgrep (`pkg install ripgrep`).
- Untested: long sessions under load, subagents, background tasks, MCP servers.

## Uninstall

```bash
./uninstall.sh            # restores the previous `claude` if this replaced it
./uninstall.sh --loader   # …and removes the shared musl loader
```

`~/.claude` — settings, credentials, session history — is never touched.

## Credits

- [wallentx/claude-code-termux](https://github.com/wallentx/claude-code-termux) for the
  glibc launcher that proved Claude Code could run in Termux at all, and for the in-process
  DNS proxy design this borrows.
- Anthropic, for publishing musl builds.

## License

MIT
