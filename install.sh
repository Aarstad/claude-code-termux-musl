#!/data/data/com.termux/files/usr/bin/bash
# Install Claude Code's musl build to run natively in Termux, without glibc.
#
#   ./install.sh                 install as `claude-musl`
#   ./install.sh --promote       …and make it the default `claude`
#   ./install.sh --channel next  install from a channel: stable | latest | next
#
# Not "#!/usr/bin/env bash" on purpose: Android has no /usr/bin/env, and the
# termux-exec shim that normally rewrites that is absent inside Claude Code sessions.
set -euo pipefail

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
LIBEXEC="$PREFIX/libexec/claude-musl"
LOADER="$PREFIX/lib/ld-musl-aarch64.so.1"
ALPINE="${ALPINE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine/latest-stable/main/aarch64}"

PROMOTE=0
CHANNEL=latest
while [ $# -gt 0 ]; do
  case "$1" in
    --promote) PROMOTE=1 ;;
    --channel) shift; CHANNEL="${1:-latest}" ;;
    -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "install.sh: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { echo "install.sh: $*" >&2; exit 1; }

# --- preflight ---------------------------------------------------------------
[ "$(uname -m)" = "aarch64" ] || die "this targets aarch64; found $(uname -m)"
[ -d "$PREFIX/bin" ] || die "no $PREFIX/bin — this installs into Termux"
command -v curl >/dev/null || die "curl is required (pkg install curl)"
command -v tar  >/dev/null || die "tar is required"
# tar shells out to gzip; without it the extraction fails in a way that looks like a
# corrupt download rather than a missing tool.
command -v gzip >/dev/null || die "gzip is required (pkg install gzip)"

if ! command -v patchelf >/dev/null; then
  say "installing patchelf"
  pkg install -y patchelf >/dev/null || die "could not install patchelf"
fi

if command -v bun >/dev/null; then
  say "proxy runtime: bun $(bun --version)"
elif command -v node >/dev/null; then
  say "proxy runtime: node $(node --version) — bun is ~9x faster to start (pkg install bun)"
else
  die "need bun or node for the DNS proxy (pkg install bun)"
fi

# --- musl loader -------------------------------------------------------------
# The musl build asks for /lib/ld-musl-aarch64.so.1. Android has no /lib and it is
# not writable without root, so the loader goes in $PREFIX and patchelf repoints the
# binary at it. Alpine's musl package is where the loader comes from.
if [ -x "$LOADER" ]; then
  say "musl loader already present"
else
  say "fetching the musl loader from Alpine"
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  apk="$(curl -fsSL "$ALPINE/" | sed -n 's/.*href="\(musl-[0-9][^"]*\.apk\)".*/\1/p' | head -1)"
  [ -n "$apk" ] || die "could not find a musl package at $ALPINE"
  curl -fsSL -o "$tmp/musl.apk" "$ALPINE/$apk"
  # An .apk is concatenated gzip streams; tar reads the first, which holds the files.
  # Its exit status is not meaningful here, but its stderr is, so it is left visible.
  tar xzf "$tmp/musl.apk" -C "$tmp" || true
  [ -f "$tmp/lib/ld-musl-aarch64.so.1" ] || die "no loader inside $apk (extraction failed?)"
  mkdir -p "$(dirname "$LOADER")"
  install -m 755 "$tmp/lib/ld-musl-aarch64.so.1" "$LOADER"
  rm -rf "$tmp"; trap - EXIT
  say "installed $LOADER ($(du -k "$LOADER" | cut -f1)KB, from $apk)"
fi

# --- our pieces --------------------------------------------------------------
say "installing wrapper, updater and proxy"
mkdir -p "$LIBEXEC"
install -m 755 "$HERE/bin/claude-musl"        "$PREFIX/bin/claude-musl"
install -m 755 "$HERE/bin/claude-musl-update" "$PREFIX/bin/claude-musl-update"
install -m 644 "$HERE/libexec/dns-proxy.js"   "$LIBEXEC/dns-proxy.js"
[ -f "$HERE/README.md" ] && install -m 644 "$HERE/README.md" "$LIBEXEC/README.md"

# --- the binary --------------------------------------------------------------
# One code path for install and update: the updater fetches, checks the npm
# integrity hash, repoints the interpreter, proves the result runs, then swaps it in.
say "fetching Claude Code (channel: $CHANNEL) — about 95MB"
"$PREFIX/bin/claude-musl-update" --channel "$CHANNEL" --no-backup

# --- optionally take over the `claude` name ----------------------------------
if [ "$PROMOTE" = 1 ]; then
  if [ -L "$PREFIX/bin/claude" ] && [ "$(readlink "$PREFIX/bin/claude")" = "claude-musl" ]; then
    say "already promoted"
  elif [ -e "$PREFIX/bin/claude" ]; then
    [ -e "$PREFIX/bin/claude-glibc" ] && die "won't move $PREFIX/bin/claude: claude-glibc already exists"
    say "moving the existing claude to claude-glibc"
    mv "$PREFIX/bin/claude" "$PREFIX/bin/claude-glibc"
    "$PREFIX/bin/claude-glibc" --version >/dev/null 2>&1 \
      || echo "  note: claude-glibc did not report a version; it may need its original name" >&2
    ln -s claude-musl "$PREFIX/bin/claude"
  else
    ln -s claude-musl "$PREFIX/bin/claude"
  fi
fi

# --- verify ------------------------------------------------------------------
v="$("$PREFIX/bin/claude-musl" --version 2>&1 || true)"
case "$v" in
  *"Claude Code"*) say "installed: $v" ;;
  *) die "installed, but claude-musl did not report a version (said: ${v:-nothing})" ;;
esac

echo
echo "  run it with:   claude-musl"
[ "$PROMOTE" = 1 ] && echo "  or just:       claude        (claude-glibc still runs the old install)"
echo "  update it:     claude-musl-update [--channel stable|latest|next]"
echo "  log in first:  claude-musl   (then follow the browser prompts)"
