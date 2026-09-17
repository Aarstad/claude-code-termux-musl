#!/data/data/com.termux/files/usr/bin/bash
# Remove the musl install. Leaves ~/.claude (your settings, credentials, history) alone.
#
#   ./uninstall.sh              remove the musl install
#   ./uninstall.sh --loader     …and the shared musl loader in $PREFIX/lib
#
set -euo pipefail

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
LIBEXEC="$PREFIX/libexec/claude-musl"
LOADER="$PREFIX/lib/ld-musl-aarch64.so.1"
DROP_LOADER=0
[ "${1:-}" = "--loader" ] && DROP_LOADER=1

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

# If `claude` points at us, hand the name back to whatever it displaced.
if [ -L "$PREFIX/bin/claude" ] && [ "$(readlink "$PREFIX/bin/claude")" = "claude-musl" ]; then
  rm -f "$PREFIX/bin/claude"
  if [ -e "$PREFIX/bin/claude-glibc" ]; then
    mv "$PREFIX/bin/claude-glibc" "$PREFIX/bin/claude"
    say "restored the previous claude ($("$PREFIX/bin/claude" --version 2>/dev/null || echo 'version unknown'))"
  else
    say "removed the claude symlink (nothing to restore)"
  fi
fi

rm -f "$PREFIX/bin/claude-musl" "$PREFIX/bin/claude-musl-update"
freed="$(du -ms "$LIBEXEC" 2>/dev/null | cut -f1 || echo 0)"
rm -rf "$LIBEXEC"
say "removed the wrapper, updater and binaries (${freed}MB)"

if [ "$DROP_LOADER" = 1 ]; then
  rm -f "$LOADER"
  say "removed $LOADER"
else
  say "kept $LOADER (pass --loader to remove it)"
fi

echo
echo "  ~/.claude was not touched: settings, credentials and history are intact."
