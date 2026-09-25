#!/usr/bin/env bash
# Put the llama.cpp runtime the desktop app ships with into
# desktop/src-tauri/llama, on macOS or Linux.
#
# Downloads a pinned llama.cpp release from github.com/ggml-org/llama.cpp,
# checks it against the SHA-256 digest recorded below, and copies
# llama-server with the libraries it loads. Nothing else is bundled.
#
#   scripts/fetch-llama.sh              # the platform's default build
#   LLAMA_TAG=b11026 scripts/fetch-llama.sh
#
# Windows: use scripts/fetch-llama.ps1.
set -euo pipefail

TAG="${LLAMA_TAG:-b11026}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/desktop/src-tauri/llama"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  ASSET="llama-$TAG-bin-macos-arm64.tar.gz" ;;
  Darwin-x86_64) ASSET="llama-$TAG-bin-macos-x64.tar.gz" ;;
  Linux-x86_64)  ASSET="llama-$TAG-bin-ubuntu-vulkan-x64.tar.gz" ;;
  Linux-aarch64) ASSET="llama-$TAG-bin-ubuntu-vulkan-arm64.tar.gz" ;;
  *) echo "no llama.cpp build is pinned for $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac

# Digests as GitHub publishes them for these assets. A new tag needs its
# digests added here; nothing unpinned is bundled.
digest_for() {
  case "$1" in
    llama-b11026-bin-macos-arm64.tar.gz)        echo dbbfc7bd866a2594fea3bb10b56c5b205fffdaba23695f89da053b76e9a456d2 ;;
    llama-b11026-bin-macos-x64.tar.gz)          echo efa554e37e6fe9cb274734cf841fdca55fd92155980c8539bcbd83b77c3dc6cc ;;
    llama-b11026-bin-ubuntu-vulkan-x64.tar.gz)  echo 1b40310bf4d47c2c84853ebb4ccaf4dcbd992596cd1c2f610be6a0532a874708 ;;
    llama-b11026-bin-ubuntu-vulkan-arm64.tar.gz) echo a7467230a5e12475a8be95fbfb539bd5415c25ea42eccb354c2f24dd4ea9ec8a ;;
    *) echo "" ;;
  esac
}

EXPECTED="$(digest_for "$ASSET")"
if [ -z "$EXPECTED" ]; then
  echo "no pinned digest for $ASSET; add it to digest_for before bundling a new build" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
URL="https://github.com/ggml-org/llama.cpp/releases/download/$TAG/$ASSET"
echo "Downloading $URL"
curl -fsSL "$URL" -o "$WORK/$ASSET"

if command -v sha256sum >/dev/null; then
  ACTUAL="$(sha256sum "$WORK/$ASSET" | cut -d' ' -f1)"
else
  ACTUAL="$(shasum -a 256 "$WORK/$ASSET" | cut -d' ' -f1)"
fi
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "digest mismatch for $ASSET: expected $EXPECTED, got $ACTUAL" >&2
  exit 1
fi

mkdir -p "$WORK/x"
tar -xzf "$WORK/$ASSET" -C "$WORK/x"
SERVER="$(find "$WORK/x" -type f -name llama-server | head -n1)"
[ -n "$SERVER" ] || { echo "the archive has no llama-server" >&2; exit 1; }
SRC="$(dirname "$SERVER")"

rm -rf "$DEST"
mkdir -p "$DEST"
cp "$SERVER" "$DEST/"
# Shared libraries, keeping symlinks so sonames resolve as they did in the
# release. Libraries only other llama.cpp tools link are left out.
find "$SRC" -maxdepth 1 \( -name '*.so*' -o -name '*.dylib' \) ! -name '*-impl*' -exec cp -P {} "$DEST/" \;
find "$SRC" -maxdepth 1 -name 'llama-server-impl*' -exec cp -P {} "$DEST/" \;
find "$SRC/.." -maxdepth 2 -name 'LICENSE*' -type f -exec cp {} "$DEST/" \; 2>/dev/null || true
cp "$ROOT/scripts/llama-LICENSE.txt" "$DEST/LICENSE-llama.cpp.txt"
chmod +x "$DEST/llama-server"

cat > "$DEST/BUNDLED.txt" <<EOF
llama.cpp $TAG, bundled with Cordon.
Source: https://github.com/ggml-org/llama.cpp/releases/tag/$TAG
Origin: $ASSET (sha256 $ACTUAL)
EOF

echo "Bundled into $DEST: $("$DEST/llama-server" --version 2>&1 | grep -m1 version || true)"
