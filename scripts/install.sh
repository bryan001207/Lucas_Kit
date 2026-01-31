#!/usr/bin/env sh
set -eu

# Usage:
#   curl -fsSL https://raw.githubusercontent.com/lucasenlucas/Lucas_Kit/main/scripts/install.sh | sh
#   Of: REPO="owner/repo" sh install.sh
#
# Installs latest GitHub Release asset into /usr/local/bin (or ~/.local/bin if not writable)
# Automatisch detecteert architecture (amd64/arm64) en OS (Linux/macOS/Windows)

REPO="${REPO:-lucasenlucas/Lucas_Kit}"
BIN_1="ultradns"
BIN_2="sitestress"
BIN_3="ultracrack"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_RAW="$(uname -m)"

case "$OS" in
  linux) OS="linux" ;;
  darwin) OS="darwin" ;;
  msys*|mingw*|cygwin*) OS="windows" ;;
esac

case "$ARCH_RAW" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) 
    echo "❌ Onbekende architecture: $ARCH_RAW"
    echo "Ondersteund: x86_64/amd64, arm64/aarch64"
    exit 1
    ;;
esac

echo "🔍 Detecteerd: OS=$OS, Architecture=$ARCH ($ARCH_RAW)"

api="https://api.github.com/repos/${REPO}/releases/latest"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "📦 Downloaden laatste release van ${REPO} voor ${OS}/${ARCH}..."

# Expect artifact naming like: lucaskit_<os>_<arch>.tar.gz (or .zip for windows)
# Old naming was lucasdns_...
# New naming is lucaskit_...
asset=""
json="$(curl -fsSL "$api")"
asset="$(printf "%s" "$json" | grep -Eo '"browser_download_url":[^"]*"[^"]+"' | cut -d'"' -f4 | grep -E "${OS}_${ARCH}" | head -n 1 || true)"

if [ -z "$asset" ]; then
  echo "❌ Geen release asset gevonden voor ${OS}_${ARCH}."
  echo "Check https://github.com/${REPO}/releases"
  exit 1
fi

cd "$tmpdir"
echo "⬇️  Downloaden: $(basename "$asset")"
curl -fsSL -o asset "$asset"

# Probeer eerst /usr/local/bin (vereist sudo op Kali Linux)
dest="/usr/local/bin"
needs_sudo=false
if [ ! -w "$dest" ]; then
  # Check of sudo beschikbaar is
  if command -v sudo >/dev/null 2>&1; then
    needs_sudo=true
  else
    # Fallback naar ~/.local/bin als sudo niet beschikbaar is
    dest="${HOME}/.local/bin"
    mkdir -p "$dest"
  fi
fi

case "$asset" in
  *.tar.gz)
    tar -xzf asset
    ;;
  *.zip)
    unzip -q asset
    ;;
  *)
    echo "Unknown archive format: $asset"
    exit 1
    ;;
esac

# Function to install binary
install_bin() {
  bin="$1"
  
  # Handle windows extension check if needed (though this script is mostly unix)
  if [ ! -f "./${bin}" ] && [ -f "./${bin}.exe" ]; then
    bin="${bin}.exe"
  fi

  if [ ! -f "./${bin}" ]; then
    echo "⚠️  Binary ${bin} niet gevonden in archive."
    return
  fi

  chmod +x "./${bin}"
  
  if [ "$needs_sudo" = true ]; then
    echo "🔐 Installeren ${bin} naar ${dest}..."
    sudo mv "./${bin}" "${dest}/${bin%.exe}"
    sudo chmod +x "${dest}/${bin%.exe}"
  else
    echo "📁 Installeren ${bin} naar ${dest}..."
    mv "./${bin}" "${dest}/${bin%.exe}"
    chmod +x "${dest}/${bin%.exe}"
  fi
  echo "✅ ${bin} succesvol geïnstalleerd"
}

install_bin "$BIN_1"
install_bin "$BIN_2"
install_bin "$BIN_3"

echo ""

# Check if dest is in PATH
if [ "$dest" = "${HOME}/.local/bin" ]; then
  if ! echo "$PATH" | grep -q "${HOME}/.local/bin"; then
    echo "⚠️  ${dest} staat niet in je PATH!"
    echo ""
    # Detecteer shell
    if [ -n "$ZSH_VERSION" ]; then
      SHELL_RC="$HOME/.zshrc"
    elif [ -n "$BASH_VERSION" ]; then
      SHELL_RC="$HOME/.bashrc"
    else
      SHELL_RC="$HOME/.profile"
    fi
    
    echo "Voeg dit toe aan ${SHELL_RC}:"
    echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    echo "Of run direct:"
    echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ${SHELL_RC}"
    echo "  source ${SHELL_RC}"
    echo ""
    echo "Of test direct: ${dest}/${BIN_1} --help"
  else
    echo "🎉 Klaar! Run: ${BIN_1} --help"
  fi
else
  # Test of het werkt
  if command -v "${BIN_1}" >/dev/null 2>&1; then
    echo "🎉 Klaar! Run: ${BIN_1} --help"
  else
    echo "⚠️  ${BIN_1} staat mogelijk niet in je PATH."
    echo "   Run: export PATH=\"${dest}:\$PATH\""
    echo "   Of open een nieuwe terminal."
  fi
fi
