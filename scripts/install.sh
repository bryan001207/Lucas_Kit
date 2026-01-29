#!/usr/bin/env sh
set -eu

# Usage:
#   curl -fsSL https://raw.githubusercontent.com/lucasenlucas/Lucas_DNS/main/scripts/install.sh | sh
#   Of: REPO="owner/repo" sh install.sh
#
# Installs latest GitHub Release asset into /usr/local/bin (or ~/.local/bin if not writable)
# Automatisch detecteert architecture (amd64/arm64) en OS (Linux/macOS/Windows)

REPO="${REPO:-lucasenlucas/Lucas_Kit}"
BIN_NAME="${BIN_NAME:-lucasdns}"
BIN_NAME_2="${BIN_NAME_2:-lucaskill}"

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

# Expect artifact naming like: lucasdns_<os>_<arch>.tar.gz (or .zip for windows)
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

if [ ! -f "./${BIN_NAME}" ] && [ -f "./${BIN_NAME}.exe" ]; then
  BIN_NAME="${BIN_NAME}.exe"
fi

if [ ! -f "./${BIN_NAME}" ]; then
  echo "❌ Binary ${BIN_NAME} niet gevonden in archive."
  exit 1
fi

# Check for second binary (lucaskill)
if [ ! -f "./${BIN_NAME_2}" ] && [ -f "./${BIN_NAME_2}.exe" ]; then
  BIN_NAME_2="${BIN_NAME_2}.exe"
fi

if [ ! -f "./${BIN_NAME_2}" ]; then
  echo "⚠️  Binary ${BIN_NAME_2} niet gevonden in archive. (Oudere versie?)"
fi

chmod +x "./${BIN_NAME}"
if [ -f "./${BIN_NAME_2}" ]; then
  chmod +x "./${BIN_NAME_2}"
fi

# Installeren met of zonder sudo
if [ "$needs_sudo" = true ]; then
  echo "🔐 Installeren naar ${dest} (vereist sudo)..."
  sudo mv "./${BIN_NAME}" "${dest}/lucasdns"
  sudo chmod +x "${dest}/lucasdns"
  
  if [ -f "./${BIN_NAME_2}" ]; then
    echo "🔐 Installeren ${BIN_NAME_2}..."
    sudo mv "./${BIN_NAME_2}" "${dest}/lucaskill"
    sudo chmod +x "${dest}/lucaskill"
  fi
else
  echo "📁 Installeren naar ${dest}..."
  mv "./${BIN_NAME}" "${dest}/lucasdns"
  chmod +x "${dest}/lucasdns"

  if [ -f "./${BIN_NAME_2}" ]; then
    mv "./${BIN_NAME_2}" "${dest}/lucaskill"
    chmod +x "${dest}/lucaskill"
  fi
fi

echo ""
echo "✅ lucasdns succesvol geïnstalleerd naar ${dest}/lucasdns"
if [ -f "${dest}/lucaskill" ]; then
    echo "✅ lucaskill succesvol geïnstalleerd naar ${dest}/lucaskill"
fi
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
    echo "Of test direct: ${dest}/lucasdns --help"
  else
    echo "🎉 Klaar! Run: lucasdns --help"
  fi
else
  # Test of het werkt
  if command -v lucasdns >/dev/null 2>&1; then
    echo "🎉 Klaar! Run: lucasdns --help"
  else
    echo "⚠️  lucasdns staat mogelijk niet in je PATH."
    echo "   Run: export PATH=\"${dest}:\$PATH\""
    echo "   Of open een nieuwe terminal."
  fi
fi
