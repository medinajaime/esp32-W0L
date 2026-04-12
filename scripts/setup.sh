#!/usr/bin/env bash
# ============================================================
# esp32-wol - Guided Linux/macOS/WSL setup
# Configure, build, and flash ESP32 Wake-on-LAN via Tailscale.
# ============================================================
set -e

IDF_VERSION="v5.5.3"
IDF_INSTALL_DIR="${IDF_INSTALL_DIR:-$HOME/esp/esp-idf}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}[OK]${RESET} $*"; }
info() { echo -e "  $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
err()  { echo -e "${RED}[ERR]${RESET} $*" >&2; }
die()  { err "$*"; exit 1; }

confirm() {
  local prompt="$1"
  local answer
  read -r -p "$prompt [Y/n] " answer
  case "${answer:-Y}" in
    y|Y|yes|YES|Yes) return 0 ;;
    *) return 1 ;;
  esac
}

run_sudo() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    die "This step needs root privileges, but sudo is not installed. Install the missing packages manually and rerun setup.sh."
  fi
}

install_linux_packages() {
  case "$(uname -s 2>/dev/null || echo unknown)" in
    Linux*) ;;
    *)
      warn "Automatic package installation is only supported on Linux. Install git and Python manually, then rerun setup.sh."
      return 1
      ;;
  esac

  if command -v apt-get >/dev/null 2>&1; then
    run_sudo apt-get update
    run_sudo apt-get install -y git wget flex bison gperf python3 python3-pip python3-venv cmake ninja-build ccache libffi-dev libssl-dev dfu-util libusb-1.0-0
  elif command -v dnf >/dev/null 2>&1; then
    run_sudo dnf install -y git wget flex bison gperf python3 python3-pip cmake ninja-build ccache libffi-devel openssl-devel dfu-util libusbx
  elif command -v pacman >/dev/null 2>&1; then
    run_sudo pacman -Syu --needed --noconfirm git wget flex bison gperf python python-pip cmake ninja ccache libffi openssl dfu-util libusb
  elif command -v zypper >/dev/null 2>&1; then
    run_sudo zypper install -y git wget flex bison gperf python3 python3-pip cmake ninja ccache libffi-devel libopenssl-devel dfu-util libusb-1_0-0
  else
    warn "No supported package manager found. Install git, wget, python3, cmake, ninja, and ESP-IDF prerequisites manually."
    return 1
  fi
}

ensure_bootstrap_tools() {
  local missing=()
  for tool in git python3; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done

  if [[ ${#missing[@]} -eq 0 ]]; then
    return 0
  fi

  warn "Missing required setup tools: ${missing[*]}"
  if confirm "Install common ESP-IDF Linux prerequisites now?"; then
    install_linux_packages
  else
    die "Install ${missing[*]} and rerun setup.sh."
  fi
}

install_idf_from_source() {
  ensure_bootstrap_tools

  if [[ -d "$IDF_INSTALL_DIR/.git" ]]; then
    warn "ESP-IDF checkout exists at $IDF_INSTALL_DIR but export.sh was not found."
    if confirm "Update and repair this ESP-IDF checkout?"; then
      git -C "$IDF_INSTALL_DIR" fetch --tags --recurse-submodules
      git -C "$IDF_INSTALL_DIR" checkout "$IDF_VERSION"
      git -C "$IDF_INSTALL_DIR" submodule update --init --recursive
    else
      die "ESP-IDF checkout is incomplete. Repair it or set IDF_PATH to a working ESP-IDF install."
    fi
  else
    if ! confirm "ESP-IDF $IDF_VERSION was not found. Clone it to $IDF_INSTALL_DIR and install tools?"; then
      die "Install ESP-IDF $IDF_VERSION or set IDF_PATH, then rerun setup.sh."
    fi

    mkdir -p "$(dirname "$IDF_INSTALL_DIR")"
    git clone --recursive --branch "$IDF_VERSION" https://github.com/espressif/esp-idf.git "$IDF_INSTALL_DIR"
  fi

  "$IDF_INSTALL_DIR/install.sh" esp32
}

case "$(uname -s 2>/dev/null || echo unknown)" in
  Linux*|Darwin*|MSYS*|MINGW*|CYGWIN*) ;;
  *)
    die "setup.sh requires a Linux/macOS/WSL/Git-Bash style shell. On Windows PowerShell, run: .\\scripts\\setup.ps1"
    ;;
esac

if command -v grep >/dev/null 2>&1 && grep -q $'\r' "$0"; then
  die "setup.sh has Windows CRLF line endings. Re-checkout the repo after .gitattributes is applied, or run: dos2unix scripts/setup.sh"
fi

echo ""
echo -e "${CYAN}esp32-wol - Linux setup${RESET}"
echo -e "${CYAN}ESP32 Wake-on-LAN via Tailscale${RESET}"
echo ""

[[ -f CMakeLists.txt && -f sdkconfig.defaults ]] || \
  die "Run this script from the esp32-wakeonlan project root."

[[ -d "lib/tailscale/src" ]] || \
  die "Vendored Tailscale library not found in lib/tailscale/. Is the repo intact?"
ok "Project layout verified"

find_idf() {
  for path in "${IDF_PATH:-}" "$HOME/esp/esp-idf" "$HOME/esp-idf" "/opt/esp-idf"; do
    [[ -f "$path/export.sh" ]] && echo "$path" && return 0
  done
  return 1
}

IDF_FOUND=$(find_idf) || {
  err "ESP-IDF not found."
  install_idf_from_source
  IDF_FOUND=$(find_idf) || die "ESP-IDF install finished, but export.sh was not found. Check $IDF_INSTALL_DIR and rerun setup.sh."
}
ok "ESP-IDF found at: $IDF_FOUND"

# shellcheck disable=SC1091
source "$IDF_FOUND/export.sh" > /dev/null 2>&1
ok "ESP-IDF environment activated"

echo ""
echo -e "${BOLD}Configuration${RESET}"
echo ""

read -r  -p "  WiFi SSID               : " WIFI_SSID
read -rs -p "  WiFi Password           : " WIFI_PASS; echo ""
echo ""
read -rs -p "  Tailscale Auth Key      : " TS_KEY; echo ""
echo -e "  ${DIM}(get one at https://login.tailscale.com/admin/settings/keys)${RESET}"
echo ""
read -r  -p "  Target PC MAC address   : " TARGET_MAC
echo -e "  ${DIM}(Linux: ip link show  |  Windows: ipconfig /all)${RESET}"
echo ""
read -r  -p "  Device name    [esp32-wol]       : " DEVICE_NAME
read -r  -p "  Listen port    [9999]            : " LISTEN_PORT
read -r  -p "  Broadcast IP   [255.255.255.255] : " BROADCAST_IP
read -r  -p "  Serial port    [/dev/ttyUSB0]    : " PORT

DEVICE_NAME=${DEVICE_NAME:-esp32-wol}
LISTEN_PORT=${LISTEN_PORT:-9999}
BROADCAST_IP=${BROADCAST_IP:-255.255.255.255}
PORT=${PORT:-/dev/ttyUSB0}

echo ""
[[ -n "$WIFI_SSID" ]] || die "WiFi SSID cannot be empty."
[[ -n "$TS_KEY" ]] || die "Tailscale auth key cannot be empty."

if ! echo "$TARGET_MAC" | grep -qE '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'; then
  die "Invalid MAC address: '$TARGET_MAC' (expected format: AA:BB:CC:DD:EE:FF)"
fi

if ! echo "$LISTEN_PORT" | grep -qE '^[0-9]+$' || \
     (( LISTEN_PORT < 1024 || LISTEN_PORT > 65535 )); then
  die "Listen port must be a number between 1024 and 65535."
fi

[[ -e "$PORT" ]] || warn "Serial port $PORT not found - continuing anyway."
ok "Configuration validated"

echo ""
echo -e "${BOLD}Summary${RESET}"
info "WiFi SSID     : $WIFI_SSID"
info "Target MAC    : $TARGET_MAC"
info "Device name   : $DEVICE_NAME"
info "Listen port   : $LISTEN_PORT"
info "Broadcast IP  : $BROADCAST_IP"
info "Serial port   : $PORT"
echo ""

USER_CONFIG=$(mktemp /tmp/wol_config_XXXX)
cleanup() {
  rm -f "$USER_CONFIG"
}
trap cleanup EXIT

cat > "$USER_CONFIG" << CONF
CONFIG_WOL_WIFI_SSID="$WIFI_SSID"
CONFIG_WOL_WIFI_PASSWORD="$WIFI_PASS"
CONFIG_WOL_TAILSCALE_AUTH_KEY="$TS_KEY"
CONFIG_WOL_TARGET_MAC="$TARGET_MAC"
CONFIG_WOL_DEVICE_NAME="$DEVICE_NAME"
CONFIG_WOL_LISTEN_PORT=$LISTEN_PORT
CONFIG_WOL_BROADCAST_IP="$BROADCAST_IP"
CONF

# Remove stale sdkconfig so SDKCONFIG_DEFAULTS takes full effect.
rm -f sdkconfig sdkconfig.old

echo -e "${BOLD}Building firmware...${RESET}"
echo ""
if ! SDKCONFIG_DEFAULTS="sdkconfig.defaults;$USER_CONFIG" idf.py build; then
  err "idf.py build failed."
  echo ""
  echo "If the failure mentions ESP-IDF mbedtls or mbedcrypto, repair ESP-IDF:"
  echo -e "${DIM}cd \"$IDF_FOUND\""
  echo "git submodule update --init --recursive"
  echo "./install.sh esp32"
  echo "source ./export.sh${RESET}"
  exit 1
fi
echo ""
ok "Build complete"

echo ""
echo -e "${BOLD}Flashing to $PORT...${RESET}"
echo ""
SDKCONFIG_DEFAULTS="sdkconfig.defaults;$USER_CONFIG" idf.py flash -p "$PORT"

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
cp scripts/wake-pc "$INSTALL_DIR/wake-pc"
chmod +x "$INSTALL_DIR/wake-pc"

if echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
  ok "wake-pc installed to $INSTALL_DIR (already on PATH)"
else
  warn "wake-pc installed to $INSTALL_DIR"
  echo ""
  echo "Add it to your PATH by adding this to your shell profile:"
  echo ""
  echo -e "${DIM}export PATH=\"\$HOME/.local/bin:\$PATH\"${RESET}"
fi

echo ""
echo -e "${GREEN}Done! ESP32 flashed successfully.${RESET}"
echo ""
echo "Open the serial monitor to see the ESP32 Tailscale IP:"
echo ""
echo -e "${CYAN}idf.py monitor -p $PORT${RESET}"
echo ""
echo "Then save it as the default and wake your PC from anywhere:"
echo ""
echo -e "${CYAN}wake-pc --save <esp32-tailscale-ip>${RESET}"
echo -e "${CYAN}wake-pc${RESET} ${DIM}# uses saved default from now on${RESET}"
echo ""
