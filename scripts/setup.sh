#!/usr/bin/env bash
# ============================================================
#  esp32-wol  —  Guided setup: configure, build, and flash
# ============================================================
set -e

# ── Colours ─────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}✓${RESET} $*"; }
info() { echo -e "  $*"; }
warn() { echo -e "${YELLOW}⚠${RESET}  $*"; }
err()  { echo -e "${RED}✗${RESET} $*" >&2; }
die()  { err "$*"; exit 1; }

# ── Banner ───────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  esp32-wol  —  Setup                     ║${RESET}"
echo -e "${CYAN}║  ESP32 Wake-on-LAN via Tailscale          ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${RESET}"
echo ""

# ── Check we are in the right directory ─────────────────────
[[ -f CMakeLists.txt && -f sdkconfig.defaults ]] || \
  die "Run this script from the wol-esp32 project root."

# ── Check vendored Tailscale library ──────────────────────────
[[ -d "lib/tailscale/src" ]] || die "Vendored Tailscale library not found in lib/tailscale/. Is the repo intact?"
ok "Tailscale library found"

# ── Find ESP-IDF ─────────────────────────────────────────────
find_idf() {
  for path in "${IDF_PATH:-}" "$HOME/esp/esp-idf" "$HOME/esp-idf" "/opt/esp-idf"; do
    [[ -f "$path/export.sh" ]] && echo "$path" && return 0
  done
  return 1
}

IDF_FOUND=$(find_idf) || {
  err "ESP-IDF not found."
  echo ""
  echo "  Install ESP-IDF v5.5.3:"
  echo ""
  echo -e "  ${DIM}mkdir -p ~/esp && cd ~/esp"
  echo -e "  git clone --recursive https://github.com/espressif/esp-idf.git"
  echo -e "  cd esp-idf && git checkout v5.5.3"
  echo -e "  ./install.sh esp32"
  echo -e "  cd -${RESET}"
  echo ""
  die "Install ESP-IDF and re-run setup.sh"
}
ok "ESP-IDF found at: $IDF_FOUND"

# Source ESP-IDF (suppress output)
# shellcheck disable=SC1091
source "$IDF_FOUND/export.sh" > /dev/null 2>&1
ok "ESP-IDF environment activated"

# ── Collect configuration ────────────────────────────────────
echo ""
echo -e "${BOLD}Configuration${RESET}"
echo -e "${DIM}──────────────────────────────────────────${RESET}"
echo ""

read -r  -p "  WiFi SSID               : " WIFI_SSID
read -rs -p "  WiFi Password           : " WIFI_PASS;  echo ""
echo ""
read -rs -p "  Tailscale Auth Key      : " TS_KEY;     echo ""
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

# ── Validate inputs ──────────────────────────────────────────
echo ""
[[ -n "$WIFI_SSID" ]]  || die "WiFi SSID cannot be empty."
[[ -n "$TS_KEY" ]]     || die "Tailscale auth key cannot be empty."

if ! echo "$TARGET_MAC" | grep -qE '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'; then
  die "Invalid MAC address: '$TARGET_MAC'  (expected format: AA:BB:CC:DD:EE:FF)"
fi

if ! echo "$LISTEN_PORT" | grep -qE '^[0-9]+$' || \
     (( LISTEN_PORT < 1024 || LISTEN_PORT > 65535 )); then
  die "Listen port must be a number between 1024 and 65535."
fi

[[ -e "$PORT" ]] || warn "Serial port $PORT not found — continuing anyway."

ok "Configuration validated"

# ── Summary ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Summary${RESET}"
echo -e "${DIM}──────────────────────────────────────────${RESET}"
info "WiFi SSID     : $WIFI_SSID"
info "Target MAC    : $TARGET_MAC"
info "Device name   : $DEVICE_NAME"
info "Listen port   : $LISTEN_PORT"
info "Broadcast IP  : $BROADCAST_IP"
info "Serial port   : $PORT"
echo ""

# ── Write temporary config ───────────────────────────────────
USER_CONFIG=$(mktemp /tmp/wol_config_XXXX)
cat > "$USER_CONFIG" << CONF
CONFIG_WOL_WIFI_SSID="$WIFI_SSID"
CONFIG_WOL_WIFI_PASSWORD="$WIFI_PASS"
CONFIG_WOL_TAILSCALE_AUTH_KEY="$TS_KEY"
CONFIG_WOL_TARGET_MAC="$TARGET_MAC"
CONFIG_WOL_DEVICE_NAME="$DEVICE_NAME"
CONFIG_WOL_LISTEN_PORT=$LISTEN_PORT
CONFIG_WOL_BROADCAST_IP="$BROADCAST_IP"
CONF

# Remove stale sdkconfig so our SDKCONFIG_DEFAULTS takes full effect
rm -f sdkconfig sdkconfig.old

# ── Build ────────────────────────────────────────────────────
echo -e "${BOLD}Building firmware...${RESET}"
echo ""
SDKCONFIG_DEFAULTS="sdkconfig.defaults;$USER_CONFIG" idf.py build
echo ""
ok "Build complete"

# ── Flash ────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Flashing to $PORT...${RESET}"
echo ""
SDKCONFIG_DEFAULTS="sdkconfig.defaults;$USER_CONFIG" idf.py flash -p "$PORT"

# Cleanup — credentials never touch the filesystem permanently
rm -f "$USER_CONFIG"

# ── Install wake-pc command ────────────────────────────────────
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
cp scripts/wake-pc "$INSTALL_DIR/wake-pc"
chmod +x "$INSTALL_DIR/wake-pc"

if echo "$PATH" | tr ':' '\n' | grep -q "$INSTALL_DIR"; then
  ok "wake-pc installed to $INSTALL_DIR (already on PATH)"
else
  warn "wake-pc installed to $INSTALL_DIR"
  echo ""
  echo "  Add it to your PATH by adding this to your shell profile:"
  echo ""
  echo -e "  ${DIM}export PATH=\"\$HOME/.local/bin:\$PATH\"${RESET}"
fi

# ── Done ─────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║  Done! ESP32 flashed successfully.       ║${RESET}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${RESET}"
echo ""
echo "  Open the serial monitor to see the ESP32 Tailscale IP:"
echo ""
echo -e "  ${CYAN}idf.py monitor -p $PORT${RESET}"
echo ""
echo "  Then save it as the default and wake your PC from anywhere:"
echo ""
echo -e "  ${CYAN}wake-pc --save <esp32-tailscale-ip>${RESET}"
echo -e "  ${CYAN}wake-pc${RESET}   ${DIM}# uses saved default from now on${RESET}"
echo ""
