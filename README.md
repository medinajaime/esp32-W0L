# ESP32 Wake-on-LAN via Tailscale

Wake up any PC on your home network from anywhere in the world — through a Tailscale
VPN — using a $5 ESP32 as a permanent LAN bridge.

```
[You, anywhere] ──Tailscale VPN──▶ [ESP32 on LAN] ──UDP broadcast──▶ [Sleeping PC]
```

The ESP32 stays connected to your Tailscale network 24/7. Any Tailscale peer can send
a single UDP packet to trigger a WoL broadcast on the local network.

> **[Full documentation](https://jaimesalcedo1.github.io/wol-esp32/)** — architecture deep dive, memory tuning, state machine walkthrough, and more.

---

## How it works

```
 ┌─────────────────────────────────────────────────────────────────────┐
 │  Your home network                                                  │
 │                                                                     │
 │   ┌─────────────┐    UDP broadcast    ┌──────────────────────────┐  │
 │   │  Sleeping PC │◀──────────────────│  ESP32                    │  │
 │   │  (Ethernet)  │  255.255.255.255  │  WiFi STA + WireGuard    │  │
 │   └─────────────┘                    └──────────┬───────────────┘  │
 │                                                  │ WiFi             │
 │                                             ┌────┴─────┐           │
 │                                             │  Router   │           │
 │                                             └────┬─────┘           │
 └──────────────────────────────────────────────────┼─────────────────┘
                                                    │ Internet
                                        ┌───────────┴────────────┐
                                        │  Tailscale DERP relay  │
                                        └───────────┬────────────┘
                                                    │ WireGuard
                                        ┌───────────┴──────────────┐
                                        │  Your laptop / phone      │
                                        │  (any Tailscale peer)     │
                                        └──────────────────────────┘
```

1. ESP32 boots, connects to WiFi, registers with Tailscale, and establishes a WireGuard tunnel
2. A UDP listener waits for trigger packets on port 9999 (configurable)
3. Any Tailscale peer sends `echo wake | nc -u <esp32-ip> 9999 -w1`
4. ESP32 broadcasts a WoL magic packet on the LAN
5. The target PC's NIC recognises its MAC and powers on

---

## Hardware

Any ESP32 dev board works. No PSRAM required.

The firmware uses ~960 KB flash (37% of 4 MB free) and runs within the 520 KB SRAM
of a standard ESP32. Tested on a NodeMCU-32S / ESP32S.

---

## Quick start

### Prerequisites

- [ESP-IDF v5.5.3](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/)
- A [Tailscale auth key](https://login.tailscale.com/admin/settings/keys) (reusable + ephemeral recommended)
- Your target PC's Ethernet MAC address

### Setup

```bash
git clone https://github.com/jaimesalcedo1/wol-esp32.git
cd wol-esp32
bash scripts/setup.sh
```

The setup script will prompt for your WiFi credentials, Tailscale auth key, and
target MAC address, then build and flash the firmware.

After flashing, open the serial monitor to see the ESP32's Tailscale IP:

```bash
idf.py monitor -p /dev/ttyUSB0
```

### Wake your PC

The setup script installs a `wake-pc` command to `~/.local/bin`:

```bash
wake-pc --save <esp32-tailscale-ip>   # save default IP (one-time)
wake-pc                                # wake PC using saved IP
```

Or trigger manually from any Tailscale peer:

```bash
echo wake | nc -u <esp32-tailscale-ip> 9999 -w1
```

---

## Configuration

All settings are configured during `setup.sh` or via `idf.py menuconfig` → **"Wake-on-LAN Configuration"**.

| Setting | Default | Description |
|---------|---------|-------------|
| `WOL_WIFI_SSID` | — | Your WiFi network name |
| `WOL_WIFI_PASSWORD` | — | WiFi password |
| `WOL_TAILSCALE_AUTH_KEY` | — | Tailscale auth key |
| `WOL_TARGET_MAC` | — | Target PC Ethernet MAC (`AA:BB:CC:DD:EE:FF`) |
| `WOL_DEVICE_NAME` | `esp32-wol` | Name in Tailscale admin console |
| `WOL_LISTEN_PORT` | `9999` | UDP trigger port (1024–65535) |
| `WOL_BROADCAST_IP` | `255.255.255.255` | LAN broadcast address |

---

## Target PC setup

WoL requires configuration on the target PC:

**BIOS/UEFI:** Enable Wake on LAN. Disable ErP/EuP Ready (it cuts standby power to the NIC).

**Linux:**
```bash
sudo ethtool -s eth0 wol g
```

**Windows:** Device Manager → Network Adapter → Properties → Power Management → Allow this device to wake the computer.

> WoL only works over **Ethernet**. Most WiFi NICs do not support magic packets.

See the [full docs](https://jaimesalcedo1.github.io/wol-esp32/docs.html) for persistent configuration and troubleshooting.

---

## Known limitations

- **DERP-only connectivity** — Direct UDP paths often fail on ESP32 due to NAT; traffic relays through Tailscale's encrypted DERP servers (still end-to-end WireGuard encrypted)
- **Single target MAC** — One configured PC per device. Multiple targets would require firmware changes
- **No trigger authentication** — Any Tailscale peer can wake the PC. Use Tailscale ACLs to restrict access
- **No PSRAM** — Heap runs close to the edge (~6 KB minimum during peer sync). If OOM occurs, reduce `CONFIG_TS_COORD_BUFFER_SIZE_KB` to 16 in `sdkconfig.defaults`

---

## License

MIT
