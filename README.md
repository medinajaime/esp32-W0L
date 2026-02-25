# ESP32 Wake-on-LAN via Tailscale

Wake up any PC on your home network from anywhere in the world — through a Tailscale
VPN — using a $5 ESP32 as a permanent LAN bridge.

---

## Table of Contents

1. [What problem it solves](#1-what-problem-it-solves)
2. [High-level architecture](#2-high-level-architecture)
3. [Component overview](#3-component-overview)
4. [How it works — step by step](#4-how-it-works--step-by-step)
   - 4.1 [Boot sequence](#41-boot-sequence)
   - 4.2 [WiFi connection](#42-wifi-connection)
   - 4.3 [Tailscale registration (MicroLink)](#43-tailscale-registration-microlink)
   - 4.4 [WireGuard tunnel](#44-wireguard-tunnel)
   - 4.5 [DERP relay and NAT traversal](#45-derp-relay-and-nat-traversal)
   - 4.6 [DISCO path optimisation](#46-disco-path-optimisation)
   - 4.7 [UDP trigger listener](#47-udp-trigger-listener)
   - 4.8 [Wake-on-LAN magic packet](#48-wake-on-lan-magic-packet)
5. [Data flow — from button press to PC waking](#5-data-flow--from-button-press-to-pc-waking)
6. [Memory layout and constraints](#6-memory-layout-and-constraints)
7. [Project structure](#7-project-structure)
8. [Configuration reference](#8-configuration-reference)
9. [Build, flash and monitor](#9-build-flash-and-monitor)
10. [Triggering Wake-on-LAN](#10-triggering-wake-on-lan)
11. [Target PC setup](#11-target-pc-setup)
12. [Reconnection behaviour](#12-reconnection-behaviour)
13. [Known limitations](#13-known-limitations)

---

## 1. What problem it solves

Wake-on-LAN (WoL) requires a magic packet to be broadcast on the same LAN segment as
the sleeping PC. The problem: you are remote.

Traditional solutions:
- **Port-forward UDP 9** — exposes your router, requires a static IP.
- **Always-on server** — wasteful; the whole point is to avoid leaving machines on.
- **Router with WoL support** — uncommon in consumer gear.

This project turns a NodeMCU-32S / ESP32S into a permanent, low-power (≈80 mW during
Tailscale keepalive) LAN bridge:

```
[You, anywhere] ──Tailscale VPN──▶ [ESP32 on LAN] ──UDP broadcast──▶ [Sleeping PC]
```

The ESP32 stays connected to your Tailscale network 24/7. Any Tailscale peer can send
it a single UDP packet to trigger a WoL broadcast on the local network.

---

## 2. High-level architecture

```
 ┌────────────────────────────────────────────────────────────────────────────┐
 │  Your home network (192.168.x.x / 10.x.x.x)                               │
 │                                                                            │
 │   ┌─────────────┐      ARP/UDP     ┌──────────────────────────────────┐   │
 │   │  Sleeping PC│◀─────────────────│  NodeMCU-32S / ESP32S            │   │
 │   │  NIC MAC:   │  255.255.255.255 │                                  │   │
 │   │  10:FF:E0:  │  port 9          │  WiFi STA ──▶ WireGuard tun      │   │
 │   │  08:CC:4C   │                  │  (lwIP dual interface)            │   │
 │   └─────────────┘                  └──────────┬───────────────────────┘   │
 │                                               │ WiFi                       │
 │                                          ┌────┴─────┐                     │
 │                                          │  Router  │                     │
 │                                          └────┬─────┘                     │
 └───────────────────────────────────────────────┼────────────────────────── ┘
                                                 │ Internet
                                     ┌───────────┴────────────┐
                                     │  Tailscale DERP relay  │
                                     │  (Dallas / NYC / ...)  │
                                     └───────────┬────────────┘
                                                 │ WireGuard / DERP
                                     ┌───────────┴──────────────┐
                                     │  Your laptop / phone      │
                                     │  (any Tailscale peer)    │
                                     └──────────────────────────┘
```

---

## 3. Component overview

| Component | Role |
|-----------|------|
| **ESP-IDF v5.5.3** | Firmware SDK (FreeRTOS, lwIP, mbedTLS, WiFi driver) |
| **MicroLink v3.0.0** | Pure-C Tailscale implementation for ESP32 |
| **wireguard-lwip** | WireGuard kernel integrated into lwIP (bundled with MicroLink) |
| **mbedTLS** | TLS 1.2 for HTTPS coordination channel |
| **cJSON** | JSON parser used by MicroLink to decode Tailscale's MapResponse |
| **lwIP** | TCP/IP stack — hosts both the WiFi STA interface and the WireGuard tunnel interface |

---

## 4. How it works — step by step

### 4.1 Boot sequence

```
app_main()
  │
  ├─ nvs_flash_init()          — NVS partition (required by WiFi driver)
  ├─ wifi_init()               — connect to LAN WiFi, block until IP assigned
  ├─ microlink_init()          — allocate MicroLink state (heap-critical)
  ├─ microlink_connect()       — start async Tailscale registration
  ├─ xTaskCreate(wol_task)     — UDP listener runs in its own FreeRTOS task
  └─ loop: microlink_update()  — drives MicroLink state machine every 50 ms
```

### 4.2 WiFi connection

`wifi_init()` registers two event handlers with the ESP-IDF event loop:

- `WIFI_EVENT_STA_START` → calls `esp_wifi_connect()`
- `WIFI_EVENT_STA_DISCONNECTED` → retries up to 20 times, then reboots
- `IP_EVENT_STA_GOT_IP` → sets the `WIFI_CONNECTED_BIT` event group bit

`wifi_init()` blocks on `xEventGroupWaitBits()` until the bit is set, so
`app_main()` only proceeds once DHCP has assigned an IP.

The WiFi STA interface key is `"WIFI_STA_DEF"`. This key is used later when
binding the WoL broadcast socket to ensure broadcast packets exit via WiFi
(not the WireGuard tunnel interface).

### 4.3 Tailscale registration (MicroLink)

MicroLink implements Tailscale's **ts2021** coordination protocol. After
`microlink_connect()` is called, it progresses through these states:

```
IDLE ──▶ REGISTERING ──▶ FETCHING_PEERS ──▶ CONFIGURING_WG ──▶ CONNECTED ──▶ MONITORING
```

**REGISTERING** — HTTPS POST to `controlplane.tailscale.com:443`:

1. Opens a TLS 1.2 connection (mbedTLS, with Tailscale's CA bundle).
2. Sends a registration request containing the device's WireGuard public key,
   the auth key from Kconfig, and the device hostname.
3. Receives a `RegisterResponse` with the assigned Tailscale VPN IP (100.x.x.x).

**FETCHING_PEERS** — HTTP/2 long-poll (`/machine/map`):

1. Sends a `MapRequest` to the control server.
2. Receives a `MapResponse` JSON document (~22 KB for a typical tailnet).
3. cJSON parses the document on the heap — this is the peak memory moment
   (see [Memory layout](#6-memory-layout-and-constraints)).
4. Extracts peer public keys, VPN IPs, and endpoint lists.

**CONFIGURING_WG** — programs the WireGuard interface:

1. Adds each peer's public key and allowed IPs to wireguard-lwip.
2. Sets the pre-shared key (if any) and keepalive.

**CONNECTED / MONITORING** — steady state:

- Sends a WireGuard heartbeat every 25 seconds to maintain "online" status
  in the Tailscale admin console.
- Re-runs `MapRequest` when the control server closes the long-poll connection
  (typically every 10–15 minutes).

### 4.4 WireGuard tunnel

MicroLink uses **wireguard-lwip**, which implements WireGuard as a lwIP network
interface (`wg0`). This means:

- The WireGuard interface appears alongside the WiFi STA interface inside lwIP.
- Traffic to 100.x.x.x addresses is routed through the tunnel automatically.
- Incoming VPN packets arrive as ordinary lwIP frames after decryption.

The handshake uses **Noise_IK_25519_ChaChaPoly_BLAKE2s**:

- **X25519** — Diffie-Hellman key agreement (ephemeral + static key pairs)
- **ChaCha20-Poly1305** — authenticated encryption of all data frames
- **BLAKE2s** — keyed hash / MAC

MicroLink generates the device's WireGuard key pair internally. The public key
is sent to `controlplane.tailscale.com` during registration; Tailscale
distributes it to all peers so they can encrypt traffic addressed to this device.

### 4.5 DERP relay and NAT traversal

When direct UDP between two Tailscale peers is blocked by NAT or firewall,
Tailscale uses **DERP** (Designated Encrypted Relay for Packets) servers as
a relay of last resort.

MicroLink connects to a DERP server over **TLS 1.2 on port 443** (the same
port as HTTPS, so it passes through almost every firewall). DERP servers are
geographically distributed; MicroLink defaults to Dallas (region 9) with NYC
as fallback.

DERP is transparent to the application: WireGuard-encrypted packets are
wrapped in a DERP frame and relayed through the server. The receiving peer
unwraps and decrypts them normally.

On this device DERP is the primary (and often only) path because:

1. The ESP32 is behind a home NAT router — it has no public IP.
2. DISCO (see below) often fails to bind at boot time.

Even over DERP the traffic is still end-to-end WireGuard encrypted; the
relay server sees only opaque ciphertext.

### 4.6 DISCO path optimisation

Tailscale's **DISCO** protocol probes for direct UDP paths between peers to
bypass DERP relays and reduce latency.

DISCO sends **Ping / Pong** messages encrypted with a separate 32-byte DISCO
key (exchanged via the coordination server). If both sides can reach each other
directly, DISCO promotes the connection to a direct path.

On this ESP32 deployment DISCO often fails to bind its socket at boot
(`errno=112 ENETDOWN`) because the WireGuard interface is not yet fully up
when DISCO initialises. This is non-fatal: MicroLink continues using DERP.
Once the interface stabilises, subsequent DISCO attempts may succeed and
establish a direct path.

### 4.7 UDP trigger listener

`wol_task()` runs in a dedicated FreeRTOS task (6144 byte stack):

```c
// Wait for Tailscale to be fully up
while (!microlink_is_connected(ml))
    vTaskDelay(pdMS_TO_TICKS(500));

// Create a UDP socket on the WireGuard (VPN) interface
sock = microlink_udp_create(ml, CONFIG_WOL_LISTEN_PORT);  // default: 9999

// Listen loop
for (;;) {
    err = microlink_udp_recv(sock, &src_ip, &src_port, buf, &len, 5000 /*ms*/);
    if (err == ESP_OK)
        wol_send_magic_packet(target_mac);
    // ESP_ERR_TIMEOUT → keep looping (normal)
    // other error    → recreate socket
}
```

The socket is bound to the WireGuard lwIP interface. Only packets arriving
from within the Tailscale VPN can reach it — the port is invisible on the
public internet.

Any UDP payload triggers the WoL broadcast; the content of the packet is
ignored. The design is intentionally stateless: one packet in → one magic
packet out.

### 4.8 Wake-on-LAN magic packet

A WoL magic packet is exactly **102 bytes**:

```
Bytes 0–5   : FF FF FF FF FF FF          (6-byte synchronisation stream)
Bytes 6–101 : <target MAC> × 16          (target MAC repeated 16 times)
```

`wol_send_magic_packet()` builds this packet and broadcasts it:

```c
// 1. Open a plain BSD UDP socket (NOT the WireGuard socket)
int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

// 2. Enable SO_BROADCAST
setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));

// 3. Bind to the WiFi STA IP — critical!
//    Ensures the packet exits via WiFi, not the WireGuard tunnel interface.
//    Without this, lwIP might route the broadcast to the VPN interface,
//    where it would be dropped (WireGuard has no concept of broadcasts).
struct sockaddr_in src = { .sin_addr.s_addr = wifi_sta_ip };
bind(sock, (struct sockaddr *)&src, sizeof(src));

// 4. Send to LAN broadcast address on WoL port 9
struct sockaddr_in dest = {
    .sin_addr.s_addr = inet_addr("255.255.255.255"),
    .sin_port        = htons(9),
};
sendto(sock, pkt, 102, 0, (struct sockaddr *)&dest, sizeof(dest));
```

The target PC's NIC receives the broadcast, recognises its own MAC in the
magic packet, and powers on.

---

## 5. Data flow — from button press to PC waking

```
[Tailscale peer]
   1. echo wake | nc -u 100.126.139.97 9999 -w1
      │
      │  UDP payload ("wake\n")
      │  encrypted by WireGuard (ChaCha20-Poly1305)
      │
      ▼
[DERP server]  ← relay if no direct path
      │
      │  WireGuard-encrypted UDP frame
      │  arrives at ESP32's UDP port
      │
      ▼
[ESP32 — wireguard-lwip]
   2. Decrypt WireGuard frame
   3. Deliver decrypted UDP payload to lwIP socket layer
      │
      ▼
[ESP32 — wol_task]
   4. microlink_udp_recv() returns ESP_OK
   5. Call wol_send_magic_packet(target_mac)
      │
      │  UDP broadcast, 102 bytes
      │  src: ESP32 WiFi STA IP
      │  dst: 255.255.255.255:9
      │  plaintext (LAN traffic, not encrypted)
      │
      ▼
[Sleeping PC NIC]
   6. NIC sees broadcast, matches own MAC × 16
   7. Asserts PCIe wake signal
   8. PC powers on
```

Total latency (DERP path, typical): 200–800 ms from `nc` to power-on signal.

---

## 6. Memory layout and constraints

The NodeMCU-32S has **520 KB SRAM** and **no PSRAM**. This is tight for a
full TLS + WireGuard + cJSON stack. All major tuning decisions are recorded
here.

### Heap budget at boot (approximate)

| Allocation | Size |
|------------|------|
| WiFi driver (static RX/TX buffers) | ~48 KB |
| mbedTLS handshake + buffers | ~40 KB (dynamic) |
| MicroLink internal state + peer table | ~20 KB |
| cJSON parse of MapResponse | ~60 KB peak (freed after parse) |
| WireGuard session state | ~16 KB |
| FreeRTOS task stacks (main 6KB, wol 6KB, idle, timer) | ~20 KB |
| lwIP buffers | ~16 KB |
| **Free at steady state** | ~80–100 KB |

### Minimum free heap

During the MapResponse cJSON parse (~22 KB JSON → ~60 KB AST), the heap
reaches its lowest point. The observed minimum is **~6 KB**. If this drops
to zero the device will crash with a heap corruption abort.

### Tuning applied in `sdkconfig.defaults`

| Setting | Value | Reason |
|---------|-------|--------|
| `CONFIG_MBEDTLS_SSL_IN_CONTENT_LEN` | 4096 | Reduced from default 16 KB; TLS records from Tailscale fit in 4 KB |
| `CONFIG_MBEDTLS_SSL_OUT_CONTENT_LEN` | 4096 | Same |
| `CONFIG_MBEDTLS_DYNAMIC_BUFFER` | y | Buffers allocated only during handshake, freed after |
| `CONFIG_MICROLINK_COORD_BUFFER_SIZE_KB` | 24 | Receive buffer for MapResponse HTTP/2 stream |
| `CONFIG_MICROLINK_MAX_PEERS` | 4 | Caps per-peer heap usage |
| `CONFIG_ESP_MAIN_TASK_STACK_SIZE` | 6144 | Main task runs MicroLink update loop |
| `CONFIG_LWIP_TCP_SND_BUF_DEFAULT` | 4096 | Reduced from 5744 |
| `CONFIG_LWIP_TCP_WND_DEFAULT` | 4096 | Reduced from 5744 |
| `CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM` | 6 | Fewer static DMA buffers |
| `CONFIG_COMPILER_OPTIMIZATION_SIZE` | y | `-Os` reduces .text size by ~5% |

### Code fix: dynamic json_buffer sizing

`microlink_coordination.c` originally allocated a fixed 64 KB `json_buffer`
on top of the cJSON heap peak, which caused OOM crashes. The fix allocates
only as much as the actual HTTP/2 payload:

```c
// Before (crashed):
uint8_t *json_buffer = malloc(65536);

// After (correct):
size_t json_buffer_size = h2_buffer_len + 8;
uint8_t *json_buffer = malloc(json_buffer_size);
```

---

## 7. Project structure

```
wol-esp32/
├── CMakeLists.txt              Top-level build (adds ../microlink as component)
├── sdkconfig.defaults          Memory-tuned defaults for no-PSRAM ESP32
├── main/
│   ├── CMakeLists.txt          Component registration (requires microlink, nvs_flash, …)
│   ├── Kconfig.projbuild       "Wake-on-LAN Configuration" menuconfig menu
│   └── main.c                  All application code (WiFi, MicroLink, WoL)
└── build/                      (generated by idf.py build)

../microlink/                   MicroLink library (sibling directory)
├── include/
│   ├── microlink.h             Public API
│   └── microlink_internal.h
├── src/
│   ├── microlink.c             State machine entry point
│   ├── microlink_coordination.c  Tailscale ts2021 coordination (HTTPS + cJSON)
│   ├── microlink_connection.c  WireGuard connection management
│   ├── microlink_derp.c        DERP relay client
│   ├── microlink_disco.c       DISCO path discovery
│   ├── microlink_stun.c        STUN NAT type discovery
│   ├── microlink_udp.c         UDP socket API over WireGuard interface
│   ├── microlink_wireguard.c   wireguard-lwip integration
│   └── nacl_box.c / x25519.c  Cryptographic primitives
└── components/
    └── wireguard_lwip/         WireGuard as a lwIP netif
```

---

## 8. Configuration reference

All settings are set once via `idf.py menuconfig` → **"Wake-on-LAN Configuration"**
and baked into the firmware image.

| Kconfig symbol | Default | Description |
|----------------|---------|-------------|
| `WOL_WIFI_SSID` | `myssid` | SSID of your home WiFi network |
| `WOL_WIFI_PASSWORD` | _(empty)_ | WiFi password (blank for open networks) |
| `WOL_TAILSCALE_AUTH_KEY` | `tskey-auth-…` | Auth key from Tailscale admin console. Use a **reusable, ephemeral** key so the device does not clutter your admin panel when offline |
| `WOL_DEVICE_NAME` | `esp32-wol` | Name shown in Tailscale admin console |
| `WOL_TARGET_MAC` | `AA:BB:CC:DD:EE:FF` | Ethernet MAC of the NIC to wake. Find it with `ip link show` (Linux) or `ipconfig /all` (Windows) |
| `WOL_LISTEN_PORT` | `9999` | UDP port to listen on (over Tailscale). Range 1024–65535 |
| `WOL_BROADCAST_IP` | `255.255.255.255` | Broadcast address for the magic packet. Use subnet broadcast (e.g. `192.168.1.255`) if your router blocks 255.255.255.255 |

---

## 9. Build, flash and monitor

**Prerequisites:**
- ESP-IDF v5.5.3 installed at `$HOME/esp/esp-idf`
- Device on `/dev/ttyUSB0`
- MicroLink cloned as a sibling directory (`../microlink`)

```bash
# One-time: activate IDF environment
. $HOME/esp/esp-idf/export.sh

cd /path/to/wol-esp32

# Configure WiFi credentials, Tailscale auth key, target MAC
idf.py menuconfig

# Build, flash, and open serial monitor
idf.py build flash monitor -p /dev/ttyUSB0
```

**Expected boot log (steady state):**

```
I (0)    wol: ESP32 Wake-on-LAN  (MicroLink 3.0.0)
I (412)  wol: WiFi connected: 192.168.1.123
I (1840) wol: Tailscale state: IDLE → REGISTERING
I (5200) wol: Tailscale state: REGISTERING → FETCHING_PEERS
I (8100) wol: Tailscale state: FETCHING_PEERS → CONFIGURING_WG
I (8300) wol: Tailscale state: CONFIGURING_WG → CONNECTED
I (8301) wol: *** Tailscale CONNECTED ***
I (8350) wol: Tailscale state: CONNECTED → MONITORING
I (8351) wol: ╔══════════════════════════════════════════╗
I (8352) wol: ║  ESP32 Wake-on-LAN  —  READY             ║
I (8353) wol: ║  Tailscale IP : 100.126.139.97           ║
I (8354) wol: ║  Listen port  : 9999                     ║
I (8355) wol: ╚══════════════════════════════════════════╝
I (8356) wol: UDP socket bound to Tailscale port 9999
```

Once `UDP socket bound to Tailscale port 9999` appears, the device is ready.

**To save logs to a file** (IDF monitor does not support `--logfile`):

```bash
# Option A — minicom
minicom -D /dev/ttyUSB0 -b 115200 -C monitor.log

# Option B — Python one-liner
python3 -c "
import serial, sys
s = serial.Serial('/dev/ttyUSB0', 115200)
while True:
    line = s.readline()
    sys.stdout.buffer.write(line)
    open('monitor.log', 'ab').write(line)
"
```

---

## 10. Triggering Wake-on-LAN

From **any machine connected to your Tailscale network**:

```bash
echo wake | nc -u 100.126.139.97 9999 -w1
```

- `100.126.139.97` — Tailscale IP of the ESP32 (shown in the banner above, or
  in the Tailscale admin console under the device name `esp32-wol`)
- `9999` — UDP trigger port (configurable)
- `-w1` — close after 1 second (nc won't receive a reply)

The ESP32 serial monitor will show:

```
I (xxxxx) wol: Trigger from 100.x.x.x:XXXXX — firing WoL
I (xxxxx) wol: Magic packet sent → 10:FF:E0:08:CC:4C  (via 255.255.255.255:9)
```

You can wrap this in a shell alias, a phone shortcut, or any automation tool
(Home Assistant, Tasker, etc.) that can run a command or send a UDP packet.

---

## 11. Target PC setup

WoL requires configuration on both the motherboard and the OS.

### BIOS / UEFI

Enter BIOS setup and enable:
- **Wake on LAN** (may be under Power Management, Advanced, or Network)
- **PCI-E Power On** / **ErP / EuP Ready** must be **disabled** (it cuts standby power to the NIC)
- **Deep Sleep** may need to be disabled

### Windows

1. Open **Device Manager** → expand **Network Adapters**
2. Right-click your Ethernet NIC → **Properties**
3. **Power Management** tab → check **Allow this device to wake the computer**
4. **Advanced** tab → find **Wake on Magic Packet** → set to **Enabled**

### Linux

```bash
# Check current WoL setting (g = enabled, d = disabled)
sudo ethtool eth0 | grep Wake-on

# Enable WoL (persists until reboot)
sudo ethtool -s eth0 wol g

# To persist across reboots (systemd):
# Create /etc/systemd/network/10-eth0.link with:
#   [Match]
#   MACAddress=10:FF:E0:08:CC:4C
#   [Link]
#   WakeOnLan=magic
```

> **Important:** WoL requires the PC to be connected via **Ethernet**, not WiFi.
> Most wireless NICs do not support WoL magic packets.

---

## 12. Reconnection behaviour

The Tailscale coordination server (`controlplane.tailscale.com`) closes the
HTTP/2 long-poll connection every 10–15 minutes. This is normal and expected.

When the connection drops, MicroLink automatically re-registers:

```
MONITORING ──▶ REGISTERING ──▶ FETCHING_PEERS ──▶ CONFIGURING_WG ──▶ CONNECTED ──▶ MONITORING
```

During this ~5–10 second window, the UDP listener socket is kept open. The
task only recreates the socket if `microlink_udp_recv()` returns an error
other than `ESP_ERR_TIMEOUT`.

Reconnection triggers a new cJSON heap spike (same ~60 KB peak as boot).
The heap minimum may degrade slightly across multiple reconnection cycles
if any allocations are not perfectly reclaimed. If the device crashes during
reconnection, reduce `CONFIG_MICROLINK_COORD_BUFFER_SIZE_KB` from 24 to 16
in `sdkconfig.defaults` and rebuild.

---

## 13. Known limitations

| Limitation | Notes |
|------------|-------|
| **DISCO bind failure at boot** | `errno=112 ENETDOWN` — WireGuard interface not yet up when DISCO initialises. Non-fatal; device falls back to DERP. |
| **WoL only works over Ethernet** | The target PC must be connected to the LAN via a wired NIC. WiFi cards generally do not support WoL. |
| `255.255.255.255` may not cross VLANs | If your router segments the network, set `WOL_BROADCAST_IP` to the subnet broadcast (e.g. `192.168.1.255`). |
| **No authentication on trigger port** | Any Tailscale peer can trigger a wake. Tailscale's ACL rules can restrict this if needed. |
| **No PSRAM** | All heap usage (TLS, WireGuard, cJSON) must fit in 520 KB SRAM. Running close to the edge is expected on this hardware. |
| **Single target MAC** | The firmware wakes one configured PC. To support multiple targets, the trigger payload would need to encode the MAC, requiring code changes. |
