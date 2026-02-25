# Contributing the WireGuard DERP Fix to MicroLink

This project vendors a patched copy of [MicroLink](https://github.com/CamM2325/microlink)
that includes a bug fix for WireGuard handshakes over DERP relay.
This guide explains how to contribute that fix upstream.

---

## What Was Fixed

**File:** `microlink/src/microlink_wireguard.c`
**Function:** `microlink_wireguard_inject_derp_packet()`

**Bug:** When a WireGuard `HANDSHAKE_INIT` arrived from a peer via DERP, the peer's
VPN IP (e.g. `100.112.151.63`) was passed as the source address into wireguard-lwip.
`update_peer_addr()` stored it as `peer->ip`. On the little-endian ESP32, the uint32
was byte-swapped by lwIP's display, so `wireguardif_peer_output()` tried to send the
`HANDSHAKE_RESPONSE` via direct UDP to `63.151.112.100:41641` — a completely wrong,
unreachable address — instead of routing it through the DERP relay callback.
The handshake silently failed every time, so no WireGuard data session ever established.

**Fix:** Always inject DERP-received packets with `src_addr = 0.0.0.0`.
`update_peer_addr()` already skips zero addresses, so `peer->ip` stays `0.0.0.0`
(as set by `wireguardif_connect_derp()`), and `wireguardif_peer_output()` correctly
routes responses through the DERP output callback.

The changed lines are in `microlink/src/microlink_wireguard.c` around the comment:
```
// Always inject DERP packets with src_addr = 0.0.0.0.
```

---

## Steps to Contribute Upstream

### 1. Fork MicroLink on GitHub

Go to https://github.com/CamM2325/microlink and click **Fork**.
This creates `github.com/medinajaime/microlink` (or whatever your username is).

### 2. Clone your fork

```bash
cd ~/Documents/WAL
git clone git@github.com:medinajaime/microlink.git microlink-upstream
cd microlink-upstream
```

### 3. Apply the fix

Copy the fixed file from this repo:

```bash
cp ~/Documents/WAL/wol-esp32/microlink/src/microlink_wireguard.c \
   ~/Documents/WAL/microlink-upstream/src/microlink_wireguard.c
```

### 4. Commit

```bash
git add src/microlink_wireguard.c
git commit -m "fix: always inject DERP packets with src_addr=0.0.0.0

When a WireGuard HANDSHAKE_INIT arrived from a peer via DERP,
microlink_wireguard_inject_derp_packet() passed the peer's VPN IP
as the source address. wireguard-lwip's update_peer_addr() stored
this as peer->ip, causing wireguardif_peer_output() to skip the DERP
relay callback and attempt a direct udp_sendto() to the VPN IP.

On a little-endian ESP32, the uint32 is byte-swapped when lwIP formats
it for display/routing (e.g. 100.112.151.63 becomes 63.151.112.100),
making the destination completely unreachable. The HANDSHAKE_RESPONSE
was silently dropped every time, so the WireGuard data session never
established.

Fix: pass 0.0.0.0 for all DERP-injected packets. update_peer_addr()
already guards against any-address and skips the update, so peer->ip
stays 0.0.0.0 (as cleared by wireguardif_connect_derp()), ensuring
wireguardif_peer_output() routes responses through the DERP callback."
```

### 5. Push and open a Pull Request

```bash
git push origin main
```

Then go to https://github.com/CamM2325/microlink and open a Pull Request
from `medinajaime/microlink:main`.

---

## Keeping the Vendored Copy in Sync

If MicroLink releases a new version after your PR is merged:

```bash
# In wol-esp32/
cp -r /path/to/new/microlink/src  microlink/src
cp -r /path/to/new/microlink/include microlink/include
cp -r /path/to/new/microlink/components microlink/components
# Review any new files, then commit
git add microlink/
git commit -m "vendor: update MicroLink to vX.Y.Z"
```
