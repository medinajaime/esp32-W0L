# MicroLink v1.2.0 Release Notes

## Bidirectional UDP Communication

This release adds full bidirectional UDP data transfer over Tailscale VPN, enabling ESP32 devices to both send and receive data from any peer on the tailnet.

### New Features

- **UDP Socket API** - Create UDP sockets for send/receive operations
  - `microlink_udp_create()` - Create socket with optional port binding
  - `microlink_udp_send()` - Send UDP data to any peer
  - `microlink_udp_recv()` - Receive UDP data with timeout
  - `microlink_udp_set_rx_callback()` - Register callback for low-latency packet handling
  - `microlink_udp_close()` - Clean up socket resources

- **Callback-based Reception** - Register callbacks for immediate packet handling by high-priority task, achieving consistent low-latency responses

- **New Example: udp_netcat_example** - Demonstrates bidirectional UDP communication equivalent to Linux `netcat -u`

### Bug Fixes

- **NAT Traversal (Magicsock Pattern)** - Fixed WireGuard packets arriving on DISCO port instead of WG port. Tailscale multiplexes all traffic onto a single UDP port for NAT traversal; MicroLink now correctly routes WireGuard packets received on the DISCO socket.

- **Direct Path Endpoint Updates** - WireGuard endpoint now properly updates when DISCO discovers a direct path, enabling direct UDP communication instead of always using DERP relay.

- **WireGuard Packet Injection** - Fixed source IP handling when injecting packets received on DISCO port. Previously hardcoded to 0.0.0.0 (DERP indicator), now uses actual source IP for direct path tracking.

- **allowed_ip Configuration** - Fixed wireguard-lwip compatibility issue where decrypted packets were being dropped. The library checks destination IP against allowed_source_ips (non-standard behavior); now correctly configured to accept packets destined for ESP32's VPN IP.

### Performance Improvements

- **Reduced Heat/Power** - Decreased DISCO probe interval (5s → 30s) and poll rate (100Hz → 50Hz) to reduce WiFi activity and ESP32 temperature
- **Retry Logic** - Added robust retry handling for UDP socket creation during connection establishment

### Current Behavior

After these fixes:
- **TX (ESP32 → PC)**: Uses DERP relay (consistent, works through all NATs)
- **RX (PC → ESP32)**: Uses direct UDP path when available (lower latency)

This asymmetric behavior is normal and provides reliable bidirectional communication.

### Initialization Time

Boot to "READY FOR COMMUNICATION": ~50-60 seconds

| Phase | Duration |
|-------|----------|
| WiFi connection | 5-10s |
| Tailscale coordination | 10-15s |
| Peer list fetch | 5-10s |
| DERP connection | 5-10s |
| WireGuard handshake | 2s |

### Testing the New Features

1. Flash `examples/udp_netcat_example` to your ESP32
2. Wait for "READY FOR COMMUNICATION" banner
3. On your PC: `nc -u -l 9000` to receive from ESP32
4. On your PC: `echo "test" | nc -u <ESP32_IP> 9000` to send to ESP32

### Files Changed

- `src/microlink_disco.c` - WireGuard packet detection and routing
- `src/microlink_wireguard.c` - Packet injection and allowed_ip fixes
- `src/microlink_udp.c` - Enhanced UDP API with callbacks
- `components/wireguard_lwip/src/wireguardif.c` - Debug logging
- New: `examples/udp_netcat_example/` - Bidirectional UDP example

### Upgrade Notes

This release is backward compatible. Existing code using `microlink_send()`/`microlink_receive()` continues to work. The new UDP socket API is recommended for new projects requiring bidirectional communication.

---

**Full Changelog**: v1.1.0...v1.2.0
