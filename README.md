# ESP32 Wake-on-LAN via Tailscale

Wake up a PC on your home network from anywhere through Tailscale, using an
ESP32 as a small always-on Wake-on-LAN bridge.

```text
[You, anywhere] --Tailscale--> [ESP32 on LAN] --UDP broadcast--> [Sleeping PC]
```

The ESP32 joins your tailnet, listens for a UDP trigger, and broadcasts a WoL
magic packet on your local network.

## How It Works

1. The ESP32 boots, connects to WiFi, and registers with Tailscale.
2. The firmware keeps a UDP listener open on port `9999` by default.
3. Any allowed Tailscale peer sends a wake trigger to the ESP32.
4. The ESP32 broadcasts a WoL magic packet on the LAN.
5. The target PC's Ethernet NIC receives the packet and powers on.

## Hardware

Any standard ESP32 dev board should work. The project is tuned for a classic
ESP32 without PSRAM, such as a NodeMCU-32S / ESP32S.

WoL requires the target PC to be connected by Ethernet. Most WiFi NICs do not
support Wake-on-LAN magic packets.

## Quick Start: Windows PowerShell

Windows users should use the native PowerShell setup script. It checks for
ESP-IDF, installs Espressif EIM CLI with `winget` when possible, installs the
preferred ESP-IDF version, prompts for project settings, builds, and flashes.

```powershell
git clone https://github.com/medinajaime/esp32-wakeonlan.git
cd esp32-wakeonlan
.\scripts\setup.ps1
```

The script uses Windows COM ports, such as `COM3`, and lists detected serial
ports when possible.

If Windows blocks script execution, run this once in the same PowerShell window:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\setup.ps1
```

The Windows setup uses Espressif's official installer tooling instead of a
custom GUI. Espressif documents the Windows installer and PowerShell/CMD
environment flow here:

https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/windows-setup.html

## Quick Start: Linux

Linux users should use the Bash setup script:

```bash
git clone https://github.com/medinajaime/esp32-wakeonlan.git
cd esp32-wakeonlan
bash scripts/setup.sh
```

The Linux script looks for ESP-IDF `v5.5.3` under one of these locations:

```text
$IDF_PATH
~/esp/esp-idf
~/esp-idf
/opt/esp-idf
```

If ESP-IDF is missing, the script can clone it from Espressif's upstream source,
checkout `v5.5.3`, run `./install.sh esp32`, and continue. On supported Linux
distributions it can also install common prerequisites with `apt-get`, `dnf`,
`pacman`, or `zypper`.

To choose a different ESP-IDF install location:

```bash
IDF_INSTALL_DIR="$HOME/tools/esp-idf" bash scripts/setup.sh
```

It uses `/dev/ttyUSB0` as the default serial port.

## Configuration

Both setup scripts prompt for the same firmware settings:

| Setting | Default | Description |
| --- | --- | --- |
| `WOL_WIFI_SSID` | none | WiFi network name |
| `WOL_WIFI_PASSWORD` | none | WiFi password |
| `WOL_TAILSCALE_AUTH_KEY` | none | Tailscale auth key |
| `WOL_TARGET_MAC` | none | Target PC Ethernet MAC, such as `AA:BB:CC:DD:EE:FF` |
| `WOL_DEVICE_NAME` | `esp32-wol` | Tailscale device name |
| `WOL_LISTEN_PORT` | `9999` | UDP trigger port |
| `WOL_BROADCAST_IP` | `255.255.255.255` | LAN broadcast address |

You can also change these later with:

```bash
idf.py menuconfig
```

Open `Wake-on-LAN Configuration` in menuconfig.

## Wake Your PC

After flashing, open the serial monitor to find the ESP32's Tailscale IP.

Linux:

```bash
idf.py monitor -p /dev/ttyUSB0
```

Windows:

```powershell
idf.py monitor -p COM3
```

Then send a UDP trigger from any Tailscale peer:

```bash
echo wake | nc -u <esp32-tailscale-ip> 9999 -w1
```

The Linux setup script also installs `scripts/wake-pc` to `~/.local/bin`:

```bash
wake-pc --save <esp32-tailscale-ip>
wake-pc
```

## Target PC Setup

In BIOS/UEFI:

- Enable Wake on LAN.
- Disable ErP/EuP Ready if it cuts standby power to the NIC.

On Windows:

- Open Device Manager.
- Open the Ethernet adapter properties.
- Enable `Allow this device to wake the computer`.
- Enable Wake-on-LAN or Magic Packet options if your driver exposes them.

On Linux:

```bash
sudo ethtool -s eth0 wol g
```

## 3D Printed Enclosure

This repo includes a parametric CadQuery enclosure for the NodeMCU-32S /
ESP32S-style board:

```bash
pip install cadquery
python cad/esp32_enclosure.py
```

Generated STEP files are written to `cad/out/`:

- `esp32_enclosure_base.step`
- `esp32_enclosure_lid.step`
- `esp32_enclosure_assembly.step`

Open the assembly STEP in Fusion 360 to inspect or modify the design. The CAD
script keeps board dimensions, clearances, wall thickness, screw sizing, USB
cutout size, vents, and label text as editable parameters near the top of the
file.

## Troubleshooting

### Bash reports `$'\r': command not found`

The Bash script has Windows CRLF line endings. This repo includes
`.gitattributes` to keep `.sh` files as LF. Re-checkout the repo or run:

```bash
dos2unix scripts/setup.sh scripts/wake-pc
```

On Windows PowerShell, prefer:

```powershell
.\scripts\setup.ps1
```

### `idf.py` is not found on Windows

Run the Windows setup script first:

```powershell
.\scripts\setup.ps1
```

It will try to install Espressif EIM CLI with `winget` and install ESP-IDF
`v5.5.3`. If ESP-IDF was just installed and `idf.py` is still missing, open a
new PowerShell window and run the setup script again.

### Build fails in ESP-IDF `mbedtls`

If the error mentions `mbedcrypto` not being built, the ESP-IDF checkout or
tools install is likely incomplete or stale. Repair ESP-IDF:

```powershell
cd $env:IDF_PATH
git submodule update --init --recursive
.\install.ps1
. .\export.ps1
```

Then rerun:

```powershell
.\scripts\setup.ps1
```

On Linux:

```bash
cd "$IDF_PATH"
git submodule update --init --recursive
./install.sh esp32
source ./export.sh
bash scripts/setup.sh
```

### No COM port is detected on Windows

Reconnect the ESP32, try another USB cable, and check Device Manager. Some
boards need a CP210x or CH340 USB-to-serial driver. You can still type the COM
port manually, such as `COM3`.

### Stale `sdkconfig`

Both setup scripts remove `sdkconfig` and `sdkconfig.old` before building so the
temporary guided configuration is applied cleanly.

## Known Limitations

- DERP-only connectivity is expected for many home networks.
- One ESP32 wakes one configured target MAC.
- Any allowed Tailscale peer can trigger wake unless restricted by Tailscale ACLs.
- The no-PSRAM ESP32 heap is tight; reduce `CONFIG_TS_COORD_BUFFER_SIZE_KB` if needed.

## License

MIT
