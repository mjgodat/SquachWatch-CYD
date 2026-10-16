# SquachWatch Toolbox Edition

**A pentest toolkit built on top of [SquachWatch-CYD](https://github.com/skizzophrenic/SquachWatch-CYD) by [TalkingSasquach (skizzophrenic)](https://github.com/skizzophrenic).**

This is a community fork that adds offensive security tools to SquachWatch's detection platform. All credit for the SquachWatch firmware, visual engine, detection system, and hardware support goes to **skizzophrenic** and the SquachWatch community.

## What This Fork Adds

30+ pentest tools integrated into SquachWatch's menu system, accessible via touchscreen or CLI serial commands.

### WiFi Tools
| Tool | Description |
|------|-------------|
| WiFi Scan | Scan networks with RSSI, channel, encryption |
| Deauth | 802.11 deauthentication (long-press target from scan) |
| Beacon Spam | 20 funny SSID names broadcast |
| Rickroll | Rick Astley lyrics as SSIDs |
| Evil Portal | Captive portal credential harvester |
| Clone AP | Evil twin (long-press target from scan) |
| Karma | Auto-respond to probe requests with fake APs |
| Probe Sniff | Show what SSIDs nearby devices search for |
| DHCP Starve | Flood DHCP requests with random MACs |
| Handshake Capture | WPA2 4-way EAPOL capture to PCAP on SD |
| PCAP Capture | Full packet capture to SD card |
| WiFi Logger | Network logging to CSV on SD |

### BLE Tools
| Tool | Description |
|------|-------------|
| BLE Scan | Scan devices with RSSI, name, address |
| BLE Track | Live RSSI signal strength gauge (long-press target) |
| Apple BLE Spam | Fake AirPods/Beats pairing popups on iPhones |
| Samsung BLE Spam | Fake Galaxy Buds pairing on Samsung phones |
| SwiftPair Spam | Windows Bluetooth pairing notifications |
| Flipper Detect | Scan for Flipper Zero devices |
| AirTag Spoof | Broadcast fake FindMy advertisements |
| Haystack | Apple FindMy location beacon (OpenHaystack) |
| BLE Enumerate | GATT service discovery (long-press target) |

### USB / BadUSB Tools
| Tool | Description |
|------|-------------|
| BadUSB Payloads | 24 built-in payloads for Windows/Mac/Linux |
| USB Keyboard | Native USB HID keyboard mode |
| USB Recon | Covert network recon via hidden PowerShell |

### Built-in BadUSB Payloads (per OS)
- WiFi Password Dump
- System Info Collection
- Reverse Shell (with IP input screen)
- Create Admin User
- Disable Antivirus
- Download & Execute (with IP input)
- Browser Credential Extract
- Persistence (with IP input)

### Utilities
| Tool | Description |
|------|-------------|
| SD Browser | Browse files on SD card |
| WiFi Logger | Periodic network scan to CSV |
| PCAP Viewer | Parse and display PCAP files from SD |
| USB Wireshark | Stream PCAP over USB for live Wireshark |
| LAN Scanner (WiFi) | ARP + port scan after joining a network |
| LAN Scanner (USB) | BadUSB-style network recon |

### WiChat Mesh
Off-grid mesh chat using raw 802.11 frames. Communicate with other SquachWatch/WiChat devices without any infrastructure. Features:
- On-screen QWERTY keyboard
- Message history with delivery status
- Node discovery and tracking
- Channel selection via long-press menu
- Shares radio with SquachWatch detection (no conflict)

### CLI Serial Interface
Full remote control via USB serial (115200 baud). Commands:
```
wifi scan|stop|list|connect|disconnect|status|ip
ble scan|stop|list
chat send|ping|nodes|channel|name|status
hid type|key|run
tap|hold|release|swipe (touch simulation)
heap|uptime|reboot|brightness
batch|end|sleep|echo
```

## UX Design
- **Long press** on any scanned target opens a context menu with applicable tools
- **Drag to scroll** through long menus
- **Tap bottom bar** to stop any running tool
- All tools share the radio cooperatively via hook system — detection keeps running

## Hardware & Test Platform

**Tested on:** Freenove ESP32-S3 3.5" Capacitive Touch Display (FNK0104N) only. Other boards may work but have not been tested with the toolbox. The base SquatchWatch firmware supports many boards — see the [upstream repo](https://github.com/skizzophrenic/SquachWatch-CYD) for full hardware compatibility.

**Primary board specs (FNK0104N):**
- ESP32-S3 with 16MB Flash, 8MB PSRAM
- ST77922 320x480 QSPI display
- Capacitive touch (I2C, integrated in display)
- SD card (SDMMC 4-bit)
- WS2812 RGB LED
- Native USB (CDC + HID composite)
- Battery connector with ADC

## Building
```bash
# Install PlatformIO
pip install platformio

# Build
pio run -e freenove-s3-35

# Flash (hold BOOT, press RESET for bootloader mode)
python -m esptool --chip esp32s3 --port COMx --baud 921600 write_flash \
  0x0 .pio/build/freenove-s3-35/bootloader.bin \
  0x8000 .pio/build/freenove-s3-35/partitions.bin \
  0x10000 .pio/build/freenove-s3-35/firmware.bin
```

## Credits
- **[SquachWatch-CYD](https://github.com/skizzophrenic/SquachWatch-CYD)** by [TalkingSasquach (skizzophrenic)](https://github.com/skizzophrenic) — the foundation this is built on. All detection, visual engine, theme system, and hardware support.
- **[Bruce Firmware](https://github.com/BruceDevices/firmware)** — EAPOL detection logic ported from their sniffer module. Bruce shim layer for compatibility.
- **[WiChat](https://github.com/mjgodat)** — mesh chat protocol by mjgodat.
- **ESP32 pentest community** — Marauder, Ghost ESP, and others for research and techniques.

## License
GPL v3 — same as upstream SquachWatch-CYD. See [LICENSE](LICENSE).

## Disclaimer
This tool is for authorized security testing, educational purposes, and CTF competitions only. Do not use against networks or devices you do not own or have explicit written permission to test. The authors are not responsible for misuse.
