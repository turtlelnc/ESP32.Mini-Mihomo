# ESP32 mini-mihomo for ChatGPT

This firmware lets a normal computer use ChatGPT without Ghelper, Clash, a PAC
file, or a manually configured browser proxy. It supports both a wired-LAN
client and the ESP32's own Wi-Fi access point, forwarding browser TLS through
the selected `新加坡3` HTTP-over-TLS node.

The firmware does not use the OpenAI API, terminate browser TLS, install a CA,
or store ChatGPT login tokens. The browser still establishes TLS directly with
the real destination, so its certificate checks, browser fingerprint, cookies,
Cloudflare flow, and OAuth redirects are preserved.

## Use from a wired computer

The wired computer and ESP32 must be on the same router/LAN. Configure the
Ethernet adapter's DNS server as the ESP32 station address (currently
`192.168.9.100`), then:

1. Open `http://192.168.9.100:50032/`.
2. Enter the password from `LOCAL_ACCESS_PASSWORD` in the ESP32 login page.
3. The ESP32 authorizes that computer in RAM and redirects to ChatGPT.

This is only a DNS change; do not configure an HTTP/HTTPS proxy in the browser.
If DHCP later gives the ESP32 another address, use the new address for both DNS
and port `50032`, or reserve its current address in the router.

Use the complete URL including `http://`. Port `50032` is deliberately plain
HTTP for the local password gate; `https://192.168.9.100:50032` will not work.

## Use from a Wi-Fi computer or phone

1. Connect the computer or phone to the Wi-Fi named by `ESP32_AP_SSID` in
   `include/Secrets.h`.
2. Enter the WPA2 password from `ESP32_AP_PASSWORD`.
3. Open `http://192.168.4.1:50032/` in the browser.
4. Enter the password from `LOCAL_ACCESS_PASSWORD` in the ESP32 login page.
5. The ESP32 authorizes that device in RAM and redirects the browser to
   `https://chatgpt.com/`.

While connected to this ESP32 Wi-Fi, use `192.168.4.1`, not the station/LAN
address `192.168.9.100`. The latter is only for a computer wired to the original
router. Again, enter the complete `http://192.168.4.1:50032/` URL.

No browser extension or proxy setting is needed. Authorization lasts 30 minutes
and is erased on reboot. Opening the ESP32 address again renews it. The Wi-Fi
and wired modes can remain enabled in the same firmware.

For diagnostics, open
`http://192.168.4.1:50032/__mini_mihomo_status` after authenticating. It reports
the uplink state, current/accepted/failed tunnel counts, and free heap.

## How it works

```text
Browser on wired LAN or ESP32 Wi-Fi
  -> ESP32 selective DNS (ChatGPT-related A records become the ESP32 interface)
  -> ESP32 TCP 443 listener reads only TLS ClientHello SNI
  -> encrypted connection to 新加坡3
  -> HTTP CONNECT <SNI>:443
  -> browser TLS bytes relayed unchanged to the destination
```

Opening port `50032` is the authorization gate. Before that visit, ESP32 rejects
all transparent TLS connections and makes no upstream forwarding request.

The browser-facing gate is a normal HTML password form. HTTP Basic
authentication with username `esp32` remains accepted for command-line status
checks, but is not required in the browser.

Selective DNS interception is needed because an IP-address reverse proxy cannot reliably
host ChatGPT: changing the browser origin breaks secure cookies, certificate
validation, Cloudflare challenges, CDN hosts, and login redirects.

## Build and flash

Install PlatformIO, connect the board, then run:

```sh
pio run
pio run --target upload --upload-port /dev/cu.usbserial-10
```

All Wi-Fi, local-access, and upstream credentials are compile-time macros in
the gitignored `include/Secrets.h`; none are environment variables. Copy
`include/Secrets.example.h` when setting up a new device.

## Limits and security

- Use the dedicated ESP32 Wi-Fi while browsing. The computer will normally show
  only application-level internet access because this is not full IP NAT. Turn
  off auto-join for the original Wi-Fi while using the ESP32 hotspot; otherwise
  the OS may switch networks and reset the browser's existing TLS connections.
- Quit any existing Clash/TUN process before testing hotspot mode. A TUN route
  can capture `192.168.4.1` as soon as the computer leaves the ESP32 hotspot.
- Custom browser DNS-over-HTTPS can bypass the ESP32 DNS. If ChatGPT does not
  resolve to `192.168.4.1`, temporarily use the browser/system DNS provider or
  disable custom Secure DNS on this dedicated Wi-Fi.
- DNS names outside the ChatGPT/OpenAI login and content domain set are resolved
  normally, so wired clients keep their existing direct-internet behavior.
- HTTP/3/QUIC is not forwarded; browsers normally fall back to TCP/TLS.
- Classic ESP32 RAM limits the firmware to two concurrent TLS tunnels. Pending
  browser connections remain queued and continue as a slot becomes free.
- Only a device connected to the ESP32 subnet can authorize or use the tunnel.
- Upstream TLS is encrypted but currently uses `setInsecure()` because the
  subscription does not provide a CA chain. Browser-to-destination TLS remains
  independently verified end-to-end.
- The current firmware supports the subscription's HTTPS HTTP-proxy node. It is
  intentionally not a full Mihomo implementation (no TUN, UDP, rules engine,
  or other node protocols).

The desktop prototype under `desktop/` remains available for protocol testing,
but it is not required by the ESP32 workflow.
