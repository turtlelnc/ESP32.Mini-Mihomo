# mini-mihomo desktop prototype

This is a deliberately small C++ feasibility prototype, not a replacement for
Mihomo. It supports HTTPS HTTP-proxy nodes and browser `CONNECT` tunnels. The
local password is read from `../include/Secrets.h`.

Build and run:

```sh
cmake -S desktop -B desktop/build
cmake --build desktop/build
desktop/build/mini-mihomo
```

To parse a downloaded `subs/default` subscription file and prefer the node
labelled `新加坡3`, run:

```sh
desktop/build/mini-mihomo --subscription /path/to/default-subscription.txt
```

Set a browser's **HTTP proxy** to `127.0.0.1:12321`. The listener deliberately
binds only to the local computer while testing, so it does not require a local
proxy password; this allows Ghelper custom-proxy entries to use it.

The prototype proves the portion an ESP32 could potentially implement. It does
not implement Mihomo rules, fake-IP DNS, SOCKS/VLESS/TUIC, UDP, full YAML, or
multi-protocol selection. It reads only the standard HTTPS HTTP-proxy entries
from a default subscription file.
