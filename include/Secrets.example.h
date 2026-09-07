#pragma once

// Copy this file to Secrets.h and replace the macro values.
// Secrets.h is intentionally excluded from Git.
#define WIFI_PRIMARY_SSID "your-primary-wifi"
#define WIFI_PRIMARY_PASSWORD "your-primary-password"
#define WIFI_FALLBACK_SSID "your-fallback-wifi"
#define WIFI_FALLBACK_PASSWORD "your-fallback-password"

// Browser login for http://ESP32_IP:50032. Use "esp32" as the username.
#define LOCAL_ACCESS_PASSWORD "choose-a-long-local-password"

// The computer connects to this ESP32 access point. WPA2 requires at least
// eight characters. Keep both values as compile-time macros in Secrets.h.
#define ESP32_AP_SSID "ESP32-ChatGPT"
#define ESP32_AP_PASSWORD "choose-an-ap-password"

// The chosen node must be an HTTP proxy. TLS means HTTPS to that proxy.
#define UPSTREAM_PROXY_HOST "proxy.example.com"
#define UPSTREAM_PROXY_PORT 443
#define UPSTREAM_PROXY_TLS true
#define UPSTREAM_PROXY_USERNAME "username"
#define UPSTREAM_PROXY_PASSWORD "password"
