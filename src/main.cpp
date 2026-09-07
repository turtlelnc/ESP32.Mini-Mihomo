#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <WiFiUdp.h>
#include <errno.h>
#include <lwip/sockets.h>
#include <memory>
#include <new>

#include "Secrets.h"

namespace {
constexpr uint16_t kControlPort = 50032;
constexpr uint16_t kTransparentTlsPort = 443;
constexpr size_t kHeaderLimit = 4096;
constexpr size_t kClientHelloLimit = 8192;
constexpr unsigned long kWifiAttemptMs = 15000;
constexpr unsigned long kReadTimeoutMs = 8000;
constexpr unsigned long kIdleTimeoutMs = 120000;
constexpr unsigned long kClientAuthorizationMs = 30UL * 60UL * 1000UL;
constexpr uint8_t kMaxConcurrentTunnels = 2;
constexpr uint16_t kDnsForwardPort = 53053;
constexpr uint8_t kMaxPendingDnsQueries = 8;
constexpr unsigned long kDnsForwardTimeoutMs = 5000;

const IPAddress kApAddress(192, 168, 4, 1);
const IPAddress kApNetmask(255, 255, 255, 0);

WiFiServer controlServer(kControlPort);
WiFiServer transparentTlsServer(kTransparentTlsPort);
WiFiServer connectivityServer(80);
WiFiUDP dnsUdp;
WiFiUDP dnsUpstreamUdp;
IPAddress authorizedClientIp;
unsigned long clientAuthorizedAt = 0;
bool clientAuthorizationActive = false;
volatile uint8_t activeTunnelCount = 0;
volatile uint32_t acceptedTunnelCount = 0;
volatile uint32_t failedTunnelCount = 0;

struct PendingDnsQuery {
  bool active = false;
  uint16_t forwardedId = 0;
  uint16_t originalId = 0;
  IPAddress clientAddress;
  uint16_t clientPort = 0;
  unsigned long startedAt = 0;
};

PendingDnsQuery pendingDnsQueries[kMaxPendingDnsQueries];
uint16_t nextForwardedDnsId = 1;

String base64Encode(const String &input) {
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  String output;
  output.reserve(((input.length() + 2) / 3) * 4);
  for (size_t index = 0; index < input.length(); index += 3) {
    const uint32_t a = static_cast<uint8_t>(input[index]);
    const uint32_t b = index + 1 < input.length()
                           ? static_cast<uint8_t>(input[index + 1])
                           : 0;
    const uint32_t c = index + 2 < input.length()
                           ? static_cast<uint8_t>(input[index + 2])
                           : 0;
    const uint32_t group = (a << 16) | (b << 8) | c;
    output += alphabet[(group >> 18) & 0x3f];
    output += alphabet[(group >> 12) & 0x3f];
    output += index + 1 < input.length() ? alphabet[(group >> 6) & 0x3f] : '=';
    output += index + 2 < input.length() ? alphabet[group & 0x3f] : '=';
  }
  return output;
}

bool hasHeaderValue(const String &headers, const String &name,
                    const String &value) {
  int cursor = headers.indexOf("\r\n") + 2;
  while (cursor >= 2 && cursor < static_cast<int>(headers.length())) {
    const int end = headers.indexOf("\r\n", cursor);
    if (end < 0 || end == cursor) break;
    const String line = headers.substring(cursor, end);
    const int colon = line.indexOf(':');
    if (colon > 0) {
      String foundName = line.substring(0, colon);
      String foundValue = line.substring(colon + 1);
      foundName.trim();
      foundValue.trim();
      if (foundName.equalsIgnoreCase(name) && foundValue == value) return true;
    }
    cursor = end + 2;
  }
  return false;
}

bool hasLocalAccess(const String &headers) {
  const String expected = "Basic " +
                          base64Encode(String("esp32:") + LOCAL_ACCESS_PASSWORD);
  return hasHeaderValue(headers, "Authorization", expected);
}

bool isApClient(const IPAddress &address) {
  return address[0] == kApAddress[0] && address[1] == kApAddress[1] &&
         address[2] == kApAddress[2] && address[3] != 0 && address[3] != 255;
}

bool addressInSubnet(const IPAddress &address, const IPAddress &networkAddress,
                     const IPAddress &mask) {
  for (size_t index = 0; index < 4; ++index) {
    if ((address[index] & mask[index]) != (networkAddress[index] & mask[index])) {
      return false;
    }
  }
  return true;
}

bool isLanClient(const IPAddress &address) {
  if (WiFi.status() != WL_CONNECTED) return false;
  const IPAddress stationAddress = WiFi.localIP();
  const IPAddress mask = WiFi.subnetMask();
  return addressInSubnet(address, stationAddress, mask) &&
         address != stationAddress && address != WiFi.broadcastIP();
}

bool isTrustedClient(const IPAddress &address) {
  return isApClient(address) || isLanClient(address);
}

void grantClientAccess(const IPAddress &address) {
  authorizedClientIp = address;
  clientAuthorizedAt = millis();
  clientAuthorizationActive = true;
  Serial.printf("Access granted to AP client %s\n", address.toString().c_str());
}

bool clientHasAccess(const IPAddress &address) {
  if (!clientAuthorizationActive) return false;
  if (millis() - clientAuthorizedAt >= kClientAuthorizationMs) {
    clientAuthorizationActive = false;
    return false;
  }
  return address == authorizedClientIp;
}

bool readHeaders(WiFiClient &client, String &headers) {
  headers = "";
  const unsigned long started = millis();
  while (client.connected() && millis() - started < kReadTimeoutMs) {
    while (client.available()) {
      headers += static_cast<char>(client.read());
      if (headers.endsWith("\r\n\r\n")) return true;
      if (headers.length() > kHeaderLimit) return false;
    }
    delay(1);
  }
  return false;
}

String requestPath(const String &headers) {
  const int firstSpace = headers.indexOf(' ');
  const int secondSpace = headers.indexOf(' ', firstSpace + 1);
  if (firstSpace < 0 || secondSpace < 0) return "";
  return headers.substring(firstSpace + 1, secondSpace);
}

int requestContentLength(const String &headers) {
  int cursor = headers.indexOf("\r\n") + 2;
  while (cursor >= 2 && cursor < static_cast<int>(headers.length())) {
    const int end = headers.indexOf("\r\n", cursor);
    if (end < 0 || end == cursor) break;
    const String line = headers.substring(cursor, end);
    const int colon = line.indexOf(':');
    if (colon > 0) {
      String name = line.substring(0, colon);
      if (name.equalsIgnoreCase("Content-Length")) {
        return line.substring(colon + 1).toInt();
      }
    }
    cursor = end + 2;
  }
  return 0;
}

bool readRequestBody(WiFiClient &client, int length, String &body) {
  if (length < 0 || length > 128) return false;
  body = "";
  body.reserve(length);
  unsigned long lastActivity = millis();
  while (body.length() < static_cast<size_t>(length) && client.connected() &&
         millis() - lastActivity < kReadTimeoutMs) {
    while (client.available() && body.length() < static_cast<size_t>(length)) {
      body += static_cast<char>(client.read());
      lastActivity = millis();
    }
    delay(1);
  }
  return body.length() == static_cast<size_t>(length);
}

void sendLoginPage(WiFiClient &client, bool incorrectPassword) {
  client.print("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
               "Cache-Control: no-store\r\nConnection: close\r\n\r\n"
               "<!doctype html><meta name=viewport content='width=device-width'>"
               "<title>ESP32 ChatGPT</title><style>body{font:16px system-ui;"
               "max-width:28rem;margin:15vh auto;padding:1.5rem}input,button{font:inherit;"
               "padding:.7rem;margin:.4rem 0;width:100%;box-sizing:border-box}"
               ".error{color:#b00020}</style><h1>ESP32 ChatGPT</h1>"
               "<p>Unlock transparent ChatGPT forwarding for this device.</p>");
  if (incorrectPassword) client.print("<p class=error>Incorrect password.</p>");
  client.print("<form method=post action=/login><input type=password name=password "
               "placeholder='Local access password' autofocus required>"
               "<button type=submit>Open ChatGPT</button></form>");
}

void sendStatus(WiFiClient &client) {
  String body;
  body.reserve(256);
  body += "mini_mihomo_mode=transparent_sni\n";
  body += "station_status=" + String(static_cast<int>(WiFi.status())) + "\n";
  body += "station_ip=" + WiFi.localIP().toString() + "\n";
  body += "ap_ip=" + WiFi.softAPIP().toString() + "\n";
  body += "ap_clients=" + String(WiFi.softAPgetStationNum()) + "\n";
  body += "authorization_active=" + String(clientAuthorizationActive ? 1 : 0) + "\n";
  body += "active_tunnels=" + String(activeTunnelCount) + "\n";
  body += "accepted_tls_tunnels=" + String(acceptedTunnelCount) + "\n";
  body += "failed_tls_tunnels=" + String(failedTunnelCount) + "\n";
  body += "free_heap=" + String(ESP.getFreeHeap()) + "\n";
  client.print("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
               "Cache-Control: no-store\r\nConnection: close\r\nContent-Length: ");
  client.print(body.length());
  client.print("\r\n\r\n");
  client.print(body);
}

void handleControlClient(WiFiClient client) {
  String request;
  if (!readHeaders(client, request)) {
    client.stop();
    return;
  }
  const String path = requestPath(request);
  const bool suppliedBasicPassword = hasLocalAccess(request);
  if (!isTrustedClient(client.remoteIP())) {
    client.print("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\n"
                 "Connection: close\r\n\r\nUse the ESP32 Wi-Fi or the same trusted LAN.\n");
  } else if (path == "/__mini_mihomo_status" &&
             (suppliedBasicPassword || clientHasAccess(client.remoteIP()))) {
    if (suppliedBasicPassword) grantClientAccess(client.remoteIP());
    sendStatus(client);
  } else if (path == "/login" && request.startsWith("POST ")) {
    String body;
    const bool validBody = readRequestBody(client, requestContentLength(request), body);
    if (validBody && body == String("password=") + LOCAL_ACCESS_PASSWORD) {
      grantClientAccess(client.remoteIP());
      client.print("HTTP/1.1 302 Found\r\nLocation: https://chatgpt.com/\r\n"
                   "Cache-Control: no-store\r\nConnection: close\r\n"
                   "Content-Length: 0\r\n\r\n");
    } else {
      sendLoginPage(client, true);
    }
  } else if (suppliedBasicPassword) {
    grantClientAccess(client.remoteIP());
    if (path == "/__mini_mihomo_status") {
      sendStatus(client);
    } else {
      client.print("HTTP/1.1 302 Found\r\nLocation: https://chatgpt.com/\r\n"
                   "Cache-Control: no-store\r\nConnection: close\r\n"
                   "Content-Length: 0\r\n\r\n");
    }
  } else {
    sendLoginPage(client, false);
  }
  delay(1);
  client.stop();
}

bool readAll(WiFiClient &client, uint8_t *buffer, size_t length,
             unsigned long timeoutMs) {
  size_t offset = 0;
  unsigned long lastActivity = millis();
  while (offset < length && client.connected() &&
         millis() - lastActivity < timeoutMs) {
    const int available = client.available();
    if (available <= 0) {
      delay(1);
      continue;
    }
    const size_t wanted = min(length - offset, static_cast<size_t>(available));
    const int received = client.read(buffer + offset, wanted);
    if (received > 0) {
      offset += static_cast<size_t>(received);
      lastActivity = millis();
    }
  }
  return offset == length;
}

uint16_t readU16(const uint8_t *data) {
  return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

uint32_t readU24(const uint8_t *data) {
  return (static_cast<uint32_t>(data[0]) << 16) |
         (static_cast<uint32_t>(data[1]) << 8) | data[2];
}

bool takeBytes(size_t &cursor, size_t count, size_t end) {
  if (cursor > end || count > end - cursor) return false;
  cursor += count;
  return true;
}

bool validHostname(const uint8_t *data, size_t length) {
  if (length == 0 || length > 253 || data[0] == '.' || data[length - 1] == '.') {
    return false;
  }
  for (size_t index = 0; index < length; ++index) {
    const char ch = static_cast<char>(data[index]);
    const bool valid = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                       (ch >= '0' && ch <= '9') || ch == '-' || ch == '.';
    if (!valid) return false;
  }
  return true;
}

bool hostnameMatches(const String &hostname, const char *domain) {
  const String suffix(domain);
  if (hostname == suffix) return true;
  return hostname.length() > suffix.length() && hostname.endsWith(suffix) &&
         hostname[hostname.length() - suffix.length() - 1] == '.';
}

bool isChatGptDomain(const String &hostname) {
  static const char *const domains[] = {
      "chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com",
      "auth0.com", "challenges.cloudflare.com", "arkoselabs.com",
      "funcaptcha.com"};
  for (const char *domain : domains) {
    if (hostnameMatches(hostname, domain)) return true;
  }
  return false;
}

bool isConnectivityProbeDomain(const String &hostname) {
  static const char *const domains[] = {
      "captive.apple.com",
      "www.msftconnecttest.com",
      "ipv6.msftconnecttest.com",
      "www.msftncsi.com",
      "ipv6.msftncsi.com",
      "connectivitycheck.gstatic.com",
      "connectivitycheck.android.com",
      "clients3.google.com",
      "play.googleapis.com",
      "firefox-portal-detection.com",
      "detectportal.firefox.com"};
  for (const char *domain : domains) {
    if (hostname == domain) return true;
  }
  return false;
}

bool parseClientHelloSni(const uint8_t *record, size_t recordLength,
                         String &hostname) {
  if (recordLength < 9 || record[0] != 0x16 || record[1] != 0x03) return false;
  const size_t payloadEnd = 5 + readU16(record + 3);
  if (payloadEnd != recordLength || record[5] != 0x01) return false;
  const size_t helloEnd = 9 + readU24(record + 6);
  if (helloEnd > payloadEnd) return false;  // Fragmented ClientHello is unsupported.

  size_t cursor = 9;
  if (!takeBytes(cursor, 2 + 32, helloEnd)) return false;
  if (cursor >= helloEnd) return false;
  const size_t sessionIdLength = record[cursor++];
  if (!takeBytes(cursor, sessionIdLength, helloEnd) || cursor + 2 > helloEnd) return false;
  const size_t cipherLength = readU16(record + cursor);
  cursor += 2;
  if (!takeBytes(cursor, cipherLength, helloEnd) || cursor >= helloEnd) return false;
  const size_t compressionLength = record[cursor++];
  if (!takeBytes(cursor, compressionLength, helloEnd) || cursor + 2 > helloEnd) return false;
  const size_t extensionsLength = readU16(record + cursor);
  cursor += 2;
  if (extensionsLength > helloEnd - cursor) return false;
  const size_t extensionsEnd = cursor + extensionsLength;

  while (cursor + 4 <= extensionsEnd) {
    const uint16_t type = readU16(record + cursor);
    const size_t length = readU16(record + cursor + 2);
    cursor += 4;
    if (length > extensionsEnd - cursor) return false;
    const size_t extensionEnd = cursor + length;
    if (type == 0) {
      if (cursor + 2 > extensionEnd) return false;
      const size_t listLength = readU16(record + cursor);
      cursor += 2;
      if (listLength > extensionEnd - cursor) return false;
      const size_t listEnd = cursor + listLength;
      while (cursor + 3 <= listEnd) {
        const uint8_t nameType = record[cursor++];
        const size_t nameLength = readU16(record + cursor);
        cursor += 2;
        if (nameLength > listEnd - cursor) return false;
        if (nameType == 0 && validHostname(record + cursor, nameLength)) {
          hostname = "";
          hostname.reserve(nameLength);
          for (size_t index = 0; index < nameLength; ++index) {
            char ch = static_cast<char>(record[cursor + index]);
            hostname += static_cast<char>(tolower(static_cast<unsigned char>(ch)));
          }
          return true;
        }
        cursor += nameLength;
      }
      return false;
    }
    cursor = extensionEnd;
  }
  return false;
}

bool readClientHello(WiFiClient &client, uint8_t *buffer, size_t &length,
                     String &hostname) {
  if (!readAll(client, buffer, 5, kReadTimeoutMs)) return false;
  const size_t payloadLength = readU16(buffer + 3);
  length = 5 + payloadLength;
  if (payloadLength < 4 || length > kClientHelloLimit) return false;
  if (!readAll(client, buffer + 5, payloadLength, kReadTimeoutMs)) return false;
  return parseClientHelloSni(buffer, length, hostname);
}

void expirePendingDnsQueries() {
  const unsigned long now = millis();
  for (PendingDnsQuery &pending : pendingDnsQueries) {
    if (pending.active && now - pending.startedAt >= kDnsForwardTimeoutMs) {
      pending.active = false;
    }
  }
}

bool forwardDnsRequest(uint8_t *query, size_t length,
                       const IPAddress &clientAddress, uint16_t clientPort) {
  expirePendingDnsQueries();
  PendingDnsQuery *slot = nullptr;
  for (PendingDnsQuery &pending : pendingDnsQueries) {
    if (!pending.active) {
      slot = &pending;
      break;
    }
  }
  if (!slot || length < 12 || WiFi.status() != WL_CONNECTED) return false;

  IPAddress resolver = WiFi.dnsIP(0);
  if (resolver == IPAddress(0, 0, 0, 0)) resolver = WiFi.gatewayIP();
  if (resolver == IPAddress(0, 0, 0, 0)) return false;

  const uint16_t originalId = readU16(query);
  ++nextForwardedDnsId;
  if (nextForwardedDnsId == 0) ++nextForwardedDnsId;
  query[0] = static_cast<uint8_t>(nextForwardedDnsId >> 8);
  query[1] = static_cast<uint8_t>(nextForwardedDnsId & 0xff);

  if (!dnsUpstreamUdp.beginPacket(resolver, 53) ||
      dnsUpstreamUdp.write(query, length) != length ||
      !dnsUpstreamUdp.endPacket()) {
    query[0] = static_cast<uint8_t>(originalId >> 8);
    query[1] = static_cast<uint8_t>(originalId & 0xff);
    return false;
  }

  slot->active = true;
  slot->forwardedId = nextForwardedDnsId;
  slot->originalId = originalId;
  slot->clientAddress = clientAddress;
  slot->clientPort = clientPort;
  slot->startedAt = millis();
  return true;
}

void processForwardedDnsResponse() {
  const int packetSize = dnsUpstreamUdp.parsePacket();
  if (packetSize <= 0) {
    expirePendingDnsQueries();
    return;
  }
  if (packetSize < 12 || packetSize > 512) {
    uint8_t discard[64];
    while (dnsUpstreamUdp.available()) {
      dnsUpstreamUdp.read(discard, sizeof(discard));
    }
    return;
  }

  uint8_t response[512];
  const int received = dnsUpstreamUdp.read(response, sizeof(response));
  if (received != packetSize) return;
  const uint16_t forwardedId = readU16(response);
  for (PendingDnsQuery &pending : pendingDnsQueries) {
    if (!pending.active || pending.forwardedId != forwardedId) continue;
    response[0] = static_cast<uint8_t>(pending.originalId >> 8);
    response[1] = static_cast<uint8_t>(pending.originalId & 0xff);
    dnsUdp.beginPacket(pending.clientAddress, pending.clientPort);
    dnsUdp.write(response, received);
    dnsUdp.endPacket();
    pending.active = false;
    return;
  }
}

void processDnsRequest() {
  const int packetSize = dnsUdp.parsePacket();
  if (packetSize < 12 || packetSize > 512) {
    if (packetSize > 0) {
      uint8_t discard[64];
      while (dnsUdp.available()) dnsUdp.read(discard, sizeof(discard));
    }
    return;
  }

  uint8_t query[512];
  const int received = dnsUdp.read(query, sizeof(query));
  if (received != packetSize || (query[2] & 0x80) != 0 ||
      readU16(query + 4) == 0) {
    return;
  }

  size_t cursor = 12;
  String hostname;
  while (cursor < static_cast<size_t>(received) && query[cursor] != 0) {
    const uint8_t labelLength = query[cursor];
    if ((labelLength & 0xc0) != 0 || labelLength > 63 ||
        cursor + 1 + labelLength >= static_cast<size_t>(received)) {
      return;
    }
    if (!hostname.isEmpty()) hostname += '.';
    for (size_t index = 0; index < labelLength; ++index) {
      const char ch = static_cast<char>(query[cursor + 1 + index]);
      hostname += static_cast<char>(tolower(static_cast<unsigned char>(ch)));
    }
    cursor += 1 + labelLength;
  }
  if (cursor + 5 > static_cast<size_t>(received)) return;
  ++cursor;
  const uint16_t queryType = readU16(query + cursor);
  const uint16_t queryClass = readU16(query + cursor + 2);
  const size_t questionEnd = cursor + 4;
  const IPAddress requester = dnsUdp.remoteIP();
  const uint16_t requesterPort = dnsUdp.remotePort();
  if (!isTrustedClient(requester)) return;
  IPAddress answerAddress;
  const bool localDomain = isChatGptDomain(hostname) ||
                           isConnectivityProbeDomain(hostname);
  if (!localDomain) {
    forwardDnsRequest(query, received, requester, requesterPort);
    return;
  }
  bool answerWithIpv4 = queryType == 1 && queryClass == 1;
  if (answerWithIpv4) {
    answerAddress = isApClient(requester) ? kApAddress : WiFi.localIP();
  }

  uint8_t response[528];
  memcpy(response, query, questionEnd);
  response[2] = 0x81;  // Response, recursion desired copied, recursion available.
  response[3] = 0x80;
  response[4] = 0;
  response[5] = 1;
  response[6] = 0;
  response[7] = answerWithIpv4 ? 1 : 0;
  response[8] = response[9] = response[10] = response[11] = 0;
  size_t responseLength = questionEnd;

  if (answerWithIpv4) {
    const uint8_t answer[] = {
        0xc0, 0x0c,              // Compressed name: first question.
        0x00, 0x01,              // A record.
        0x00, 0x01,              // Internet class.
        0x00, 0x00, 0x00, 0x00,  // Do not cache the intercepted address.
        0x00, 0x04,
        answerAddress[0], answerAddress[1], answerAddress[2], answerAddress[3]};
    memcpy(response + responseLength, answer, sizeof(answer));
    responseLength += sizeof(answer);
  }

  dnsUdp.beginPacket(dnsUdp.remoteIP(), dnsUdp.remotePort());
  dnsUdp.write(response, responseLength);
  dnsUdp.endPacket();
}

void sendHttpBody(WiFiClient &client, const char *contentType,
                  const char *body) {
  client.print("HTTP/1.1 200 OK\r\nContent-Type: ");
  client.print(contentType);
  client.print("\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: ");
  client.print(strlen(body));
  client.print("\r\n\r\n");
  client.print(body);
}

void handleConnectivityClient(WiFiClient client) {
  String request;
  if (!readHeaders(client, request)) {
    client.stop();
    return;
  }
  const String path = requestPath(request);
  if (path == "/generate_204" || path.startsWith("/generate_204?")) {
    client.print("HTTP/1.1 204 No Content\r\nCache-Control: no-store\r\n"
                 "Connection: close\r\n\r\n");
  } else if (path == "/connecttest.txt") {
    sendHttpBody(client, "text/plain", "Microsoft Connect Test");
  } else if (path == "/ncsi.txt") {
    sendHttpBody(client, "text/plain", "Microsoft NCSI");
  } else if (path == "/hotspot-detect.html") {
    sendHttpBody(client, "text/html",
                 "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>");
  } else if (path == "/success.txt" || path.startsWith("/success.txt?")) {
    sendHttpBody(client, "text/plain", "success\n");
  } else {
    client.print("HTTP/1.1 302 Found\r\nLocation: http://");
    client.print(client.localIP().toString());
    client.print(":50032/\r\nCache-Control: no-store\r\nConnection: close\r\n"
                 "Content-Length: 0\r\n\r\n");
  }
  delay(1);
  client.stop();
}

bool readHttpHeaders(WiFiClientSecure &client, String &headers) {
  headers = "";
  unsigned long lastActivity = millis();
  while (client.connected() && millis() - lastActivity < kReadTimeoutMs) {
    while (client.available()) {
      headers += static_cast<char>(client.read());
      lastActivity = millis();
      if (headers.endsWith("\r\n\r\n")) return true;
      if (headers.length() > kHeaderLimit) return false;
    }
    delay(1);
  }
  return false;
}

bool connectUpstream(WiFiClientSecure &upstream, const String &target) {
  // The subscription does not include a CA chain. The hop is encrypted, but
  // its certificate is not verified. Browser-to-origin TLS remains untouched.
  upstream.setTimeout(15);
  upstream.setHandshakeTimeout(15);
  upstream.setInsecure();
  if (!upstream.connect(UPSTREAM_PROXY_HOST, UPSTREAM_PROXY_PORT, 15000)) {
    char error[128];
    const int code = upstream.lastError(error, sizeof(error));
    Serial.printf("Upstream TLS failed for %s (%d): %s\n", target.c_str(), code, error);
    return false;
  }

  const String credentials =
      base64Encode(String(UPSTREAM_PROXY_USERNAME) + ":" + UPSTREAM_PROXY_PASSWORD);
  upstream.print("CONNECT ");
  upstream.print(target);
  upstream.print(" HTTP/1.1\r\nHost: ");
  upstream.print(target);
  upstream.print("\r\nProxy-Authorization: Basic ");
  upstream.print(credentials);
  upstream.print("\r\nProxy-Connection: keep-alive\r\n\r\n");

  String response;
  if (!readHttpHeaders(upstream, response)) {
    Serial.printf("Upstream CONNECT timed out for %s\n", target.c_str());
    return false;
  }
  const int lineEnd = response.indexOf("\r\n");
  const String status = lineEnd < 0 ? response : response.substring(0, lineEnd);
  const bool accepted = status.startsWith("HTTP/1.1 200") ||
                        status.startsWith("HTTP/1.0 200");
  Serial.printf("Upstream CONNECT %s: %s\n", target.c_str(), status.c_str());
  return accepted;
}

template <typename Client>
bool writeAll(Client &client, const uint8_t *data, size_t length) {
  size_t offset = 0;
  unsigned long lastActivity = millis();
  while (offset < length && client.connected() &&
         millis() - lastActivity < kReadTimeoutMs) {
    const size_t written = client.write(data + offset, length - offset);
    if (written > 0) {
      offset += written;
      lastActivity = millis();
    } else {
      delay(1);
    }
  }
  return offset == length;
}

bool socketOpen(WiFiClient &client) {
  const int socket = client.fd();
  if (socket < 0) return false;
  uint8_t byte = 0;
  const int result = recv(socket, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
  if (result > 0) return true;
  if (result == 0) return false;  // Orderly TCP FIN from the peer.
  return errno == EWOULDBLOCK || errno == EAGAIN;
}

void relay(WiFiClient &downstream, WiFiClientSecure &upstream,
           bool fromAccessPoint) {
  uint8_t buffer[1024];
  unsigned long lastActivity = millis();
  while (socketOpen(downstream) && socketOpen(upstream) &&
         millis() - lastActivity < kIdleTimeoutMs) {
    if (fromAccessPoint && WiFi.softAPgetStationNum() == 0) return;
    bool moved = false;
    while (downstream.available()) {
      const int received = downstream.read(buffer, sizeof(buffer));
      if (received <= 0 || !writeAll(upstream, buffer, received)) return;
      moved = true;
    }
    while (upstream.available()) {
      const int received = upstream.read(buffer, sizeof(buffer));
      if (received <= 0 || !writeAll(downstream, buffer, received)) return;
      moved = true;
    }
    if (moved) {
      lastActivity = millis();
    } else {
      delay(1);
    }
  }
}

struct TransparentTunnelJob {
  WiFiClient downstream;
  bool fromAccessPoint;
};

void runTransparentTunnel(void *context) {
  std::unique_ptr<TransparentTunnelJob> job(
      static_cast<TransparentTunnelJob *>(context));
  std::unique_ptr<uint8_t[]> hello(new (std::nothrow) uint8_t[kClientHelloLimit]);
  size_t helloLength = 0;
  String hostname;
  WiFiClientSecure upstream;

  if (!hello || !readClientHello(job->downstream, hello.get(), helloLength, hostname)) {
    ++failedTunnelCount;
    Serial.printf("Rejected invalid TLS ClientHello from %s\n",
                  job->downstream.remoteIP().toString().c_str());
  } else {
    const String target = hostname + ":443";
    Serial.printf("Transparent TLS request: %s\n", target.c_str());
    if (connectUpstream(upstream, target) &&
        writeAll(upstream, hello.get(), helloLength)) {
      ++acceptedTunnelCount;
      hello.reset();
      relay(job->downstream, upstream, job->fromAccessPoint);
    } else {
      ++failedTunnelCount;
    }
  }

  upstream.stop();
  job->downstream.stop();
  if (activeTunnelCount > 0) --activeTunnelCount;
  vTaskDelete(nullptr);
}

void acceptTransparentTunnel(WiFiClient client) {
  const IPAddress remote = client.remoteIP();
  if (!isTrustedClient(remote) || !clientHasAccess(remote)) {
    client.stop();
    return;
  }
  std::unique_ptr<TransparentTunnelJob> job(
      new (std::nothrow) TransparentTunnelJob{client, isApClient(remote)});
  if (!job) {
    client.stop();
    return;
  }
  ++activeTunnelCount;
  if (xTaskCreatePinnedToCore(runTransparentTunnel, "sni-tunnel", 12288,
                              job.get(), 1, nullptr, 1) != pdPASS) {
    --activeTunnelCount;
    client.stop();
    return;
  }
  job.release();
}

bool connectWifi(const char *ssid, const char *password) {
  WiFi.begin(ssid, password);
  const unsigned long started = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - started < kWifiAttemptMs) {
    delay(250);
  }
  return WiFi.status() == WL_CONNECTED;
}

void ensureWifi() {
  if (WiFi.status() == WL_CONNECTED) return;
  Serial.println("Wi-Fi: trying primary network");
  WiFi.disconnect();
  if (!connectWifi(WIFI_PRIMARY_SSID, WIFI_PRIMARY_PASSWORD)) {
    Serial.printf("Wi-Fi: primary failed (status %d); trying fallback\n", WiFi.status());
    WiFi.disconnect();
    if (!connectWifi(WIFI_FALLBACK_SSID, WIFI_FALLBACK_PASSWORD)) {
      Serial.printf("Wi-Fi: fallback failed (status %d)\n", WiFi.status());
    }
  }
}

void startAccessPoint() {
  if (!WiFi.softAPConfig(kApAddress, kApAddress, kApNetmask)) {
    Serial.println("SoftAP address configuration failed");
  }
  if (!WiFi.softAP(ESP32_AP_SSID, ESP32_AP_PASSWORD, 1, 0, 2)) {
    Serial.println("SoftAP startup failed");
  }
  if (dnsUdp.begin(53) != 1) {
    Serial.println("Selective DNS startup failed");
  }
  if (dnsUpstreamUdp.begin(kDnsForwardPort) != 1) {
    Serial.println("DNS forward socket startup failed");
  }
  controlServer.begin();
  transparentTlsServer.begin();
  connectivityServer.begin();
  Serial.printf("Connect to AP %s, then open http://%s:%u\n", ESP32_AP_SSID,
                kApAddress.toString().c_str(), kControlPort);
}
}  // namespace

void setup() {
  Serial.begin(115200);
  WiFi.persistent(false);
  WiFi.mode(WIFI_AP_STA);
  WiFi.setSleep(false);
  WiFi.setAutoReconnect(true);
  ensureWifi();
  startAccessPoint();
  Serial.printf("Station uplink: %s\n", WiFi.localIP().toString().c_str());
}

void loop() {
  processForwardedDnsResponse();
  processDnsRequest();

  WiFiClient control = controlServer.available();
  if (control) handleControlClient(control);

  WiFiClient connectivity = connectivityServer.available();
  if (connectivity) handleConnectivityClient(connectivity);

  if (activeTunnelCount < kMaxConcurrentTunnels) {
    WiFiClient tls = transparentTlsServer.available();
    if (tls) acceptTransparentTunnel(tls);
  }

  static unsigned long nextWifiCheck = 0;
  if (millis() >= nextWifiCheck) {
    if (WiFi.status() != WL_CONNECTED) ensureWifi();
    nextWifiCheck = millis() + 10000;
  }
  delay(1);
}
