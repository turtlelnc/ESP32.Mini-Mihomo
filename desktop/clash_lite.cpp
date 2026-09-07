#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <array>
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "../include/Secrets.h"

namespace {
constexpr int kListenPort = 12321;
constexpr std::size_t kHeaderLimit = 8192;
std::atomic<unsigned long> acceptedTunnels{0};

struct FdCloser {
  void operator()(int *fd) const {
    if (fd && *fd >= 0) close(*fd);
    delete fd;
  }
};
using Socket = std::unique_ptr<int, FdCloser>;

struct Node {
  std::string host;
  std::string port;
  std::string username;
  std::string password;
  std::string label;
};

Socket makeSocket(int fd) { return Socket(new int(fd)); }

int socketFn(int family, int type, int protocol) { return socket(family, type, protocol); }

std::string base64(const std::string &input) {
  std::string output(4 * ((input.size() + 2) / 3), '\0');
  const int size = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output.data()),
                                   reinterpret_cast<const unsigned char *>(input.data()),
                                   static_cast<int>(input.size()));
  output.resize(size);
  return output;
}

std::optional<std::string> base64Decode(std::string input) {
  input.erase(std::remove_if(input.begin(), input.end(), [](unsigned char c) { return std::isspace(c); }),
              input.end());
  if (input.empty()) return std::string{};
  input.append((4 - input.size() % 4) % 4, '=');
  std::string output(3 * (input.size() / 4), '\0');
  const int size = EVP_DecodeBlock(reinterpret_cast<unsigned char *>(output.data()),
                                   reinterpret_cast<const unsigned char *>(input.data()),
                                   static_cast<int>(input.size()));
  if (size < 0) return std::nullopt;
  std::size_t padding = 0;
  if (!input.empty() && input.back() == '=') ++padding;
  if (input.size() > 1 && input[input.size() - 2] == '=') ++padding;
  output.resize(static_cast<std::size_t>(size) - padding);
  return output;
}

std::optional<Node> parseHttpNode(const std::string &encodedUri) {
  constexpr std::string_view prefix = "https://";
  if (encodedUri.rfind(prefix, 0) != 0) return std::nullopt;
  const auto decoded = base64Decode(encodedUri.substr(prefix.size()));
  if (!decoded) return std::nullopt;
  const std::string &raw = *decoded;  // user:password@host:port/#name
  const std::size_t at = raw.find('@');
  const std::size_t separator = raw.find(':');
  const std::size_t slash = raw.find('/', at == std::string::npos ? 0 : at);
  if (at == std::string::npos || separator == std::string::npos || slash == std::string::npos) return std::nullopt;
  const std::string endpoint = raw.substr(at + 1, slash - at - 1);
  const std::size_t portSeparator = endpoint.rfind(':');
  if (portSeparator == std::string::npos) return std::nullopt;
  Node node{endpoint.substr(0, portSeparator), endpoint.substr(portSeparator + 1),
            raw.substr(0, separator), raw.substr(separator + 1, at - separator - 1), ""};
  const std::size_t hash = raw.find('#');
  if (hash != std::string::npos) node.label = raw.substr(hash + 1);
  return node;
}

std::optional<Node> loadSubscriptionNode(const std::string &path, const std::string &preferredLabel) {
  std::ifstream file(path, std::ios::binary);
  std::stringstream contents;
  contents << file.rdbuf();
  const auto decoded = base64Decode(contents.str());
  if (!decoded) return std::nullopt;
  std::istringstream lines(*decoded);
  std::string line;
  std::optional<Node> firstNode;
  while (std::getline(lines, line)) {
    const auto node = parseHttpNode(line);
    if (!node) continue;
    if (!firstNode) firstNode = node;
    if (node->label.find(preferredLabel) != std::string::npos) return node;
  }
  return firstNode;
}

Node macroNode() {
  return {UPSTREAM_PROXY_HOST, std::to_string(UPSTREAM_PROXY_PORT),
          UPSTREAM_PROXY_USERNAME, UPSTREAM_PROXY_PASSWORD, "macro fallback"};
}

bool writeAll(int fd, const char *data, std::size_t size) {
  while (size > 0) {
    const ssize_t written = send(fd, data, size, 0);
    if (written <= 0) return false;
    data += written;
    size -= static_cast<std::size_t>(written);
  }
  return true;
}

bool sslWriteAll(SSL *ssl, const char *data, std::size_t size) {
  while (size > 0) {
    const int written = SSL_write(ssl, data, static_cast<int>(size));
    if (written <= 0) return false;
    data += written;
    size -= static_cast<std::size_t>(written);
  }
  return true;
}

bool readHeaders(int fd, std::string &headers) {
  std::array<char, 512> buffer{};
  headers.clear();
  while (headers.size() <= kHeaderLimit) {
    const ssize_t received = recv(fd, buffer.data(), buffer.size(), 0);
    if (received <= 0) return false;
    headers.append(buffer.data(), static_cast<std::size_t>(received));
    if (headers.find("\r\n\r\n") != std::string::npos) return true;
  }
  return false;
}

bool sslReadHeaders(SSL *ssl, std::string &headers) {
  std::array<char, 512> buffer{};
  headers.clear();
  while (headers.size() <= kHeaderLimit) {
    const int received = SSL_read(ssl, buffer.data(), static_cast<int>(buffer.size()));
    if (received <= 0) return false;
    headers.append(buffer.data(), static_cast<std::size_t>(received));
    if (headers.find("\r\n\r\n") != std::string::npos) return true;
  }
  return false;
}

Socket connectTcp(const char *host, const char *port) {
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  addrinfo *results = nullptr;
  if (getaddrinfo(host, port, &hints, &results) != 0) return {};
  Socket socket;
  for (addrinfo *entry = results; entry; entry = entry->ai_next) {
    const int fd = socketFn(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, entry->ai_addr, entry->ai_addrlen) == 0) {
      socket = makeSocket(fd);
      break;
    }
    close(fd);
  }
  freeaddrinfo(results);
  return socket;
}

bool authorized(const std::string &headers) {
  const std::string expected = "Proxy-Authorization: Basic " +
                               base64(std::string("esp32:") + LOCAL_ACCESS_PASSWORD);
  return headers.find(expected) != std::string::npos;
}

void relay(int localFd, SSL *upstream) {
  std::array<char, 4096> buffer{};
  while (true) {
    pollfd watch{localFd, POLLIN, 0};
    const int ready = poll(&watch, 1, 25);
    if (ready < 0) break;
    if (ready > 0 && (watch.revents & POLLIN)) {
      const ssize_t got = recv(localFd, buffer.data(), buffer.size(), 0);
      if (got <= 0 || !sslWriteAll(upstream, buffer.data(), static_cast<std::size_t>(got))) break;
    }
    if (SSL_pending(upstream) > 0) {
      const int got = SSL_read(upstream, buffer.data(), static_cast<int>(buffer.size()));
      if (got <= 0 || !writeAll(localFd, buffer.data(), static_cast<std::size_t>(got))) break;
      continue;
    }
    pollfd upstreamFd{SSL_get_fd(upstream), POLLIN, 0};
    if (poll(&upstreamFd, 1, 0) > 0 && (upstreamFd.revents & POLLIN)) {
      const int got = SSL_read(upstream, buffer.data(), static_cast<int>(buffer.size()));
      if (got <= 0 || !writeAll(localFd, buffer.data(), static_cast<std::size_t>(got))) break;
    }
  }
}

void handleClient(int localFd, SSL_CTX *tlsContext, const Node &node) {
  std::string request;
  if (!readHeaders(localFd, request)) return;
  if (request.rfind("GET /__mini_mihomo_status", 0) == 0) {
    const std::string body = "accepted_connect_tunnels=" + std::to_string(acceptedTunnels.load()) + "\n";
    const std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
                                 std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    writeAll(localFd, response.data(), response.size());
    return;
  }
  // The desktop test listener is bound to loopback only. Ghelper's custom
  // proxy form cannot provide Basic credentials, so local clients are allowed.
  if (request.rfind("CONNECT ", 0) != 0) {
    writeAll(localFd, "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n", 57);
    return;
  }
  const auto firstBreak = request.find("\r\n");
  const auto firstSpace = request.find(' ');
  const auto secondSpace = request.find(' ', firstSpace + 1);
  if (firstBreak == std::string::npos || secondSpace == std::string::npos) return;
  const std::string target = request.substr(firstSpace + 1, secondSpace - firstSpace - 1);
  ++acceptedTunnels;
  std::cerr << "Accepted CONNECT tunnel to " << target << "\n";

  Socket upstreamFd = connectTcp(node.host.c_str(), node.port.c_str());
  if (!upstreamFd) {
    writeAll(localFd, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n", 47);
    return;
  }
  SSL *upstream = SSL_new(tlsContext);
  SSL_set_fd(upstream, *upstreamFd);
  SSL_set_tlsext_host_name(upstream, node.host.c_str());
  if (SSL_connect(upstream) != 1) {
    SSL_free(upstream);
    writeAll(localFd, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n", 47);
    return;
  }
  const std::string connectRequest = "CONNECT " + target + " HTTP/1.1\r\nHost: " + target +
      "\r\nProxy-Authorization: Basic " +
      base64(node.username + ":" + node.password) +
      "\r\nProxy-Connection: keep-alive\r\n\r\n";
  std::string response;
  if (!sslWriteAll(upstream, connectRequest.data(), connectRequest.size()) ||
      !sslReadHeaders(upstream, response) || response.rfind("HTTP/1.1 200", 0) != 0) {
    SSL_free(upstream);
    writeAll(localFd, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n", 47);
    return;
  }
  writeAll(localFd, "HTTP/1.1 200 Connection Established\r\n\r\n", 39);
  relay(localFd, upstream);
  SSL_free(upstream);
}
}  // namespace

int main(int argc, char **argv) {
  Node node = macroNode();
  if (argc == 3 && std::string(argv[1]) == "--subscription") {
    const auto parsed = loadSubscriptionNode(argv[2], "新加坡3");
    if (!parsed) {
      std::cerr << "No HTTPS HTTP proxy node could be read from the subscription.\n";
      return 1;
    }
    node = *parsed;
  } else if (argc != 1) {
    std::cerr << "Usage: mini-mihomo [--subscription /path/to/default-subscription.txt]\n";
    return 1;
  }
  SSL_library_init();
  SSL_CTX *context = SSL_CTX_new(TLS_client_method());
  SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nullptr);

  const int server = socket(AF_INET, SOCK_STREAM, 0);
  const int reuse = 1;
  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(kListenPort);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(server, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 || listen(server, 4) != 0) {
    std::cerr << "Unable to listen on 127.0.0.1:" << kListenPort << "\n";
    return 1;
  }
  std::cout << "mini-mihomo listening on 127.0.0.1:" << kListenPort
            << " using " << node.label << "\n";
  while (true) {
    const int client = accept(server, nullptr, nullptr);
    if (client >= 0) {
      std::thread([client, context, node] {
        handleClient(client, context, node);
        close(client);
      }).detach();
    }
  }
}
