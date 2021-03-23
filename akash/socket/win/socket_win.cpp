// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/socket/win/socket_win.h"

#include <WS2tcpip.h>

#include "utils/log.h"
#include "utils/convert.h"

#pragma comment(lib, "Ws2_32.lib")


namespace akash {
namespace win {

    bool is_initialized_ = false;

    void initializeSocket() {
        if (is_initialized_) {
            LOG(Log::ERR) << "Winsock.dll is already initialized!";
            return;
        }

        WORD ver_req = MAKEWORD(2, 2);
        WSADATA wsa_data;

        auto ret = WSAStartup(ver_req, &wsa_data);
        if (ret != 0) {
            LOG(Log::ERR) << "Failed to init Winsock.dll: " << ret;
        }

        if (LOBYTE(wsa_data.wVersion) != 2 || HIBYTE(wsa_data.wVersion) != 2) {
            LOG(Log::ERR) << "Could not find a usable version of Winsock.dll";
            WSACleanup();
        }

        is_initialized_ = true;
    }

    void unInitializeSocket() {
        WSACleanup();
        is_initialized_ = false;
    }

    bool isSocketInitialized() {
        return is_initialized_;
    }


    // SocketClient
    SocketClientWin::SocketClientWin()
        : socket_(INVALID_SOCKET) {
    }

    SocketClientWin::~SocketClientWin() {
        if (socket_ != INVALID_SOCKET) {
            closesocket(socket_);
        }
    }

    bool SocketClientWin::connect(const std::string& ip, uint16_t port) {
        if (!is_initialized_) {
            LOG(Log::ERR) << "Winsock.dll is not initialized!";
            return false;
        }

        if (socket_ != INVALID_SOCKET) {
            LOG(Log::ERR) << "This client is already connected!";
            return false;
        }

        socket_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socket_ == INVALID_SOCKET) {
            LOG(Log::ERR) << "Failed to create socket: " << WSAGetLastError();
            return false;
        }

        ULONG addr_bin = 0;
        if (InetPtonA(AF_INET, ip.c_str(), &addr_bin) != 1) {
            LOG(Log::ERR) << "Failed to convert ip addr: " << WSAGetLastError();
        }

        sockaddr_in addr = { 0 };
        addr.sin_family = AF_INET;
        addr.sin_addr.S_un.S_addr = addr_bin;
        addr.sin_port = htons(port);

        if (::connect(socket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            LOG(Log::ERR) << "Failed to connect: " << WSAGetLastError();
            return false;
        }

        return true;
    }

    bool SocketClientWin::connectByHost(const std::string& host, uint16_t port) {
        if (!is_initialized_) {
            LOG(Log::ERR) << "Winsock.dll is not initialized!";
            return false;
        }

        if (socket_ != INVALID_SOCKET) {
            LOG(Log::ERR) << "This client is already connected!";
            return false;
        }

        socket_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socket_ == INVALID_SOCKET) {
            LOG(Log::ERR) << "Failed to create socket: " << WSAGetLastError();
            return false;
        }

        ADDRINFOA addr_info = { 0 };
        addr_info.ai_family = AF_INET;
        addr_info.ai_socktype = SOCK_STREAM;
        addr_info.ai_protocol = IPPROTO_TCP;

        PADDRINFOA addr_ret = nullptr;
        auto result = ::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &addr_info, &addr_ret);
        if (result != 0) {
            LOG(Log::ERR) << "Failed to get addr info: " << result;
            return false;
        }
        if (!addr_ret) {
            LOG(Log::ERR) << "No addr info";
            return false;
        }

        sockaddr_in addr = { 0 };
        memcpy(&addr, addr_ret->ai_addr, addr_ret->ai_addrlen);
        freeaddrinfo(addr_ret);

        if (::connect(socket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            LOG(Log::ERR) << "Failed to connect: " << WSAGetLastError();
            return false;
        }

        return true;
    }

    bool SocketClientWin::send(const std::string& buf) {
        if (socket_ == INVALID_SOCKET) {
            LOG(Log::ERR) << "Invalid socket.";
            return false;
        }

        auto bytes_sent = ::send(socket_, buf.data(), utl::STLCInt(buf.length()), 0);
        if (bytes_sent == SOCKET_ERROR) {
            LOG(Log::ERR) << "Failed to send: " << WSAGetLastError();
            return false;
        }
        return true;
    }

    bool SocketClientWin::recv(int length, std::string* buf) {
        if (length <= 0) {
            return true;
        }
        if (socket_ == INVALID_SOCKET) {
            LOG(Log::ERR) << "Invalid socket.";
            return false;
        }

        int bytes_revd;
        char recv_buf[512];
        std::string response;

        do {
            int cur_length = (length >= 512) ? 512 : length;

            bytes_revd = ::recv(socket_, recv_buf, cur_length, 0);
            if (bytes_revd > 0) {
                response.append(recv_buf, bytes_revd);
                length -= bytes_revd;
            } else if (bytes_revd == 0) {
                LOG(Log::INFO) << "Connection closed";
            } else {
                LOG(Log::ERR) << "Failed to recv: " << WSAGetLastError();
                return false;
            }
        } while (bytes_revd > 0 && length > 0);

        *buf = std::move(response);
        return true;
    }

    bool SocketClientWin::recv(std::string* buf) {
        if (socket_ == INVALID_SOCKET) {
            LOG(Log::ERR) << "Invalid socket.";
            return false;
        }

        int bytes_revd;
        char recv_buf[512];
        std::string response;

        do {
            bytes_revd = ::recv(socket_, recv_buf, 512, 0);
            if (bytes_revd > 0) {
                response.append(recv_buf, bytes_revd);
            } else if (bytes_revd == 0) {
                LOG(Log::INFO) << "Connection closed";
            } else {
                LOG(Log::ERR) << "Failed to recv: " << WSAGetLastError();
                return false;
            }
        } while (bytes_revd > 0);

        *buf = std::move(response);
        return true;
    }

    bool SocketClientWin::shutdown() {
        if (socket_ != INVALID_SOCKET) {
            if (::shutdown(socket_, SD_SEND) == SOCKET_ERROR) {
                LOG(Log::ERR) << "Failed to shutdown: " << WSAGetLastError();
                return false;
            }
        }
        return true;
    }

    void SocketClientWin::close() {
        if (socket_ != INVALID_SOCKET) {
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
        }
    }

    bool SocketClientWin::wait(WaitType type, int timeout_sec) {
        if (type == WaitType::SEND) {
            FD_SET wset;
            FD_ZERO(&wset);
            FD_SET(socket_, &wset);
            timeval timeout = { timeout_sec, 0 };
            int ret = ::select(socket_ + 1, nullptr, &wset, nullptr, timeout_sec == -1 ? nullptr : &timeout);
            if (ret == SOCKET_ERROR) {
                LOG(Log::ERR) << "Failed to select: " << WSAGetLastError();
                return false;
            }

            if (FD_ISSET(socket_, &wset)) {
                return true;
            }
        } else if (type == WaitType::RECV) {
            FD_SET rset;
            FD_ZERO(&rset);
            FD_SET(socket_, &rset);
            timeval timeout = { timeout_sec, 0 };
            int ret = ::select(socket_ + 1, &rset, nullptr, nullptr, timeout_sec == -1 ? nullptr : &timeout);
            if (ret == SOCKET_ERROR) {
                LOG(Log::ERR) << "Failed to select: " << WSAGetLastError();
                return false;
            }

            if (FD_ISSET(socket_, &rset)) {
                return true;
            }
        }
        return false;
    }


    // SocketServer
    SocketServerWin::SocketServerWin()
        : server_socket_(INVALID_SOCKET),
          accept_socket_(INVALID_SOCKET) {
    }

    SocketServerWin::~SocketServerWin() {
        if (server_socket_ != INVALID_SOCKET) {
            closesocket(server_socket_);
        }
        if (accept_socket_ != INVALID_SOCKET) {
            closesocket(accept_socket_);
        }
    }

    bool SocketServerWin::wait(const std::string& ip, uint16_t port) {
        if (!is_initialized_) {
            LOG(Log::ERR) << "Winsock.dll is not initialized!";
            return false;
        }

        if (server_socket_ != INVALID_SOCKET) {
            LOG(Log::ERR) << "This server socket is already created!";
            return false;
        }

        server_socket_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_socket_ == INVALID_SOCKET) {
            LOG(Log::ERR) << "Failed to create socket: " << WSAGetLastError();
            return false;
        }

        ULONG addr_bin = 0;
        if (InetPtonA(AF_INET, ip.c_str(), &addr_bin) != 1) {
            LOG(Log::ERR) << "Failed to convert ip addr: " << WSAGetLastError();
        }

        sockaddr_in addr = { 0 };
        addr.sin_family = AF_INET;
        addr.sin_addr.S_un.S_addr = addr_bin;
        addr.sin_port = htons(port);

        if (::bind(server_socket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            LOG(Log::ERR) << "Failed to bind: " << WSAGetLastError();
            return false;
        }

        if (::listen(server_socket_, SOMAXCONN) == SOCKET_ERROR) {
            LOG(Log::ERR) << "Failed to listen: " << WSAGetLastError();
            return false;
        }

        accept_socket_ = ::accept(server_socket_, nullptr, nullptr);
        if (accept_socket_ == INVALID_SOCKET) {
            LOG(Log::ERR) << "Failed to accept: " << WSAGetLastError();
            return false;
        }
        return true;
    }

    bool SocketServerWin::recv(std::string* buf) {
        if (accept_socket_ == INVALID_SOCKET) {
            LOG(Log::ERR) << "Invalid accept socket!";
            return false;
        }

        char recv_buf[512];
        std::string response;

        int bytes_revd = ::recv(accept_socket_, recv_buf, 512, 0);
        if (bytes_revd > 0) {
            response.append(recv_buf, bytes_revd);
        } else if (bytes_revd == 0) {
            LOG(Log::INFO) << "Connection closed";
            return false;
        } else {
            LOG(Log::ERR) << "Failed to recv: " << WSAGetLastError();
            return false;
        }

        *buf = std::move(response);
        return true;
    }

}
}