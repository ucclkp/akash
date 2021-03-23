// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_SOCKET_WIN_SOCKET_WIN_H_
#define AKASH_SOCKET_WIN_SOCKET_WIN_H_

#include <winsock2.h>

#include "akash/socket/socket.h"


namespace akash {
namespace win {

    class SocketClientWin : public SocketClient {
    public:
        SocketClientWin();
        ~SocketClientWin();

        bool connect(const std::string& ip, uint16_t port) override;
        bool connectByHost(const std::string& host, uint16_t port) override;
        bool send(const std::string& buf) override;
        bool recv(int length, std::string* buf) override;
        bool recv(std::string* buf) override;

        bool shutdown() override;
        void close() override;

    private:
        enum class WaitType {
            SEND,
            RECV,
        };

        bool wait(WaitType type, int timeout_sec = -1);

        SOCKET socket_;
    };

    class SocketServerWin : public SocketServer {
    public:
        SocketServerWin();
        ~SocketServerWin();

        bool wait(const std::string& ip, uint16_t port) override;
        bool recv(std::string* buf) override;

    private:
        SOCKET server_socket_;
        SOCKET accept_socket_;
    };

    void initializeSocket();
    void unInitializeSocket();
    bool isSocketInitialized();

}
}

#endif  // AKASH_SOCKET_WIN_SOCKET_WIN_H_