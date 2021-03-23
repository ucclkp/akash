// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_SOCKET_SOCKET_H_
#define AKASH_SOCKET_SOCKET_H_

#include <string>


namespace akash {

    class SocketClient {
    public:
        static SocketClient* create();

        virtual ~SocketClient() = default;

        virtual bool connect(const std::string& ip, uint16_t port) = 0;
        virtual bool connectByHost(const std::string& host, uint16_t port) = 0;
        virtual bool send(const std::string& buf) = 0;
        virtual bool recv(int length, std::string* buf) = 0;
        virtual bool recv(std::string* buf) = 0;

        virtual bool shutdown() = 0;
        virtual void close() = 0;
    };


    class SocketServer {
    public:
        static SocketServer* create();

        virtual ~SocketServer() = default;

        virtual bool wait(const std::string& ip, uint16_t port) = 0;
        virtual bool recv(std::string* buf) = 0;
    };

    void initializeSocket();
    void unInitializeSocket();
    bool isSocketInitialized();

}

#endif  // AKASH_SOCKET_SOCKET_H_