// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/socket/socket.h"

#include "akash/socket/win/socket_win.h"


namespace akash {

    SocketClient* SocketClient::create() {
        if (!isSocketInitialized()) {
            initializeSocket();
        }
        return new win::SocketClientWin();
    }

    SocketServer* SocketServer::create() {
        if (!isSocketInitialized()) {
            initializeSocket();
        }
        return new win::SocketServerWin();
    }

    void initializeSocket() {
        win::initializeSocket();
    }

    void unInitializeSocket() {
        win::unInitializeSocket();
    }

    bool isSocketInitialized() {
        return win::isSocketInitialized();
    }
}
