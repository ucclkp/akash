// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_TLS_HANDSHAKES_TLS_HS_H_
#define AKASH_TLS_HANDSHAKES_TLS_HS_H_

#include <istream>

#include "akash/tls/tls_common.h"


namespace akash {
namespace tls {

    class HSHandshake {
    public:
        struct Data {
            HandshakeType type;
            uint32_t length;
        };

        static bool parse(std::istream& s, Data* d);
    };

}
}

#endif  // AKASH_TLS_HANDSHAKES_TLS_HS_H_