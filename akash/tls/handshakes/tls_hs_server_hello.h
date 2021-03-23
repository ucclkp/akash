// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_TLS_HANDSHAKES_TLS_HS_SERVER_HELLO_H_
#define AKASH_TLS_HANDSHAKES_TLS_HS_SERVER_HELLO_H_

#include <istream>

#include "akash/security/big_integer/big_integer.h"
#include "akash/tls/tls_common.h"


namespace akash {
namespace tls {

    class HSServerHello {
    public:
        bool parse(std::istream& s);

    private:
        bool parsePlainExtensions(std::istream& s);

    public:
        ProtocolVersion legacy_ver;
        uint8_t random[32];
        std::string legacy_session_id_echo;
        CipherSuite cipher_suite;
        uint8_t legacy_compression_method;

        //
        std::string share_K_;
        utl::BigInteger x25519_P_, x25519_K_;
    };

}
}

#endif  // AKASH_TLS_HANDSHAKES_TLS_HS_SERVER_HELLO_H_