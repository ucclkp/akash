// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_TLS_HANDSHAKES_TLS_HS_CLIENT_HELLO_H_
#define AKASH_TLS_HANDSHAKES_TLS_HS_CLIENT_HELLO_H_

#include <ostream>

#include "akash/security/big_integer/big_integer.h"
#include "akash/tls/tls_common.h"


namespace akash {
namespace tls {

    class HSClientHello {
    public:
        bool write(const std::string& host, std::ostream& s);

    private:
        bool writeRandomBytes(uint32_t size, std::ostream& s);
        bool writeSupportCipherSuites(const std::vector<CipherSuite>& suites, std::ostream& s);
        bool writeSupportCompressionMethods(std::ostream& s);
        bool writeSupportExtensions(const std::string& host, std::ostream& s);

    public:
        utl::BigInteger x25519_K_;
        utl::BigInteger x25519_P_;
    };

}
}

#endif  // AKASH_TLS_HANDSHAKES_TLS_HS_CLIENT_HELLO_H_