// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_TLS_TLS_H_
#define AKASH_TLS_TLS_H_

#include <string>

#include "akash/security/big_integer/big_integer.h"
#include "akash/tls/tls_common.h"
#include "akash/tls/tls_record_layer.h"


namespace akash {
namespace tls {

    // 根据 RFC 8446 实现的 TLS 1.3 客户端
    // https://tools.ietf.org/html/rfc8446
    class TLS {
    public:
        TLS();
        ~TLS();

        void testHandshake();

    private:
        bool parseFragment(const TLSRecordLayer::TLSPlaintext& text);

        bool writeHandshake(HandshakeType type, std::ostream& s);
        bool parseHandshake(std::istream& s, const std::string& fragment);

        // Section 7.1
        bool generateServerWriteKey();

        std::string host_;
        TLSRecordLayer record_layer_;
        bool finished_ = false;

        // handshake context
        std::string client_hello_data_;
        std::string server_hello_data_;
        std::string encrypted_exts_data_;
        std::string certificate_data_;
        std::string certificate_verify_data_;

        KeyShareClientHello key_share_;
        utl::BigInteger x25519_K_;
        utl::BigInteger x25519_P_;
        std::string share_K_;
        std::string server_handshake_traffic_secret_;
        CipherSuite selected_cs_;
    };


}
}

#endif  // AKASH_TLS_TLS_H_