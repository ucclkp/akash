// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/tls/handshakes/tls_hs_client_hello.h"

#include <random>

#include "utils/stream_utils.h"

#include "akash/tls/extensions/tls_ext_server_name.h"
#include "akash/tls/extensions/tls_ext_sp_vers.h"
#include "akash/tls/extensions/tls_ext_sp_groups.h"
#include "akash/tls/extensions/tls_ext_sign_algos.h"
#include "akash/tls/extensions/tls_ext_key_share.h"


namespace akash {
namespace tls {

    bool HSClientHello::write(const std::string& host, std::ostream& s) {
        // client_version
        PUT_STREAM(3); // major
        PUT_STREAM(3); // minor

        // random
        if (!writeRandomBytes(32, s)) {
            return false;
        }

        // session_id
        PUT_STREAM(32);
        if (!writeRandomBytes(32, s)) {
            return false;
        }

        // cipher_suites
        // 在 9.1 节中规定了必须支持的加密套件
        if (!writeSupportCipherSuites({
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_AES_128_CCM_SHA256,
            CipherSuite::TLS_AES_128_CCM_8_SHA256,
            // https://tools.ietf.org/html/rfc5246
            // TLS 1.2 需要该套件，见第 9 节
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256 }, s))
        {
            return false;
        }

        // compression_methods
        if (!writeSupportCompressionMethods(s)) {
            return false;
        }

        // extensions
        if (!writeSupportExtensions(host, s)) {
            return false;
        }

        return true;
    }

    bool HSClientHello::writeRandomBytes(uint32_t size, std::ostream& s) {
        std::random_device rd;
        std::default_random_engine en(rd());
        std::uniform_int_distribution<int> user_dist(0, 255);

        for (uint32_t i = 0; i < size; ++i) {
            PUT_STREAM(user_dist(en));
        }
        return true;
    }

    bool HSClientHello::writeSupportCipherSuites(
        const std::vector<CipherSuite>& suites, std::ostream& s)
    {
        auto size = UIntToUInt16(std::max(suites.size() * 2, size_t(2)));
        WRITE_STREAM_BE(size, 2);

        struct Data {
            uint8_t cs0;
            uint8_t cs1;
        } data;

        for (const auto& suite : suites) {
            switch (suite) {
            case CipherSuite::TLS_NULL_WITH_NULL_NULL:             data = { 0x00, 0x00 }; break;
            case CipherSuite::TLS_RSA_WITH_NULL_MD5:               data = { 0x00, 0x01 }; break;
            case CipherSuite::TLS_RSA_WITH_NULL_SHA:               data = { 0x00, 0x02 }; break;
            case CipherSuite::TLS_RSA_WITH_NULL_SHA256:            data = { 0x00, 0x3B }; break;
            case CipherSuite::TLS_RSA_WITH_RC4_128_MD5:            data = { 0x00, 0x04 }; break;
            case CipherSuite::TLS_RSA_WITH_RC4_128_SHA:            data = { 0x00, 0x05 }; break;
            case CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA:       data = { 0x00, 0x0A }; break;
            case CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA:        data = { 0x00, 0x2F }; break;
            case CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA:        data = { 0x00, 0x35 }; break;
            case CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256:     data = { 0x00, 0x3C }; break;
            case CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256:     data = { 0x00, 0x3D }; break;
            case CipherSuite::TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:    data = { 0x00, 0x0D }; break;
            case CipherSuite::TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:    data = { 0x00, 0x10 }; break;
            case CipherSuite::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:   data = { 0x00, 0x13 }; break;
            case CipherSuite::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:   data = { 0x00, 0x16 }; break;
            case CipherSuite::TLS_DH_DSS_WITH_AES_128_CBC_SHA:     data = { 0x00, 0x30 }; break;
            case CipherSuite::TLS_DH_RSA_WITH_AES_128_CBC_SHA:     data = { 0x00, 0x31 }; break;
            case CipherSuite::TLS_DHE_DSS_WITH_AES_128_CBC_SHA:    data = { 0x00, 0x32 }; break;
            case CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA:    data = { 0x00, 0x33 }; break;
            case CipherSuite::TLS_DH_DSS_WITH_AES_256_CBC_SHA:     data = { 0x00, 0x36 }; break;
            case CipherSuite::TLS_DH_RSA_WITH_AES_256_CBC_SHA:     data = { 0x00, 0x37 }; break;
            case CipherSuite::TLS_DHE_DSS_WITH_AES_256_CBC_SHA:    data = { 0x00, 0x38 }; break;
            case CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA:    data = { 0x00, 0x39 }; break;
            case CipherSuite::TLS_DH_DSS_WITH_AES_128_CBC_SHA256:  data = { 0x00, 0x3E }; break;
            case CipherSuite::TLS_DH_RSA_WITH_AES_128_CBC_SHA256:  data = { 0x00, 0x3F }; break;
            case CipherSuite::TLS_DHE_DSS_WITH_AES_128_CBC_SHA256: data = { 0x00, 0x40 }; break;
            case CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: data = { 0x00, 0x67 }; break;
            case CipherSuite::TLS_DH_DSS_WITH_AES_256_CBC_SHA256:  data = { 0x00, 0x68 }; break;
            case CipherSuite::TLS_DH_RSA_WITH_AES_256_CBC_SHA256:  data = { 0x00, 0x69 }; break;
            case CipherSuite::TLS_DHE_DSS_WITH_AES_256_CBC_SHA256: data = { 0x00, 0x6A }; break;
            case CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: data = { 0x00, 0x6B }; break;
            case CipherSuite::TLS_DH_anon_WITH_RC4_128_MD5:        data = { 0x00, 0x18 }; break;
            case CipherSuite::TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:   data = { 0x00, 0x1B }; break;
            case CipherSuite::TLS_DH_anon_WITH_AES_128_CBC_SHA:    data = { 0x00, 0x34 }; break;
            case CipherSuite::TLS_DH_anon_WITH_AES_256_CBC_SHA:    data = { 0x00, 0x3A }; break;
            case CipherSuite::TLS_DH_anon_WITH_AES_128_CBC_SHA256: data = { 0x00, 0x6C }; break;
            case CipherSuite::TLS_DH_anon_WITH_AES_256_CBC_SHA256: data = { 0x00, 0x6D }; break;

            case CipherSuite::TLS_AES_128_GCM_SHA256:              data = { 0x13, 0x01 }; break;
            case CipherSuite::TLS_AES_256_GCM_SHA384:              data = { 0x13, 0x02 }; break;
            case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:        data = { 0x13, 0x03 }; break;
            case CipherSuite::TLS_AES_128_CCM_SHA256:              data = { 0x13, 0x04 }; break;
            case CipherSuite::TLS_AES_128_CCM_8_SHA256:            data = { 0x13, 0x05 }; break;
            default: return false;
            }

            PUT_STREAM(data.cs0);
            PUT_STREAM(data.cs1);
        }

        if (suites.empty()) {
            PUT_STREAM(0);
            PUT_STREAM(0);
        }
        return true;
    }

    bool HSClientHello::writeSupportCompressionMethods(std::ostream& s) {
        PUT_STREAM(1);  // 长度
        PUT_STREAM(0);
        return true;
    }

    bool HSClientHello::writeSupportExtensions(const std::string& host, std::ostream& s) {
        // 9.2 节中规定了必须支持的扩展
        uint16_t len = 0;
        WRITE_STREAM(len, 2);
        auto start_p = s.tellp();

        // ServerName
        if (!ext::ServerName::write(s, host)) {
            return false;
        }

        // SupportedVersions
        if (!ext::SupportedVersions::write(s)) {
            return false;
        }

        // SupportedGroups
        if (!ext::SupportedGroups::write(s)) {
            return false;
        }

        // SignatureAlgorithms
        if (!ext::SignatureAlgorithms::write(s)) {
            return false;
        }

        // KeyShare
        ext::KeyShare::Data ks_data;
        if (!ext::KeyShare::write(s, &ks_data)) {
            return false;
        }

        x25519_K_ = std::move(ks_data.x25519_K);
        x25519_P_ = std::move(ks_data.x25519_P);

        auto end_p = s.tellp();
        len = IntToUInt16(end_p - start_p);
        SEEKP_STREAM(start_p - std::streamoff(2));
        WRITE_STREAM_BE(len, 2);
        SEEKP_STREAM(end_p);

        return true;
    }

}
}