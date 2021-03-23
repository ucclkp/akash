// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/tls/handshakes/tls_hs_server_hello.h"

#include "utils/log.h"
#include "utils/stream_utils.h"

#include "akash/security/crypto/ecdp.h"
#include "akash/tls/extensions/tls_ext.h"
#include "akash/tls/extensions/tls_ext_sp_vers.h"
#include "akash/tls/extensions/tls_ext_key_share.h"


namespace akash {
namespace tls {

    bool HSServerHello::parse(std::istream& s) {
        READ_STREAM(legacy_ver.major, 1);
        READ_STREAM(legacy_ver.minor, 1);

        READ_STREAM(random[0], 32);
        {
            uint8_t hrr_token[] {
                0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
                0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
            };
            if (std::memcmp(random, hrr_token, 32) == 0) {
                DCHECK(false);
                return false;
            }
        }

        {
            uint8_t length;
            READ_STREAM(length, 1);
            legacy_session_id_echo.resize(length);
            READ_STREAM(*legacy_session_id_echo.begin(), length);
        }

        {
            uint8_t cs0, cs1;
            READ_STREAM(cs0, 1);
            READ_STREAM(cs1, 1);
            DCHECK(cs0 == 0x13 && cs1 == 0x01);
        }

        READ_STREAM(legacy_compression_method, 1);

        {
            PEEK_STREAM(char buf);
            if (buf == EOF) {
                DCHECK(false);
                return false;
            }
        }

        return parsePlainExtensions(s);
    }

    bool HSServerHello::parsePlainExtensions(std::istream& s) {
        uint16_t length;
        READ_STREAM_BE(length, 2);
        bool has_sp_ver = false;

        auto end_p = s.tellg() + std::streamoff(length);
        for (;;) {
            auto cur_p = s.tellg();
            if (cur_p == end_p) {
                break;
            }
            if (cur_p > end_p) {
                return false;
            }

            ext::Extension::Data data;
            if (!ext::Extension::parse(s, &data)) {
                return false;
            }

            auto pre_p = s.tellg();

            switch (data.type) {
            case ExtensionType::SupportedVersions:
            {
                ProtocolVersion ver;
                if (!ext::SupportedVersions::parse(s, &ver)) {
                    return false;
                }
                DCHECK(ver.major == 0x03 && ver.minor == 0x04);
                has_sp_ver = true;
                break;
            }

            case ExtensionType::KeyShare:
            {
                ext::KeyShareEntry entry;
                if (!ext::KeyShare::parseSH(s, &entry)) {
                    return false;
                }
                DCHECK(entry.group == NamedGroup::X25519);
                if (entry.group == NamedGroup::X25519) {
                    std::string U_bytes;
                    if (!ext::KeyShareEntry::parseX25519(s, &U_bytes)) {
                        return false;
                    }

                    utl::BigInteger share_K;
                    auto U = utl::BigInteger::fromBytesLE(U_bytes);
                    U.setBit(255, 0);
                    crypto::ECDP::X25519(x25519_P_, x25519_K_, U, &share_K);

                    share_K_ = share_K.getBytesLE();
                    assert(share_K_.size() == 32);
                }
                break;
            }

            default:
                SKIP_BYTES(data.length);
                break;
            }

            // 一致性检查
            if (s.tellg() - pre_p != data.length) {
                return false;
            }
        }

        DCHECK(has_sp_ver);
        return true;
    }

}
}
