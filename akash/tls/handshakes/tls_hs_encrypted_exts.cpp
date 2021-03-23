// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/tls/handshakes/tls_hs_encrypted_exts.h"

#include "utils/stream_utils.h"

#include "akash/tls/extensions/tls_ext.h"
#include "akash/tls/extensions/tls_ext_sp_groups.h"


namespace akash {
namespace tls {

    bool HSEncryptedExtensions::parse(std::istream& s) {
        uint16_t length;
        READ_STREAM_BE(length, 2);

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
            case ExtensionType::ServerName:
            {
                // data 可能是空的
                // RFC 6066 Section 3
                // https://tools.ietf.org/html/rfc6066
                SKIP_BYTES(data.length);
                break;
            }

            case ExtensionType::SupportedGroups:
            {
                std::vector<NamedGroup> grps;
                if (!ext::SupportedGroups::parse(s, &grps)) {
                    return false;
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
        return true;
    }

}
}