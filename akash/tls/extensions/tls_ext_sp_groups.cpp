// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/tls/extensions/tls_ext_sp_groups.h"

#include "utils/stream_utils.h"

#include "akash/tls/extensions/tls_ext.h"


namespace akash {
namespace tls {
namespace ext {

    bool SupportedGroups::write(std::ostream& s) {
        WRITE_STREAM_BE(enum_cast(ExtensionType::SupportedGroups), 2);
        BEGIN_WRB16(0);

        uint16_t len = 2 * 3;
        WRITE_STREAM_BE(len, 2);
        {
            WRITE_STREAM_BE(uint16_t(NamedGroup::X25519), 2);
            WRITE_STREAM_BE(uint16_t(NamedGroup::SECP384R1), 2);
            WRITE_STREAM_BE(uint16_t(NamedGroup::SECP256R1), 2);
        }

        END_WRB16(0);
        return true;
    }

    bool SupportedGroups::parse(std::istream& s, std::vector<NamedGroup>* grps) {
        uint16_t length;
        READ_STREAM_BE(length, 2);
        for (uint16_t i = 0; i < length; i += 2) {
            uint16_t ng;
            READ_STREAM_BE(ng, 2);
            grps->push_back(NamedGroup(ng));
        }
        return true;
    }

}
}
}