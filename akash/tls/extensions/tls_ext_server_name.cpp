// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/tls/extensions/tls_ext_server_name.h"

#include "utils/stream_utils.h"

#include "akash/tls/tls_common.h"
#include "akash/tls/extensions/tls_ext.h"


namespace akash {
namespace tls {
namespace ext {

    bool ServerName::write(std::ostream& s, const std::string_view& host) {
        WRITE_STREAM_BE(enum_cast(ExtensionType::ServerName), 2);
        BEGIN_WRB16(0);

        uint16_t len = 1 + 2 + UIntToUInt16(host.length());
        WRITE_STREAM_BE(len, 2);
        {
            PUT_STREAM(enum_cast(NameType::HostName));
            WRITE_STREAM_BE(UIntToUInt16(host.length()), 2);
            {
                WRITE_STREAM(host.data()[0], host.length());
            }
        }

        END_WRB16(0);
        return true;
    }

    bool ServerName::parse(std::istream& s) {
        return false;
    }

}
}
}