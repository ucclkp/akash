// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/tls/extensions/tls_ext_sp_vers.h"

#include "utils/stream_utils.h"

#include "akash/tls/tls_common.h"
#include "akash/tls/extensions/tls_ext.h"


namespace akash {
namespace tls {
namespace ext {

    bool SupportedVersions::write(std::ostream& s) {
        WRITE_STREAM_BE(enum_cast(ExtensionType::SupportedVersions), 2);
        BEGIN_WRB16(0);

        PUT_STREAM(2);
        {
            PUT_STREAM(0x03);
            PUT_STREAM(0x04);
        }

        END_WRB16(0);
        return true;
    }

    bool SupportedVersions::parse(std::istream& s, ProtocolVersion* ver) {
        READ_STREAM(ver->major, 1);
        READ_STREAM(ver->minor, 1);
        return true;
    }

}
}
}