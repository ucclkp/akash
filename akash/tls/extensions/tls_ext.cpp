// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/tls/extensions/tls_ext.h"

#include "utils/stream_utils.h"


namespace akash {
namespace tls {
namespace ext {

    bool Extension::preWrb16(
        std::ostream::pos_type* sp,
        std::ostream& s)
    {
        uint16_t len = 0;
        WRITE_STREAM(len, 2);
        *sp = s.tellp();
        return true;
    }

    bool Extension::postWrb16(
        std::ostream::pos_type sp,
        std::ostream& s)
    {
        auto end_p = s.tellp();
        uint16_t len = IntToUInt16(end_p - sp);
        SEEKP_STREAM(sp - std::streamoff(2));
        WRITE_STREAM_BE(len, 2);
        SEEKP_STREAM(end_p);
        return true;
    }

    bool Extension::parse(std::istream& s, Data* d) {
        uint16_t type;
        READ_STREAM_BE(type, 2);
        d->type = ExtensionType(type);

        READ_STREAM_BE(d->length, 2);
        return true;
    }

}
}
}