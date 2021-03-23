// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/tls/handshakes/tls_hs.h"

#include "utils/stream_utils.h"


namespace akash {
namespace tls {

    bool HSHandshake::parse(std::istream& s, Data* d) {
        uint8_t type;
        READ_STREAM(type, 1);
        d->type = HandshakeType(type);
        READ_STREAM_MLBE(d->length, 3);
        return true;
    }

}
}