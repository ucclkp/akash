// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_TLS_EXTENSIONS_TLS_EXT_SP_VERS_H_
#define AKASH_TLS_EXTENSIONS_TLS_EXT_SP_VERS_H_

#include "akash/tls/tls_common.h"


namespace akash {
namespace tls {
namespace ext {

    class SupportedVersions {
    public:
        static bool write(std::ostream& s);
        static bool parse(std::istream& s, ProtocolVersion* ver);
    };

}
}
}

#endif  // AKASH_TLS_EXTENSIONS_TLS_EXT_SP_VERS_H_