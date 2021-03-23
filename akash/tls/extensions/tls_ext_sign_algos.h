// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_TLS_EXTENSIONS_TLS_EXT_SIGN_ALGOS_H_
#define AKASH_TLS_EXTENSIONS_TLS_EXT_SIGN_ALGOS_H_

#include "tls_ext.h"


namespace akash {
namespace tls {
namespace ext {

    class SignatureAlgorithms {
    public:
        static bool write(std::ostream& s);
        static bool parse(std::istream& s);
    };

}
}
}

#endif  // AKASH_TLS_EXTENSIONS_TLS_EXT_SIGN_ALGOS_H_