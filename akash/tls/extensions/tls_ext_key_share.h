// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_TLS_EXTENSIONS_TLS_EXT_KEY_SHARE_H_
#define AKASH_TLS_EXTENSIONS_TLS_EXT_KEY_SHARE_H_

#include <istream>

#include "akash/security/big_integer/big_integer.h"
#include "akash/tls/tls_common.h"


namespace akash {
namespace tls {
namespace ext {

    class KeyShareEntry;

    class KeyShare {
    public:
        struct Data {
            utl::BigInteger x25519_K;
            utl::BigInteger x25519_P;
        };

        static bool write(std::ostream& s, Data* out);
        static bool parseSH(std::istream& s, KeyShareEntry* entry);
    };


    class KeyShareEntry {
    public:
        static bool parseX25519(std::istream& s, std::string* U);

        NamedGroup group;
    };

}
}
}

#endif  // AKASH_TLS_EXTENSIONS_TLS_EXT_KEY_SHARE_H_