// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_TLS_EXTENSIONS_TLS_EXT_H_
#define AKASH_TLS_EXTENSIONS_TLS_EXT_H_

#include <ostream>

#include "akash/tls/tls_common.h"

#define BEGIN_WRB16(no)  \
    std::ostream::pos_type start_position_##no;  \
    if (!Extension::preWrb16(&start_position_##no, s)) return false;

#define END_WRB16(no)  \
    if (!Extension::postWrb16(start_position_##no, s)) return false;


namespace akash {
namespace tls {
namespace ext {

    class Extension {
    public:
        static bool preWrb16(
            std::ostream::pos_type* sp, std::ostream& s);
        static bool postWrb16(
            std::ostream::pos_type sp, std::ostream& s);

        struct Data {
            ExtensionType type;
            uint16_t length;
        };

        static bool parse(std::istream& s, Data* d);
    };

}
}
}

#endif  // AKASH_TLS_EXTENSIONS_TLS_EXT_H_