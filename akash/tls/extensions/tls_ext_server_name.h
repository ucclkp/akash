// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_TLS_EXTENSIONS_TLS_EXT_SERVER_NAME_H_
#define AKASH_TLS_EXTENSIONS_TLS_EXT_SERVER_NAME_H_

#include <string>


namespace akash {
namespace tls {
namespace ext {

    class ServerName {
    public:
        static bool write(std::ostream& s, const std::string_view& host);
        static bool parse(std::istream& s);
    };

}
}
}

#endif  // AKASH_TLS_EXTENSIONS_TLS_EXT_SERVER_NAME_H_