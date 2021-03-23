// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_TLS_HANDSHAKE_TLS_HS_FINISHED_H_
#define AKASH_TLS_HANDSHAKE_TLS_HS_FINISHED_H_

#include <istream>


namespace akash {
namespace tls {

    class HSFinished {
    public:
        bool parse(
            std::istream& s,
            const std::string& context,
            const std::string& base_key);
    };

}
}

#endif  // AKASH_TLS_HANDSHAKE_TLS_HS_FINISHED_H_