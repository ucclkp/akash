// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_TLS_TLS_KEY_SCHEDULE_H_
#define AKASH_TLS_TLS_KEY_SCHEDULE_H_

#include <string>


namespace akash {
namespace tls {

    class KeySchedule {
    public:
        struct HKDFLabel {
            uint16_t length;
            std::string label;
            std::string context;
        };

        // Section 7.1
        static bool deriveSecret(
            const uint8_t* secret, size_t ls,
            const std::string& label, const std::string& message, std::string* out);
        static bool HKDFExpandLabel(
            const uint8_t* secret, size_t ls,
            const std::string& label, const std::string& context,
            uint32_t length, std::string* out);
    };

}
}

#endif  // AKASH_TLS_TLS_KEY_SCHEDULE_H_