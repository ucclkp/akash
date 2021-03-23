// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/tls/tls_key_schedule.h"

#include <sstream>

#include "utils/stream_utils.h"

#include "akash/security/digest/sha.h"


namespace akash {
namespace tls {

    bool KeySchedule::deriveSecret(
        const uint8_t* secret, size_t ls,
        const std::string& label, const std::string& message, std::string* out)
    {
        uint8_t hash_result[32];

        digest::SHA256 sha256;
        sha256.init();
        int ret = sha256.update(
            reinterpret_cast<const uint8_t*>(message.data()), message.size());
        if (ret != digest::shaSuccess) {
            return false;
        }
        ret = sha256.result(hash_result);
        if (ret != digest::shaSuccess) {
            return false;
        }

        return HKDFExpandLabel(
            secret, ls, label,
            std::string(reinterpret_cast<char*>(hash_result), 32), 32, out);
    }

    bool KeySchedule::HKDFExpandLabel(
        const uint8_t* secret, size_t ls,
        const std::string& label, const std::string& context,
        uint32_t length, std::string* out)
    {
        HKDFLabel hkdf_label;
        hkdf_label.length = length;
        hkdf_label.label.append("tls13 ").append(label);
        hkdf_label.context.append(context);

        std::ostringstream s(std::ios::binary);

        WRITE_STREAM_BE(hkdf_label.length, 2);
        PUT_STREAM(uint8_t(hkdf_label.label.size()));
        WRITE_STREAM_STR(hkdf_label.label);
        PUT_STREAM(uint8_t(hkdf_label.context.size()));
        WRITE_STREAM_STR(hkdf_label.context);

        std::string input(s.str());

        uint8_t* okm = new uint8_t[length];
        int result = digest::HKDF::hkdfExpand(
            digest::SHAVersion::SHA256, secret, int(ls),
            reinterpret_cast<const uint8_t*>(input.data()), input.size(),
            okm, length);
        if (result != digest::shaSuccess) {
            delete[] okm;
            return false;
        }

        *out = std::string(reinterpret_cast<char*>(okm), length);
        delete[] okm;
        return true;
    }

}
}
