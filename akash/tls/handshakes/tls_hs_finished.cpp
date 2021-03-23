// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/tls/handshakes/tls_hs_finished.h"

#include "utils/stream_utils.h"

#include "akash/security/digest/sha.h"
#include "akash/tls/tls_key_schedule.h"


namespace akash {
namespace tls {

    bool HSFinished::parse(
        std::istream& s,
        const std::string& context,
        const std::string& base_key)
    {
        std::string verify_data(32, 0);
        READ_STREAM(*verify_data.begin(), 32);

        std::string finished_key;
        if (!KeySchedule::HKDFExpandLabel(
            reinterpret_cast<const uint8_t*>(base_key.data()), base_key.length(),
            "finished", "", 32, &finished_key))
        {
            return false;
        }

        uint8_t hash[32];
        digest::SHA256 sha256;
        sha256.init();
        int ret = sha256.update(
            reinterpret_cast<const uint8_t*>(context.data()), context.length());
        if (ret != digest::SHAResult::shaSuccess) {
            return false;
        }
        ret = sha256.result(hash);
        if (ret != digest::SHAResult::shaSuccess) {
            return false;
        }

        uint8_t result_vd[32];
        ret = digest::HMAC::calculate(
            digest::SHAVersion::SHA256, hash, 32,
            reinterpret_cast<const uint8_t*>(finished_key.data()), finished_key.length(),
            result_vd);
        if (ret != digest::SHAResult::shaSuccess) {
            return false;
        }

        if (std::memcmp(verify_data.data(), result_vd, 32) != 0) {
            return false;
        }
        return true;
    }

}
}