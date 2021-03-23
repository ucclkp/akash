// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/tls/handshakes/tls_hs_certificate.h"

#include <string>
#include <fstream>

#include "utils/stream_utils.h"

#include "akash/tls/extensions/tls_ext.h"


namespace akash {
namespace tls {

    bool HSCertificate::parse(std::istream& s) {
        Certificate cert_info;

        uint8_t crc_length;
        READ_STREAM(crc_length, 1);
        if (crc_length > 0) {
            cert_info.certificate_request_context.resize(crc_length);
            READ_STREAM(*cert_info.certificate_request_context.begin(), crc_length);
        }

        uint32_t cl_length;
        READ_STREAM_MLBE(cl_length, 3);
        auto end_p = s.tellg() + std::streamoff(cl_length);

        for (;;) {
            auto cur_p = s.tellg();
            if (cur_p == end_p) {
                break;
            }
            if (cur_p > end_p) {
                return false;
            }

            CertificateEntry entry;
            uint32_t d_len;
            READ_STREAM_MLBE(d_len, 3);
            if (d_len > 0) {
                entry.cert_data.resize(d_len);
                READ_STREAM(*entry.cert_data.begin(), d_len);
            }

            uint16_t e_len;
            READ_STREAM_BE(e_len, 2);
            for (size_t j = 0; j < e_len;) {
                ext::Extension::Data data;
                if (!ext::Extension::parse(s, &data)) {
                    return false;
                }
                SKIP_BYTES(data.length);
            }
            cert_info.certs.push_back(entry);
        }

        // TEST
        int i = 0;
        for (const auto& cert : cert_info.certs) {
            std::string file_name = "D:\\X509-";
            file_name.append(std::to_string(i)).append(".cert");
            std::ofstream file(file_name, std::ios::out | std::ios::binary);
            file.write(reinterpret_cast<const char*>(cert.cert_data.data()), cert.cert_data.size());
            file.flush();
            ++i;
        }

        return true;
    }

}
}