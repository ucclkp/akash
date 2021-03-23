// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/tls/extensions/tls_ext_sign_algos.h"

#include "utils/stream_utils.h"

#include "akash/tls/tls_common.h"


namespace akash {
namespace tls {
namespace ext {

    bool SignatureAlgorithms::write(std::ostream& s) {
        WRITE_STREAM_BE(enum_cast(ExtensionType::SignatureAlgorithms), 2);
        BEGIN_WRB16(0);

        uint16_t len = 2 * 3;
        WRITE_STREAM_BE(len, 2);
        {
            WRITE_STREAM_BE(uint16_t(SignatureScheme::ECDSA_SECP256R1_SHA256), 2);
            WRITE_STREAM_BE(uint16_t(SignatureScheme::RSA_PKCS1_SHA256), 2);
            //WRITE_STREAM_BE(uint16_t(SignatureScheme::RSA_PKCS1_SHA384), 2);
            //WRITE_STREAM_BE(uint16_t(SignatureScheme::RSA_PKCS1_SHA512), 2);
            //WRITE_STREAM_BE(uint16_t(SignatureScheme::RSA_PSS_RSAE_SHA256), 2);
            //WRITE_STREAM_BE(uint16_t(SignatureScheme::RSA_PSS_PSS_SHA512), 2);
            WRITE_STREAM_BE(uint16_t(SignatureScheme::ED25519), 2);
        }

        END_WRB16(0);
        return true;
    }

    bool SignatureAlgorithms::parse(std::istream& s) {
        return false;
    }

}
}
}