// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_SECURITY_CERT_X509_H_
#define AKASH_SECURITY_CERT_X509_H_

#include <cstdint>
#include <string>

#include "asn1_reader.h"


namespace akash {
namespace cert {
namespace x509 {

    enum class Version : uint8_t {
        V1 = 0,
        V2 = 1,
        V3 = 2,
    };

    struct Time {
        bool is_utc;
        std::string utc_time;
        std::string general_time;
    };

    struct AttributeTypeAndValue {
        ASN1Reader::ObjectID type;
        std::string value;
        ASN1Reader::UniversalTags val_type;
    };

    using RDN = std::vector<AttributeTypeAndValue>;

    struct Name {
        std::vector<RDN> rdn_sequence;
    };

    struct AlgorithmIdentifier {
        ASN1Reader::ObjectID algorithm;
        std::string parameters;
    };

    struct Validity {
        Time not_before;
        Time not_after;
    };

    struct SubjectPublicKeyInfo {
        AlgorithmIdentifier algorithm;
        std::string subject_public_key;
        // subject_public_key 未使用的位数
        uint8_t spk_unused;
    };

    struct Extension {
        ASN1Reader::ObjectID extn_id;
        bool critical = false;
        std::string extn_value;
    };

    struct TBSCertificate {
        Version version = Version::V1;
        std::string serial_number;
        AlgorithmIdentifier signature;
        Name issuer;
        Validity validity;
        Name subject;
        SubjectPublicKeyInfo subject_public_key_info;
        std::string issuer_unique_id;
        // issuer_unique_id 未使用的位数
        uint8_t iui_unused;
        std::string subject_unique_id;
        // subject_unique_id 未使用的位数
        uint8_t sui_unused;
        std::vector<Extension> extensions;
    };

    struct Certificate {
        TBSCertificate tbs_certificate;
        AlgorithmIdentifier signature_algorithm;
        std::string signature_value;
        // signature_value 未使用的位数
        uint8_t sv_unused;
    };

}
}
}

#endif  // AKASH_SECURITY_CERT_X509_H_
