// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/security/cert/x509_oid.h"


namespace akash {
namespace cert {
namespace x509 {
namespace oid {

    ASN1Reader::ObjectID md2;
    ASN1Reader::ObjectID md5;
    ASN1Reader::ObjectID id_sha1;
    ASN1Reader::ObjectID id_sha224;
    ASN1Reader::ObjectID id_sha256;
    ASN1Reader::ObjectID id_sha384;
    ASN1Reader::ObjectID id_sha512;
    ASN1Reader::ObjectID ansi_X9_62;
    ASN1Reader::ObjectID id_ecSigType;
    ASN1Reader::ObjectID pkcs_1;
    ASN1Reader::ObjectID id_public_key_type;
    ASN1Reader::ObjectID id_mgf1;

    ASN1Reader::ObjectID md2WithRSAEncryption;
    ASN1Reader::ObjectID md5WithRSAEncryption;
    ASN1Reader::ObjectID sha1WithRSAEncryption;

    ASN1Reader::ObjectID id_dsa_with_sha1;
    ASN1Reader::ObjectID ecdsa_with_sha1;

    ASN1Reader::ObjectID rsaEncryption;
    ASN1Reader::ObjectID id_dsa;
    ASN1Reader::ObjectID dh_public_number;
    ASN1Reader::ObjectID id_keyExchangeAlgorithm;

    ASN1Reader::ObjectID id_ecPublicKey;
    ASN1Reader::ObjectID id_fieldType;
    ASN1Reader::ObjectID prime_field;
    ASN1Reader::ObjectID characteristic_two_field;
    ASN1Reader::ObjectID id_characteristic_two_basis;
    ASN1Reader::ObjectID gnBasis;
    ASN1Reader::ObjectID tpBasis;
    ASN1Reader::ObjectID ppBasis;

    void initOIDs() {
        uint64_t iso = 1, joint_iso_itu_t = 2;
        uint64_t member_body = 2, identified_organization = 3, country = 16;
        uint64_t us = 840, oiw = 14, organization = 1, gov = 101, csor = 3;
        uint64_t rsadsi = 113549, secsig = 3, x9_57 = 10040, ansi_x942 = 10046;
        uint64_t digestAlgorithm = 2, algorithms = 2, x9cm = 4, signatures = 4, number_type = 2,
            fieldType = 1, basisType = 1, nistalgorithm = 4, hashalgs = 2;
        uint64_t pkcs = 1, pkcs_1_v = 1;

        md2 = { iso * 40 + member_body, us, rsadsi, digestAlgorithm, 2 };
        md5 = { iso * 40 + member_body, us, rsadsi, digestAlgorithm, 5 };
        id_sha1 = { iso * 40 + identified_organization, oiw, secsig, algorithms, 26 };
        id_sha224 = { joint_iso_itu_t * 40 + country, us, organization, gov, csor, nistalgorithm, hashalgs, 4 };
        id_sha256 = { joint_iso_itu_t * 40 + country, us, organization, gov, csor, nistalgorithm, hashalgs, 1 };
        id_sha384 = { joint_iso_itu_t * 40 + country, us, organization, gov, csor, nistalgorithm, hashalgs, 2 };
        id_sha512 = { joint_iso_itu_t * 40 + country, us, organization, gov, csor, nistalgorithm, hashalgs, 3 };

        ansi_X9_62 = { iso * 40 + member_body, us, 10045 };
        id_ecSigType = ansi_X9_62; id_ecSigType.push_back(signatures);
        pkcs_1 = { iso * 40 + member_body, us, rsadsi, pkcs, 1 };
        id_public_key_type = ansi_X9_62; id_public_key_type.push_back(2);
        id_mgf1 = pkcs_1; id_mgf1.push_back(8);

        // RSA Signature Algorithm
        md2WithRSAEncryption = { iso * 40 + member_body, us, rsadsi, pkcs, pkcs_1_v, 2 };
        md5WithRSAEncryption = { iso * 40 + member_body, us, rsadsi, pkcs, pkcs_1_v, 4 };
        sha1WithRSAEncryption = { iso * 40 + member_body, us, rsadsi, pkcs, pkcs_1_v, 5 };

        // DSA Signature Algorithm
        id_dsa_with_sha1 = { iso * 40 + member_body, us, x9_57, x9cm, 3 };

        // ECDSA Signature Algorithm
        ecdsa_with_sha1 = id_ecSigType;
        ecdsa_with_sha1.push_back(1);

        // RSA Keys
        rsaEncryption = pkcs_1;
        rsaEncryption.push_back(1);

        // DSA Signature Keys
        id_dsa = { iso * 40 + member_body, us, x9_57, x9cm, 1 };

        // Diffie-Hellman Key Exchange Keys
        dh_public_number = { iso * 40 + member_body, us, ansi_x942, number_type, 1 };

        // KEA Public Keys
        id_keyExchangeAlgorithm = { 2 * 40 + 16, 840, 1, 101, 2, 1, 1, 22 };

        // ECDSA and ECDH Keys
        id_ecPublicKey = id_public_key_type; id_ecPublicKey.push_back(1);
        id_fieldType = ansi_X9_62; id_fieldType.push_back(fieldType);
        prime_field = id_fieldType; prime_field.push_back(1);
        characteristic_two_field = id_fieldType; characteristic_two_field.push_back(2);
        id_characteristic_two_basis = characteristic_two_field; id_characteristic_two_basis.push_back(basisType);
        gnBasis = id_characteristic_two_basis; gnBasis.push_back(1);
        tpBasis = id_characteristic_two_basis; tpBasis.push_back(2);
        ppBasis = id_characteristic_two_basis; ppBasis.push_back(3);
    }
}
}
}
}