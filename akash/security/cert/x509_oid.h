// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_SECURITY_CERT_X509_OID_H_
#define AKASH_SECURITY_CERT_X509_OID_H_

#include "asn1_reader.h"


namespace akash {
namespace cert {
namespace x509 {
namespace oid {

    /**
     * X509 Signature Algorithms
     * RFC3279: https://tools.ietf.org/html/rfc3279
     * RFC4055: https://tools.ietf.org/html/rfc4055
     * RFC4491: https://tools.ietf.org/html/rfc4491
     */

    extern ASN1Reader::ObjectID md2;
    extern ASN1Reader::ObjectID md5;
    extern ASN1Reader::ObjectID id_sha1;
    extern ASN1Reader::ObjectID id_sha224;
    extern ASN1Reader::ObjectID id_sha256;
    extern ASN1Reader::ObjectID id_sha384;
    extern ASN1Reader::ObjectID id_sha512;

    extern ASN1Reader::ObjectID ansi_X9_62;
    extern ASN1Reader::ObjectID id_ecSigType;
    extern ASN1Reader::ObjectID pkcs_1;
    extern ASN1Reader::ObjectID id_public_key_type;
    extern ASN1Reader::ObjectID id_mgf1;

    /**********
     * RFC3279
     * Signature Algorithms
     */
     // RSA Signature Algorithm
    extern ASN1Reader::ObjectID md2WithRSAEncryption;
    extern ASN1Reader::ObjectID md5WithRSAEncryption;
    extern ASN1Reader::ObjectID sha1WithRSAEncryption;

    // DSA Signature Algorithm
    extern ASN1Reader::ObjectID id_dsa_with_sha1;

    // ECDSA Signature Algorithm
    extern ASN1Reader::ObjectID ecdsa_with_sha1;

    /**********
     * RFC3279
     * Subject Public Key Algorithms
     */
     // RSA Keys
    extern ASN1Reader::ObjectID rsaEncryption;

    // DSA Signature Keys
    extern ASN1Reader::ObjectID id_dsa;

    // Diffie-Hellman Key Exchange Keys
    extern ASN1Reader::ObjectID dh_public_number;

    // KEA Public Keys
    extern ASN1Reader::ObjectID id_keyExchangeAlgorithm;

    // ECDSA and ECDH Keys
    extern ASN1Reader::ObjectID id_ecPublicKey;
    extern ASN1Reader::ObjectID id_fieldType;
    extern ASN1Reader::ObjectID prime_field;
    extern ASN1Reader::ObjectID characteristic_two_field;
    extern ASN1Reader::ObjectID id_characteristic_two_basis;
    extern ASN1Reader::ObjectID gnBasis;
    extern ASN1Reader::ObjectID tpBasis;
    extern ASN1Reader::ObjectID ppBasis;

    /**********
     * RFC4055
     */

    void initOIDs();

}
}
}
}

#endif  // AKASH_SECURITY_CERT_X509_OID_H_
