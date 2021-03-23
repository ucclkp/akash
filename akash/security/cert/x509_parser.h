// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_SECURITY_CERT_X509_PARSER_H_
#define AKASH_SECURITY_CERT_X509_PARSER_H_

#include "akash/security/cert/x509.h"


namespace akash {
namespace cert {
namespace x509 {

    // RFC 8446
    // https://tools.ietf.org/html/rfc5280
    // https://docs.microsoft.com/zh-cn/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain
    // https://www.itu.int/rec/T-REC-X/en
    class X509Parser {
    public:
        X509Parser();

        bool parse(std::istream& s, Certificate* out);

        static bool parseName(ASN1Reader& reader, Name* out);

    private:
        bool parseTBSCertificate(ASN1Reader& reader, TBSCertificate* out);
        bool parseAlgorithmIdentifier(ASN1Reader& reader, AlgorithmIdentifier* out);
    };

}
}
}

#endif  // AKASH_SECURITY_CERT_X509_PARSER_H_
