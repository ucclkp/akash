// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_SECURITY_CERT_CERT_PATH_VALIDATOR_H_
#define AKASH_SECURITY_CERT_CERT_PATH_VALIDATOR_H_

#include <list>

#include "akash/security/cert/x509.h"


namespace akash {
namespace cert {

    class CertPathValidator {
    public:
        bool validate();

    private:
        void getProspectivePath(
            const std::vector<x509::Certificate>& in,
            std::list<x509::Certificate>* out);
        bool findRootCert(
            const std::list<x509::Certificate>& prosp, x509::Certificate* root);

        bool isDNEqual(const x509::Name& dn1, const x509::Name& dn2);
        bool isRDNEqual(const x509::RDN& rdn1, const x509::RDN& rdn2);
    };

}
}

#endif  // AKASH_SECURITY_CERT_CERT_PATH_VALIDATOR_H_