// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/security/cert/cert_path_validator.h"

#include <cassert>
#include <filesystem>
#include <fstream>

#include <Windows.h>
#include <Wincrypt.h>
#pragma comment(lib, "crypt32.lib")

#include "utils/log.h"
#include "utils/string_utils.h"

#include "akash/ldap/ldap_matcher.h"
#include "akash/security/cert/x509_parser.h"


namespace akash {
namespace cert {

    bool CertPathValidator::validate() {
        std::error_code ec;
        std::filesystem::path root_path(u"D:\\");
        std::vector<x509::Certificate> certs;
        for (auto& f : std::filesystem::directory_iterator(root_path, ec)) {
            if (f.is_directory(ec)) {
                continue;
            }
            if (f.path().extension().u16string() != u".cert") {
                continue;
            }
            if (!utl::ascii::startWith(f.path().filename().u16string(), u"X509-")) {
                continue;
            }

            std::ifstream file(f.path(), std::ios::binary);
            if (file) {
                x509::X509Parser x509;
                x509::Certificate cert;
                if (x509.parse(file, &cert)) {
                    certs.push_back(std::move(cert));
                } else {
                    assert(false);
                }
            } else {
                assert(false);
            }
        }

        std::list<x509::Certificate> path;
        getProspectivePath(certs, &path);

        x509::Certificate root;
        if (!findRootCert(path, &root)) {
            return false;
        }

        return true;
    }

    void CertPathValidator::getProspectivePath(
        const std::vector<x509::Certificate>& in, std::list<x509::Certificate>* out)
    {
        auto certs = in;

        if (!certs.empty()) {
            out->push_back(std::move(certs.back()));
            certs.pop_back();
        }

        for (;;) {
            bool hit = false;
            for (auto it = certs.begin(); it != certs.end(); ++it) {
                if (isDNEqual(
                    out->front().tbs_certificate.issuer,
                    it->tbs_certificate.subject))
                {
                    hit = true;
                    out->push_front(std::move(*it));
                    certs.erase(it);
                    break;
                }
            }
            if (!hit) {
                break;
            }
        }

        for (;;) {
            bool hit = false;
            for (auto it = certs.begin(); it != certs.end(); ++it) {
                if (isDNEqual(
                    out->back().tbs_certificate.subject,
                    it->tbs_certificate.issuer))
                {
                    hit = true;
                    out->push_back(std::move(*it));
                    certs.erase(it);
                    break;
                }
            }
            if (!hit) {
                break;
            }
        }
    }

    bool CertPathValidator::findRootCert(
        const std::list<x509::Certificate>& prosp, x509::Certificate* root)
    {
        HCERTSTORE store = ::CertOpenSystemStoreW(NULL, L"ROOT");
        if (!store) {
            LOG(Log::ERR) << "Failed to open sys CA cert store: " << ::GetLastError();
            return false;
        }

        bool found = false;
        PCCERT_CONTEXT context = nullptr;
        for (;;) {
            context = ::CertEnumCertificatesInStore(store, context);
            if (!context) {
                break;
            }

            auto& subject = context->pCertInfo->Subject;
            std::string raw(reinterpret_cast<char*>(subject.pbData), subject.cbData);
            std::istringstream iss(raw, std::ios::binary);

            x509::Name name;
            ASN1Reader name_reader(iss);
            if (x509::X509Parser::parseName(name_reader, &name)) {
                if (isDNEqual(name, prosp.front().tbs_certificate.issuer)) {
                    assert(context->dwCertEncodingType == X509_ASN_ENCODING);
                    std::string root_raw(
                        reinterpret_cast<char*>(context->pbCertEncoded), context->cbCertEncoded);
                    std::istringstream root_iss(root_raw, std::ios::binary);

                    x509::X509Parser x509;
                    x509::Certificate cert;
                    if (x509.parse(root_iss, &cert)) {
                        found = true;
                        *root = std::move(cert);
                    }
                }
            }
        }

        if (::CertCloseStore(store, 0) == FALSE) {
            LOG(Log::WARNING) << "Failed to close sys CA cert store: " << ::GetLastError();
        }

        return found;
    }

    bool CertPathValidator::isDNEqual(const x509::Name& dn1, const x509::Name& dn2) {
        if (dn1.rdn_sequence.size() != dn2.rdn_sequence.size()) {
            return false;
        }

        for (size_t i = 0; i < dn1.rdn_sequence.size(); ++i) {
            if (!isRDNEqual(dn1.rdn_sequence[i], dn2.rdn_sequence[i])) {
                return false;
            }
        }
        return true;
    }

    bool CertPathValidator::isRDNEqual(const x509::RDN& rdn1, const x509::RDN& rdn2) {
        if (rdn1.size() != rdn2.size()) {
            return false;
        }

        auto t1 = rdn1;
        auto t2 = rdn2;

        ldap::LDAPMatcher ldap_matcher;
        for (auto it1 = t1.begin(); it1 != t1.end();) {
            bool hit = false;
            for (auto it2 = t2.begin(); it2 != t2.end();) {
                assert(
                    it1->val_type == ASN1Reader::UniversalTags::UTF8String ||
                    it1->val_type == ASN1Reader::UniversalTags::PrintableString ||
                    it1->val_type == ASN1Reader::UniversalTags::IA5String);
                assert(
                    it2->val_type == ASN1Reader::UniversalTags::UTF8String ||
                    it2->val_type == ASN1Reader::UniversalTags::PrintableString ||
                    it2->val_type == ASN1Reader::UniversalTags::IA5String);

                if (it1->type == it2->type &&
                    ldap_matcher.caseIgnoreMatch(it1->value, it2->value))
                {
                    hit = true;
                    it1 = t1.erase(it1);
                    it2 = t2.erase(it2);
                    break;
                }
            }

            if (!hit) {
                return false;
            }
        }

        return t1.empty() && t2.empty();
    }

}
}