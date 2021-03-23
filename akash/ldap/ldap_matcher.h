// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_LDAP_LDAP_MATCHER_H_
#define AKASH_LDAP_LDAP_MATCHER_H_

#include <string>


namespace akash {
namespace ldap {

    class LDAPMatcher {
    public:
        /**
         * RFC 4517 4.2.11
         * https://tools.ietf.org/html/rfc4517
         */
        int caseIgnoreMatch(
            const std::string& attr_val1,
            const std::string& attr_val2);

        /**
         * RFC 4518
         * https://tools.ietf.org/html/rfc4518
         *
         * 当前只支持 UTF8String 和 PrintableString
         */
        bool prepareString(const std::string& org, std::string* out);

    private:
        /**
         * RFC 3454 B.2
         * https://tools.ietf.org/html/rfc3454
         */
        void caseFoldingWithNFKC(uint32_t val, uint32_t out[4], uint8_t* count);

        bool isUnassignedCodePoint(uint32_t val);
        bool isProhibited(uint32_t val);
        void insignificantSpaceHandling(std::u32string* str);
    };

}
}

#endif  // AKASH_LDAP_LDAP_MATCHER_H_