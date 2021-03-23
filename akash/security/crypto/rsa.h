// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_SECURITY_CRYPTO_RSA_H_
#define AKASH_SECURITY_CRYPTO_RSA_H_

#include "akash/security/big_integer/big_integer.h"


namespace akash {
namespace crypto {

    // 根据 RFC 8017 实现的 RSA 算法。
    // https://tools.ietf.org/html/rfc8017
    class RSA {
    public:
        RSA() = default;

        static utl::BigInteger getPrime();
        static bool isPrime(const utl::BigInteger& bi);
    };

}
}

#endif  // AKASH_SECURITY_CRYPTO_RSA_H_
