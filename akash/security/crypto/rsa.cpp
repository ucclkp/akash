// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/security/crypto/rsa.h"


namespace akash {
namespace crypto {

    utl::BigInteger RSA::getPrime() {
        auto init = utl::BigInteger::fromRandom(1024);
        if (!init.isOdd()) {
            init.add(1);
        }

        while (!isPrime(init)) {
            init.add(2);
        }
        return init;
    }

    bool RSA::isPrime(const utl::BigInteger& bi) {
        return bi.isPrime2(utl::BigInteger::TWO) &&
            bi.isPrime2(utl::BigInteger::fromU32(3));
    }

}
}