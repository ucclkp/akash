// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_TEST_SECURITY_CRYPTO_UNIT_TEST_H_
#define AKASH_TEST_SECURITY_CRYPTO_UNIT_TEST_H_


namespace akash {
namespace test {

    /**
     * 该测试代码来自 FIPS PUB 197
     */
    int TEST_AES();

    int TEST_RSA();

    /**
     * 该测试代码来自 RFC7748
     * https://tools.ietf.org/html/rfc7748
     */
    void TEST_ECDP_X25519();

    /**
     * 该测试代码来自 RFC7748
     * https://tools.ietf.org/html/rfc7748
     */
    void TEST_ECDP_X448();

    /**
     * 该测试代码来自:
     * https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES
     */
    void TEST_AEAD_AES_GCM();

}
}

#endif  // AKASH_TEST_SECURITY_CRYPTO_UNIT_TEST_H_
