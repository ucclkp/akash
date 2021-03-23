// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_SECURITY_CRYPTO_ECDP_H_
#define AKASH_SECURITY_CRYPTO_ECDP_H_

#include "akash/security/big_integer/big_integer.h"


namespace akash {
namespace crypto {

    // SEC 1: Elliptic Curve Cryptography
    // SEC 2: Recommended Elliptic Curve Domain Parameters
    // https://tools.ietf.org/html/rfc7748
    class ECDP {
    public:
        // Curve: y^2 = x^3 + ax + b
        static void secp192k1(
            utl::BigInteger* p,
            utl::BigInteger* a, utl::BigInteger* b,
            utl::BigInteger* Gx, utl::BigInteger* Gy, utl::BigInteger* n, uint8_t* h);

        static void secp192r1(
            utl::BigInteger* p,
            utl::BigInteger* a, utl::BigInteger* b, utl::BigInteger* S,
            utl::BigInteger* Gx, utl::BigInteger* Gy, utl::BigInteger* n, uint8_t* h);

        static void secp224k1(
            utl::BigInteger* p,
            utl::BigInteger* a, utl::BigInteger* b,
            utl::BigInteger* Gx, utl::BigInteger* Gy, utl::BigInteger* n, uint8_t* h);

        static void secp224r1(
            utl::BigInteger* p,
            utl::BigInteger* a, utl::BigInteger* b, utl::BigInteger* S,
            utl::BigInteger* Gx, utl::BigInteger* Gy, utl::BigInteger* n, uint8_t* h);

        static void secp256k1(
            utl::BigInteger* p,
            utl::BigInteger* a, utl::BigInteger* b,
            utl::BigInteger* Gx, utl::BigInteger* Gy, utl::BigInteger* n, uint8_t* h);

        static void secp256r1(
            utl::BigInteger* p,
            utl::BigInteger* a, utl::BigInteger* b, utl::BigInteger* S,
            utl::BigInteger* Gx, utl::BigInteger* Gy, utl::BigInteger* n, uint8_t* h);

        static void secp384r1(
            utl::BigInteger* p,
            utl::BigInteger* a, utl::BigInteger* b, utl::BigInteger* S,
            utl::BigInteger* Gx, utl::BigInteger* Gy, utl::BigInteger* n, uint8_t* h);

        static void secp521r1(
            utl::BigInteger* p,
            utl::BigInteger* a, utl::BigInteger* b, utl::BigInteger* S,
            utl::BigInteger* Gx, utl::BigInteger* Gy, utl::BigInteger* n, uint8_t* h);

        // v^2 = u^3 + A*u^2 + u
        static void curve25519(
            utl::BigInteger* p,
            uint32_t* A, utl::BigInteger* order, uint8_t* cofactor, uint8_t* Up, utl::BigInteger* Vp);

        static void curve448(
            utl::BigInteger* p,
            uint32_t* A, utl::BigInteger* order, uint8_t* cofactor, uint8_t* Up, utl::BigInteger* Vp);

        // -x^2 + y^2 = 1 + d * x^2 * y^2
        static void edwards25519(
            utl::BigInteger* p,
            utl::BigInteger* d, utl::BigInteger* order, uint8_t* cofactor, utl::BigInteger* Xp, utl::BigInteger* Yp);

        // x^2 + y^2 = 1 + d * x^2 * y^2
        static void edwards448_1(
            utl::BigInteger* p,
            utl::BigInteger* d, utl::BigInteger* order, uint8_t* cofactor, utl::BigInteger* Xp, utl::BigInteger* Yp);

        static void edwards448_2(
            utl::BigInteger* p,
            utl::BigInteger* d, utl::BigInteger* order, uint8_t* cofactor, utl::BigInteger* Xp, utl::BigInteger* Yp);


        // 对于 y^2 = x^3 + ax + b

        // (x2, y2) = (x1, y1) + (x2, y2)
        static void addPoint(
            const utl::BigInteger& p, const utl::BigInteger& a,
            const utl::BigInteger& x1, const utl::BigInteger& y1,
            utl::BigInteger* x2, utl::BigInteger* y2);

        // (x, y) = d * (x, y)
        static void mulPoint(
            const utl::BigInteger& p, const utl::BigInteger& a,
            const utl::BigInteger& d, utl::BigInteger* x, utl::BigInteger* y);

        static bool verifyPoint(
            const utl::BigInteger& p,
            const utl::BigInteger& a, const utl::BigInteger& b,
            const utl::BigInteger& x, const utl::BigInteger& y);

        static void X25519(
            const utl::BigInteger& p, const utl::BigInteger& k, const utl::BigInteger& u,
            utl::BigInteger* result);

        static void X448(
            const utl::BigInteger& p, const utl::BigInteger& k, const utl::BigInteger& u,
            utl::BigInteger* result);

    private:
        // 对于 curve25519/448
        static void X25519_448(
            const utl::BigInteger& p, const utl::BigInteger& k, const utl::BigInteger& u,
            uint32_t a24, utl::BigInteger* result);

        static void cswap(uint8_t swap, utl::BigInteger* x2, utl::BigInteger* x3);
    };

}
}

#endif  // AKASH_SECURITY_CRYPTO_ECDP_H_
