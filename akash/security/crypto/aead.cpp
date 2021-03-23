// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "aead.h"

#include <cassert>
#include <cstring>

#include "akash/security/big_integer/byte_string.h"
#include "akash/security/crypto/aes.h"


namespace akash {
namespace crypto {

    void GCM::GCM_AE(
        const uint8_t* K, size_t lk, const uint8_t* IV, size_t l_iv,
        const uint8_t* P, size_t lp, const uint8_t* A, size_t la,
        uint8_t* C, uint8_t* T, size_t t)
    {
        assert(K && lk != 0);
        assert(IV && l_iv != 0);
        assert(P || lp == 0);
        assert(A || la == 0);
        assert(C || !P);
        assert(T && t <= 16);

        assert(l_iv >= kLenIVMin && l_iv <= kLenIVMax);
        assert(lp >= kLenPMin && lp <= kLenPMax);
        assert(la >= kLenAMin && la <= kLenAMax);

        uint8_t H[16];
        uint8_t i_tmp[16];
        std::memset(i_tmp, 0, 16);
        CIPH(K, lk, i_tmp, H);

        uint8_t J0[16];
        if (l_iv == 12) {
            std::memcpy(J0, IV, 12);
            J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;
        } else {
            size_t s = 16 * ((l_iv + 15) / 16) - l_iv;
            size_t lx = l_iv + s + 8 + 8;
            uint8_t* X = new uint8_t[lx];
            auto t_X = X;

            std::memcpy(t_X, IV, l_iv); t_X += l_iv;
            std::memset(t_X, 0, s + 8); t_X += s + 8;
            utl::ByteString::len64(l_iv, t_X);

            GHASH(H, X, lx, J0);

            delete[] X;
        }

        uint8_t J0_1[16];
        std::memcpy(J0_1, J0, 16);
        utl::ByteString::inc(J0_1, 16, 4, J0_1);
        GCTR(K, lk, J0_1, P, lp, C);

        // C 的长度为 lp
        size_t u = 16 * ((lp + 15) / 16) - lp;
        size_t v = 16 * ((la + 15) / 16) - la;

        size_t lx = la + v + lp + u + 8 + 8;
        uint8_t* X = new uint8_t[lx];
        auto t_X = X;
        if (A) { std::memcpy(t_X, A, la); t_X += la; }
        std::memset(t_X, 0, v); t_X += v;
        if (C) { std::memcpy(t_X, C, lp); t_X += lp; }
        std::memset(t_X, 0, u); t_X += u;

        utl::ByteString::len64(la, t_X); t_X += 8;
        utl::ByteString::len64(lp, t_X);

        uint8_t S[16];
        GHASH(H, X, lx, S);

        delete[] X;

        uint8_t tmp[16];
        GCTR(K, lk, J0, S, 16, tmp);
        std::memcpy(T, tmp, t);
    }

    bool GCM::GCM_AD(
        const uint8_t* K, size_t lk, const uint8_t* IV, size_t l_iv,
        const uint8_t* C, size_t lc, const uint8_t* A, size_t la,
        const uint8_t* T, size_t t, uint8_t* P)
    {
        assert(K && lk != 0);
        assert(IV && l_iv != 0);
        assert(C || lc == 0);
        assert(A || la == 0);
        assert(T && t <= 16);
        assert(P || !C);

        assert(l_iv >= kLenIVMin && l_iv <= kLenIVMax);
        assert(la >= kLenAMin && la <= kLenAMax);
        assert(lc >= kLenPMin && lc <= kLenPMax);

        uint8_t H[16];
        uint8_t i_tmp[16];
        std::memset(i_tmp, 0, 16);
        CIPH(K, lk, i_tmp, H);

        uint8_t J0[16];
        if (l_iv == 12) {
            std::memcpy(J0, IV, 12);
            J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;
        } else {
            size_t s = 16 * ((l_iv + 15) / 16) - l_iv;
            size_t lx = l_iv + s + 8 + 8;
            uint8_t* X = new uint8_t[lx];
            auto t_X = X;

            std::memcpy(t_X, IV, l_iv); t_X += l_iv;
            std::memset(t_X, 0, s + 8); t_X += s + 8;

            utl::ByteString::len64(l_iv, t_X);

            GHASH(H, X, lx, J0);

            delete[] X;
        }

        uint8_t J0_1[16];
        std::memcpy(J0_1, J0, 16);
        utl::ByteString::inc(J0_1, 16, 4, J0_1);
        GCTR(K, lk, J0_1, C, lc, P);

        size_t u = 16 * ((lc + 15) / 16) - lc;
        size_t v = 16 * ((la + 15) / 16) - la;

        size_t lx = la + v + lc + u + 8 + 8;
        uint8_t* X = new uint8_t[lx];
        auto t_X = X;
        if (A) { std::memcpy(t_X, A, la); t_X += la; }
        std::memset(t_X, 0, v); t_X += v;
        if (C) { std::memcpy(t_X, C, lc); t_X += lc; }
        std::memset(t_X, 0, u); t_X += u;

        utl::ByteString::len64(la, t_X); t_X += 8;
        utl::ByteString::len64(lc, t_X);

        uint8_t S[16];
        GHASH(H, X, lx, S);

        delete[] X;

        uint8_t tmp[16];
        GCTR(K, lk, J0, S, 16, tmp);
        if (std::memcmp(T, tmp, t) != 0) {
            return false;
        }

        return true;
    }

    void GCM::product(const uint8_t X[16], const uint8_t Y[16], uint8_t* r) {
        uint8_t Z[16];
        uint8_t V[16];
        std::memset(Z, 0, 16);
        std::memcpy(V, Y, 16);

        for (int i = 0; i < 128; ++i) {
            auto t = utl::ByteString::getBit(X, i);
            if (t) {
                utl::ByteString::exor(Z, 16, V, 16, Z);
            }
            if (V[15] & 0x01) {
                utl::ByteString::div2(V, 16, V);
                V[0] ^= 0xE1;
            } else {
                utl::ByteString::div2(V, 16, V);
            }
        }
        std::memcpy(r, Z, 16);
    }

    void GCM::GHASH(const uint8_t H[16], const uint8_t* X, size_t lx, uint8_t* r) {
        size_t m = lx / 16;
        std::memset(r, 0, 16);

        for (size_t i = 0; i < m; ++i) {
            utl::ByteString::exor(r, 16, X + i * 16, 16, r);
            product(r, H, r);
        }
    }

    void GCM::GCTR(
        const uint8_t* K, size_t lk,
        const uint8_t ICB[16], const uint8_t* X, size_t lx, uint8_t* r)
    {
        if (lx == 0) {
            return;
        }
        size_t n = (lx + 15) / 16;

        size_t i;
        uint8_t CB[16];
        std::memcpy(CB, ICB, 16);

        uint8_t* Yi = r;
        for (i = 2; i <= n; ++i) {
            uint8_t crypted[16];
            CIPH(K, lk, CB, crypted);

            std::memcpy(Yi, X + (i - 2) * 16, 16);
            utl::ByteString::exor(Yi, 16, crypted, 16, Yi);
            utl::ByteString::inc(CB, 16, 4, CB);

            Yi += 16;
        }

        uint8_t crypted[16];
        CIPH(K, lk, CB, crypted);

        size_t rem = lx - (i - 2) * 16;
        std::memcpy(Yi, X + (i - 2) * 16, rem);
        utl::ByteString::exor(Yi, 16, crypted, rem, Yi);
    }

    void GCM::CIPH(
        const uint8_t* K, size_t lk, const uint8_t CB[16], uint8_t* r)
    {
        AES::encrypt(CB, r, K, lk);
    }

}
}