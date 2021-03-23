// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_SECURITY_CRYPTO_AEAD_H_
#define AKASH_SECURITY_CRYPTO_AEAD_H_

#include <cstdint>


namespace akash {
namespace crypto {

    // NIST Special Publication 800-38D
    // Based on AES.
    class GCM {
    public:
        /**
         * 加密。使用 AES。
         * K 指向 AES Key，不能为空指针。lk 必须为可用的密钥长度。
         * IV 为初始向量，不能为空指针。l_iv 为 IV 的长度。
         * P 为待加密的明文，可以为空指针，但同时 lp 必须为 0。
         * A 为额外的已认证数据 (AAD)，可以为空指针，但同时 la 必须为 0。
         * C 为加密后的密文，其长度应等于 lp。可以为空指针，但同时 P 也必须为空指针。
         * T 为认证标签 (A 和 C 的校验和)，不能为空指针，长度为 t，t 不应大于块长度。
         */
        static void GCM_AE(
            const uint8_t* K, size_t lk, const uint8_t* IV, size_t l_iv,
            const uint8_t* P, size_t lp, const uint8_t* A, size_t la,
            uint8_t* C, uint8_t* T, size_t t);

        /**
         * 解密。使用 AES。
         * K 指向 AES Key，不能为空指针。lk 必须为可用的密钥长度。
         * IV 为初始向量，不能为空指针。l_iv 为 IV 的长度。
         * C 为待解密的密文，可以为空指针，但同时 lc 必须为 0。
         * A 为额外的已认证数据 (AAD)，可以为空指针，但同时 la 必须为 0。
         * T 为认证标签 (用于确保 A 和 C 没有被篡改)，不能为空指针，长度为 t，t 不应大于块长度。
         * P 为解密后的明文，其长度应等于 lc。可以为空指针，但同时 C 也必须为空指针。
         *
         * 返回值：若由 A 和 C 计算出的校验和与提供的 T 在 t 范围内相等，返回 true，否则返回 false。
         */
        static bool GCM_AD(
            const uint8_t* K, size_t lk, const uint8_t* IV, size_t l_iv,
            const uint8_t* C, size_t lc, const uint8_t* A, size_t la,
            const uint8_t* T, size_t t, uint8_t* P);

    private:
        static const uint64_t kLenPMin = 0;
        static const uint64_t kLenPMax = (uint64_t(1) << 39) - 256;
        static const uint64_t kLenAMin = 0;
        static const uint64_t kLenAMax = -1;
        static const uint64_t kLenIVMin = 1;
        static const uint64_t kLenIVMax = -1;

        /**
         * 计算伽罗瓦域上的 X * Y。
         * 块 X 和 Y 的长度固定，r 的长度应等于该长度。
         */
        static void product(
            const uint8_t X[16], const uint8_t Y[16], uint8_t* r);

        /**
         * 计算 X 的 GHASH 值。
         * X 可以为空指针，但同时 lx 必须为 0。
         * 块 H 的长度固定，r 的长度应等于该长度。
         */
        static void GHASH(
            const uint8_t H[16], const uint8_t* X, size_t lx, uint8_t* r);

        /**
         * 计算 X 的 GCTR 值，其中使用 AES 加密/解密。
         * K 指向 AES Key，不能为空指针。lk 必须为可用的密钥长度。
         * 块 ICB 的长度固定。
         * X 可以为空指针，但同时 lx 必须为 0。
         * r 的长度应等于 lx。
         */
        static void GCTR(
            const uint8_t* K, size_t lk,
            const uint8_t ICB[16], const uint8_t* X, size_t lx, uint8_t* r);

        /**
         * 块加密/解密。使用 AES。
         * K 指向 AES Key，不能为空指针。lk 必须为可用的密钥长度。
         * 块 CB 的长度固定，r 的长度应等于该长度。
         */
        static void CIPH(
            const uint8_t* K, size_t lk, const uint8_t CB[16], uint8_t* r);

    };

}
}

#endif  // AKASH_SECURITY_CRYPTO_AEAD_H_
