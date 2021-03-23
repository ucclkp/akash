// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_SECURITY_CRYPTO_AES_H_
#define AKASH_SECURITY_CRYPTO_AES_H_

#include <cstdint>


namespace akash {
namespace crypto {

    // 根据 FIPS PUB 197 实现的 AES 算法。
    // 支持 128bit、192bit 和 256bit 密钥。
    class AES {
    public:
        // 状态矩阵的列数
        static const uint32_t Nb = 4;

        static void encrypt(
            const uint8_t in[4 * Nb], uint8_t out[4 * Nb],
            const uint8_t* key, uint32_t length);
        static void decrypt(
            const uint8_t in[4 * Nb], uint8_t out[4 * Nb],
            const uint8_t* key, uint32_t length);

    private:
        static void encrypt(
            const uint8_t in[4 * Nb], uint8_t out[4 * Nb],
            const uint32_t* w, uint32_t Nr);
        static void decrypt(
            const uint8_t in[4 * Nb], uint8_t out[4 * Nb],
            const uint32_t* w, uint32_t Nr);

        struct Context {
            uint8_t state[4 * Nb];
        };

        static void subBytes(Context* context);
        static void shiftRows(Context* context);
        static void mixColumns(Context* context);

        static void invSubBytes(Context* context);
        static void invShiftRows(Context* context);
        static void invMixColumns(Context* context);

        static void addRoundKey(Context* context, const uint32_t* w);
        static void keyExpansion(
            const uint8_t* key, uint32_t length, uint32_t* out);

        static uint8_t getSBoxSubByte(uint8_t org);
        static uint8_t getInvSBoxSubByte(uint8_t org);
        static uint32_t getNr(uint32_t Nk, uint32_t Nb);
        static uint32_t bytesToUInt32(const uint8_t* bytes);
        static uint32_t subWord(uint32_t word);
        static uint32_t rotWord(uint32_t word);
        static uint32_t rcon(uint32_t i);
        static uint8_t multi2(uint8_t val);
        static uint8_t multi2(uint8_t val, uint8_t exp);
        static uint8_t multi3(uint8_t val);
        static uint8_t multi(uint8_t val, uint8_t factor);
        static uint8_t pow2(uint8_t exp);
    };

}
}

#endif  // AKASH_SECURITY_CRYPTO_AES_H_
