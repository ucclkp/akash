// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "aes.h"

#include <algorithm>
#include <cassert>


static const uint8_t SBox[16][16] = {
     // 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
/*0*/ {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
/*1*/ {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
/*2*/ {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
/*3*/ {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
/*4*/ {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
/*5*/ {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
/*6*/ {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
/*7*/ {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
/*8*/ {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
/*9*/ {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
/*a*/ {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
/*b*/ {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
/*c*/ {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
/*d*/ {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
/*e*/ {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
/*f*/ {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16},
};

static const uint8_t InvSBox[16][16] = {
     // 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
/*0*/ {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
/*1*/ {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
/*2*/ {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
/*3*/ {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
/*4*/ {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
/*5*/ {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
/*6*/ {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
/*7*/ {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
/*8*/ {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
/*9*/ {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
/*a*/ {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
/*b*/ {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
/*c*/ {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
/*d*/ {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
/*e*/ {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
/*f*/ {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d},
};

namespace akash {
namespace crypto {

    void AES::encrypt(
        const uint8_t in[4 * Nb], uint8_t out[4 * Nb],
        const uint8_t* key, uint32_t length)
    {
        uint32_t Nr = getNr(length / 4, Nb);
        switch (Nr) {
        case 10:
        {
            uint32_t key_exp[Nb * (10 + 1)];
            keyExpansion(key, length, key_exp);
            encrypt(in, out, key_exp, Nr);
            break;
        }
        case 12:
        {
            uint32_t key_exp[Nb * (12 + 1)];
            keyExpansion(key, length, key_exp);
            encrypt(in, out, key_exp, Nr);
            break;
        }
        case 14:
        {
            uint32_t key_exp[Nb * (14 + 1)];
            keyExpansion(key, length, key_exp);
            encrypt(in, out, key_exp, Nr);
            break;
        }
        default:
            assert(false);
            break;
        }
    }

    void AES::decrypt(
        const uint8_t in[4 * Nb], uint8_t out[4 * Nb],
        const uint8_t* key, uint32_t length)
    {
        uint32_t Nr = getNr(length / 4, Nb);
        switch (Nr) {
        case 10:
        {
            uint32_t key_exp[Nb * (10 + 1)];
            keyExpansion(key, length, key_exp);
            decrypt(in, out, key_exp, Nr);
            break;
        }
        case 12:
        {
            uint32_t key_exp[Nb * (12 + 1)];
            keyExpansion(key, length, key_exp);
            decrypt(in, out, key_exp, Nr);
            break;
        }
        case 14:
        {
            uint32_t key_exp[Nb * (14 + 1)];
            keyExpansion(key, length, key_exp);
            decrypt(in, out, key_exp, Nr);
            break;
        }
        default:
            assert(false);
            break;
        }
    }

    void AES::encrypt(
        const uint8_t in[4 * Nb], uint8_t out[4 * Nb],
        const uint32_t* w, uint32_t Nr)
    {
        Context context;
        for (int i = 0; i < Nb; ++i) {
            context.state[i] = in[i * 4];
            context.state[i + 4] = in[i * 4 + 1];
            context.state[i + 8] = in[i * 4 + 2];
            context.state[i + 12] = in[i * 4 + 3];
        }

        addRoundKey(&context, w);

        for (uint32_t i = 1; i < Nr; ++i) {
            subBytes(&context);
            shiftRows(&context);
            mixColumns(&context);
            addRoundKey(&context, w + i * Nb);
        }

        subBytes(&context);
        shiftRows(&context);
        addRoundKey(&context, w + Nr * Nb);

        for (int i = 0; i < Nb; ++i) {
            out[i * 4] = context.state[i];
            out[i * 4 + 1] = context.state[i + 4];
            out[i * 4 + 2] = context.state[i + 8];
            out[i * 4 + 3] = context.state[i + 12];
        }
    }

    void AES::decrypt(
        const uint8_t in[4 * Nb], uint8_t out[4 * Nb],
        const uint32_t* w, uint32_t Nr)
    {
        Context context;
        for (int i = 0; i < Nb; ++i) {
            context.state[i] = in[i * 4];
            context.state[i + 4] = in[i * 4 + 1];
            context.state[i + 8] = in[i * 4 + 2];
            context.state[i + 12] = in[i * 4 + 3];
        }

        addRoundKey(&context, w + Nr * Nb);

        for (uint32_t i = Nr - 1; i >= 1; --i) {
            invShiftRows(&context);
            invSubBytes(&context);
            addRoundKey(&context, w + i * Nb);
            invMixColumns(&context);
        }

        invShiftRows(&context);
        invSubBytes(&context);
        addRoundKey(&context, w);

        for (int i = 0; i < Nb; ++i) {
            out[i * 4] = context.state[i];
            out[i * 4 + 1] = context.state[i + 4];
            out[i * 4 + 2] = context.state[i + 8];
            out[i * 4 + 3] = context.state[i + 12];
        }
    }

    void AES::subBytes(Context* context) {
        for (int i = 0; i < 4 * Nb; ++i) {
            context->state[i] = getSBoxSubByte(context->state[i]);
        }
    }

    void AES::shiftRows(Context* context) {
        uint8_t buf[3];

        // 1
        buf[0] = context->state[Nb];

        for (int i = 0; i < Nb; ++i) {
            if (i + 2 > Nb) {
                context->state[Nb + i] = buf[i - Nb + 1];
            } else {
                context->state[Nb + i] = context->state[Nb + i + 1];
            }
        }

        // 2
        buf[0] = context->state[Nb * 2];
        buf[1] = context->state[Nb * 2 + 1];

        for (int i = 0; i < Nb; ++i) {
            if (i + 3 > Nb) {
                context->state[Nb * 2 + i] = buf[i - Nb + 2];
            } else {
                context->state[Nb * 2 + i] = context->state[Nb * 2 + i + 2];
            }
        }

        // 3
        buf[0] = context->state[Nb * 3];
        buf[1] = context->state[Nb * 3 + 1];
        buf[2] = context->state[Nb * 3 + 2];

        for (int i = 0; i < Nb; ++i) {
            if (i + 4 > Nb) {
                context->state[Nb * 3 + i] = buf[i - Nb + 3];
            } else {
                context->state[Nb * 3 + i] = context->state[Nb * 3 + i + 3];
            }
        }
    }

    void AES::mixColumns(Context* context) {
        uint8_t buf[4];
        for (int i = 0; i < Nb; ++i) {
            buf[0] = context->state[i];
            buf[1] = context->state[i + 4];
            buf[2] = context->state[i + 8];
            buf[3] = context->state[i + 12];

            context->state[i] = multi2(buf[0]) ^ multi3(buf[1]) ^ buf[2] ^ buf[3];
            context->state[i + 4] = buf[0] ^ multi2(buf[1]) ^ multi3(buf[2]) ^ buf[3];
            context->state[i + 8] = buf[0] ^ buf[1] ^ multi2(buf[2]) ^ multi3(buf[3]);
            context->state[i + 12] = multi3(buf[0]) ^ buf[1] ^ buf[2] ^ multi2(buf[3]);
        }
    }

    void AES::invSubBytes(Context* context) {
        for (int i = 0; i < 4 * Nb; ++i) {
            context->state[i] = getInvSBoxSubByte(context->state[i]);
        }
    }

    void AES::invShiftRows(Context* context) {
        uint8_t buf[3];

        // 1
        buf[0] = context->state[Nb * 2 - 1];

        for (int i = Nb - 1; i >= 0; --i) {
            if (i < 1) {
                context->state[Nb + i] = buf[i];
            } else {
                context->state[Nb + i] = context->state[Nb + i - 1];
            }
        }

        // 2
        buf[0] = context->state[Nb * 3 - 2];
        buf[1] = context->state[Nb * 3 - 1];

        for (int i = Nb - 1; i >= 0; --i) {
            if (i < 2) {
                context->state[Nb * 2 + i] = buf[i];
            } else {
                context->state[Nb * 2 + i] = context->state[Nb * 2 + i - 2];
            }
        }

        // 3
        buf[0] = context->state[Nb * 4 - 3];
        buf[1] = context->state[Nb * 4 - 2];
        buf[2] = context->state[Nb * 4 - 1];

        for (int i = Nb - 1; i >= 0; --i) {
            if (i < 3) {
                context->state[Nb * 3 + i] = buf[i];
            } else {
                context->state[Nb * 3 + i] = context->state[Nb * 3 + i - 3];
            }
        }
    }

    void AES::invMixColumns(Context* context) {
        uint8_t buf[4];
        for (int i = 0; i < Nb; ++i) {
            buf[0] = context->state[i];
            buf[1] = context->state[i + 4];
            buf[2] = context->state[i + 8];
            buf[3] = context->state[i + 12];

            context->state[i] = multi(buf[0], 0x0e) ^ multi(buf[1], 0x0b) ^ multi(buf[2], 0x0d) ^ multi(buf[3], 0x09);
            context->state[i + 4] = multi(buf[0], 0x09) ^ multi(buf[1], 0x0e) ^ multi(buf[2], 0x0b) ^ multi(buf[3], 0x0d);
            context->state[i + 8] = multi(buf[0], 0x0d) ^ multi(buf[1], 0x09) ^ multi(buf[2], 0x0e) ^ multi(buf[3], 0x0b);
            context->state[i + 12] = multi(buf[0], 0x0b) ^ multi(buf[1], 0x0d) ^ multi(buf[2], 0x09) ^ multi(buf[3], 0x0e);
        }
    }

    void AES::addRoundKey(Context* context, const uint32_t* w) {
        for (int i = 0; i < Nb; ++i) {
            context->state[i] ^= static_cast<uint8_t>((w[i] >> 24) & 0xFF);
            context->state[i + 4] ^= static_cast<uint8_t>((w[i] >> 16) & 0xFF);
            context->state[i + 8] ^= static_cast<uint8_t>((w[i] >> 8) & 0xFF);
            context->state[i + 12] ^= static_cast<uint8_t>(w[i] & 0xFF);
        }
    }

    void AES::keyExpansion(
        const uint8_t* key, uint32_t length, uint32_t* out)
    {
        uint32_t Nk = length / 4;
        uint32_t Nr = getNr(Nk, Nb);

        uint32_t i = 0;
        while (i < Nk) {
            out[i] = bytesToUInt32(key + 4 * i);
            ++i;
        }

        i = Nk;

        while (i < Nb * (Nr + 1)) {
            uint32_t tmp = out[i - 1];
            if (i % Nk == 0) {
                tmp = subWord(rotWord(tmp)) ^ rcon(i / Nk);
            } else if (Nk > 6 && (i % Nk == 4)) {
                tmp = subWord(tmp);
            }
            out[i] = out[i - Nk] ^ tmp;
            ++i;
        }
    }

    uint8_t AES::getSBoxSubByte(uint8_t org) {
        uint8_t x = (org >> 4) & 0xF;
        uint8_t y = org & 0xF;
        return SBox[x][y];
    }

    uint8_t AES::getInvSBoxSubByte(uint8_t org) {
        uint8_t x = (org >> 4) & 0xF;
        uint8_t y = org & 0xF;
        return InvSBox[x][y];
    }

    uint32_t AES::getNr(uint32_t Nk, uint32_t Nb) {
        if (Nk == 4 && Nb == 4) {
            return 10;
        }
        if (Nk == 6 && Nb == 4) {
            return 12;
        }
        if (Nk == 8 && Nb == 4) {
            return 14;
        }
        return 0;
    }

    uint32_t AES::bytesToUInt32(const uint8_t* bytes) {
        return (static_cast<uint32_t>(bytes[0]) << 24) |
            (static_cast<uint32_t>(bytes[1]) << 16) |
            (static_cast<uint32_t>(bytes[2]) << 8) |
            (static_cast<uint32_t>(bytes[3]));
    }

    uint32_t AES::subWord(uint32_t word) {
        uint32_t result = 0;
        for (int i = 0; i < 4; ++i) {
            result |= (static_cast<uint32_t>(getSBoxSubByte((word >> i * 8) & 0xFF)) << i * 8);
        }
        return result;
    }

    uint32_t AES::rotWord(uint32_t word) {
        return (word << 8) | (word >> 24);
    }

    uint32_t AES::rcon(uint32_t i) {
        auto shift = i - 1U;
        uint32_t prev = 1U;
        for (;;) {
            prev = prev << std::min(shift, 7U);
            if (shift < 8U) {
                return (prev & 0xFF) << 24;
            }
            prev = (prev << 1U) ^ 0x1b;
            shift -= 8U;
        }
    }

    uint8_t AES::multi2(uint8_t val) {
        if (val & 0x80) {
            return (val << 1) ^ 0x1b;
        }
        return val << 1;
    }

    uint8_t AES::multi2(uint8_t val, uint8_t exp) {
        uint8_t result = val;
        for (uint8_t i = 0; i < exp; ++i) {
            result = multi2(result);
        }
        return result;
    }

    uint8_t AES::multi3(uint8_t val) {
        return multi(val, 0x3);
    }

    uint8_t AES::multi(uint8_t val, uint8_t factor) {
        uint8_t result = 0;
        for (int i = 0; i < 8; ++i) {
            if (factor & (1U << i)) {
                result ^= multi2(val, i);
            }
        }
        return result;
    }

    uint8_t AES::pow2(uint8_t exp) {
        uint8_t shift = exp;
        uint8_t prev = 1U;
        for (;;) {
            prev = prev << std::min(static_cast<uint32_t>(shift), 7U);
            if (shift < 8U) {
                return prev;
            }
            prev = (prev << 1U) ^ 0x1b;
            shift -= 8U;
        }
    }

}
}