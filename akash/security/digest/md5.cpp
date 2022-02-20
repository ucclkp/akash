// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/security/digest/md5.h"

#include <algorithm>

#include "utils/strings/int_conv.hpp"

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

/**
 * F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/**
 * ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/**
 * FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
 * Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
}


static unsigned char PADDING[64] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};


namespace akash {
namespace digest {

    std::string MD5::cal(const std::string& str) {
        MD5 md5;
        uint8_t digest[16];

        md5.init();
        md5.update(reinterpret_cast<const uint8_t*>(str.data()), str.length());
        md5.result(digest);

        std::string result;
        for (int i = 0; i < 16; ++i) {
            int val = static_cast<int>(digest[i]);
            if (val < 16) {
                result.append("0");
            }
            result.append(utl::itos8(val, 16));
        }

        return result;
    }

    std::string MD5::cal(const std::string& str, size_t block_size) {
        MD5 md5;
        uint8_t digest[16];

        md5.init();

        size_t offset = 0;
        size_t remain_length = str.length();
        while (remain_length > 0) {
            auto cur_size = std::min(block_size, remain_length);
            md5.update(reinterpret_cast<const uint8_t*>(str.data() + offset), cur_size);
            remain_length -= cur_size;
            offset += cur_size;
        }
        md5.result(digest);

        std::string result;
        for (int i = 0; i < 16; ++i) {
            int val = static_cast<int>(digest[i]);
            if (val < 16) {
                result.append("0");
            }
            result.append(utl::itos8(val, 16));
        }

        return result;
    }

    void MD5::init() {
        // 已处理 bit 数
        context_.count = 0;
        context_.computed = false;
        context_.corrupted = md5Success;

        context_.state[0] = 0x67452301;
        context_.state[1] = 0xefcdab89;
        context_.state[2] = 0x98badcfe;
        context_.state[3] = 0x10325476;
    }

    int MD5::update(const uint8_t* bytes, size_t length) {
        if (length == 0) return md5Success;
        if (!bytes) return md5Null;
        if (context_.corrupted) return context_.corrupted;
        if (context_.computed) return context_.corrupted = md5StateError;

        uint32_t index = (context_.count / 8) % 64;
        context_.count += length * 8;

        size_t i;
        uint32_t prev_remain_bytes = 64 - index;
        if (length >= prev_remain_bytes) {
            std::memcpy(&context_.buffer[index], bytes, prev_remain_bytes);
            transform(context_.state, context_.buffer);

            for (i = prev_remain_bytes; i + 63 < length; i += 64) {
                std::memcpy(context_.buffer, &bytes[i], 64);
                transform(context_.state, context_.buffer);
            }
            index = 0;
        } else {
            i = 0;
        }

        std::memcpy(&context_.buffer[index], &bytes[i], length - i);

        return context_.corrupted;
    }

    int MD5::finalBits(uint8_t bits, unsigned int length) {
        static uint8_t masks[8] = {
            /* 0 0b00000000 */ 0x00, /* 1 0b10000000 */ 0x80,
            /* 2 0b11000000 */ 0xC0, /* 3 0b11100000 */ 0xE0,
            /* 4 0b11110000 */ 0xF0, /* 5 0b11111000 */ 0xF8,
            /* 6 0b11111100 */ 0xFC, /* 7 0b11111110 */ 0xFE
        };

        static uint8_t markbit[8] = {
            /* 0 0b10000000 */ 0x80, /* 1 0b01000000 */ 0x40,
            /* 2 0b00100000 */ 0x20, /* 3 0b00010000 */ 0x10,
            /* 4 0b00001000 */ 0x08, /* 5 0b00000100 */ 0x04,
            /* 6 0b00000010 */ 0x02, /* 7 0b00000001 */ 0x01
        };

        if (length == 0) return md5Success;
        if (context_.corrupted) return context_.corrupted;
        if (context_.computed) return context_.corrupted = md5StateError;
        if (length >= 8) return context_.corrupted = md5BadParam;

        auto byte = uint8_t((bits & masks[length]) | markbit[length]);
        finalize(byte, length);

        return context_.corrupted;
    }

    int MD5::result(uint8_t digest[16]) {
        if (!digest) return md5Null;
        if (context_.corrupted) return context_.corrupted;

        if (!context_.computed) {
            finalize(0x80, 0);
        }

        UInt32sToBytes(digest, context_.state, 16);

        std::memset(&context_, 0, sizeof(context_));

        return context_.corrupted;
    }

    void MD5::finalize(uint8_t pad_byte, uint8_t ex_bit_length) {
        uint64_t real_count = context_.count + ex_bit_length;

        uint8_t bits[8];
        UInt64sToBytes(bits, &real_count, 8);

        uint32_t index = (context_.count / 8) % 64;
        uint32_t pad_len = (index < 56) ? (56 - index) : (120 - index);

        PADDING[0] = pad_byte;

        update(PADDING, pad_len);
        update(bits, 8);

        context_.computed = true;
    }

    void MD5::transform(uint32_t state[4], uint8_t block[64]) {
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

        bytesToUInt32s(x, block, 64);

        // Round 1
        FF(a, b, c, d, x[0],  S11, 0xd76aa478); /* 1 */
        FF(d, a, b, c, x[1],  S12, 0xe8c7b756); /* 2 */
        FF(c, d, a, b, x[2],  S13, 0x242070db); /* 3 */
        FF(b, c, d, a, x[3],  S14, 0xc1bdceee); /* 4 */
        FF(a, b, c, d, x[4],  S11, 0xf57c0faf); /* 5 */
        FF(d, a, b, c, x[5],  S12, 0x4787c62a); /* 6 */
        FF(c, d, a, b, x[6],  S13, 0xa8304613); /* 7 */
        FF(b, c, d, a, x[7],  S14, 0xfd469501); /* 8 */
        FF(a, b, c, d, x[8],  S11, 0x698098d8); /* 9 */
        FF(d, a, b, c, x[9],  S12, 0x8b44f7af); /* 10 */
        FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
        FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
        FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
        FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
        FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
        FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

        // Round 2
        GG(a, b, c, d, x[1],  S21, 0xf61e2562); /* 17 */
        GG(d, a, b, c, x[6],  S22, 0xc040b340); /* 18 */
        GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
        GG(b, c, d, a, x[0],  S24, 0xe9b6c7aa); /* 20 */
        GG(a, b, c, d, x[5],  S21, 0xd62f105d); /* 21 */
        GG(d, a, b, c, x[10], S22, 0x2441453);  /* 22 */
        GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
        GG(b, c, d, a, x[4],  S24, 0xe7d3fbc8); /* 24 */
        GG(a, b, c, d, x[9],  S21, 0x21e1cde6); /* 25 */
        GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
        GG(c, d, a, b, x[3],  S23, 0xf4d50d87); /* 27 */
        GG(b, c, d, a, x[8],  S24, 0x455a14ed); /* 28 */
        GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
        GG(d, a, b, c, x[2],  S22, 0xfcefa3f8); /* 30 */
        GG(c, d, a, b, x[7],  S23, 0x676f02d9); /* 31 */
        GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

        // Round 3
        HH(a, b, c, d, x[5],  S31, 0xfffa3942); /* 33 */
        HH(d, a, b, c, x[8],  S32, 0x8771f681); /* 34 */
        HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
        HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
        HH(a, b, c, d, x[1],  S31, 0xa4beea44); /* 37 */
        HH(d, a, b, c, x[4],  S32, 0x4bdecfa9); /* 38 */
        HH(c, d, a, b, x[7],  S33, 0xf6bb4b60); /* 39 */
        HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
        HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
        HH(d, a, b, c, x[0],  S32, 0xeaa127fa); /* 42 */
        HH(c, d, a, b, x[3],  S33, 0xd4ef3085); /* 43 */
        HH(b, c, d, a, x[6],  S34, 0x4881d05);  /* 44 */
        HH(a, b, c, d, x[9],  S31, 0xd9d4d039); /* 45 */
        HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
        HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
        HH(b, c, d, a, x[2],  S34, 0xc4ac5665); /* 48 */

        // Round 4
        II(a, b, c, d, x[0],  S41, 0xf4292244); /* 49 */
        II(d, a, b, c, x[7],  S42, 0x432aff97); /* 50 */
        II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
        II(b, c, d, a, x[5],  S44, 0xfc93a039); /* 52 */
        II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
        II(d, a, b, c, x[3],  S42, 0x8f0ccc92); /* 54 */
        II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
        II(b, c, d, a, x[1],  S44, 0x85845dd1); /* 56 */
        II(a, b, c, d, x[8],  S41, 0x6fa87e4f); /* 57 */
        II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
        II(c, d, a, b, x[6],  S43, 0xa3014314); /* 59 */
        II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
        II(a, b, c, d, x[4],  S41, 0xf7537e82); /* 61 */
        II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
        II(c, d, a, b, x[2],  S43, 0x2ad7d2bb); /* 63 */
        II(b, c, d, a, x[9],  S44, 0xeb86d391); /* 64 */

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;

        std::memset(x, 0, sizeof(x));
    }

    void MD5::UInt32sToBytes(uint8_t* out, const uint32_t* in, uint32_t len) {
        for (uint32_t i = 0, j = 0; j < len; ++i, j += 4) {
            out[j] = static_cast<uint8_t>(in[i] & 0xff);
            out[j + 1] = static_cast<uint8_t>((in[i] >> 8) & 0xff);
            out[j + 2] = static_cast<uint8_t>((in[i] >> 16) & 0xff);
            out[j + 3] = static_cast<uint8_t>((in[i] >> 24) & 0xff);
        }
    }

    void MD5::UInt64sToBytes(uint8_t* out, const uint64_t* in, uint32_t len) {
        for (uint32_t i = 0, j = 0; j < len; ++i, j += 8) {
            out[j] = static_cast<uint8_t>(in[i] & 0xff);
            out[j + 1] = static_cast<uint8_t>((in[i] >> 8) & 0xff);
            out[j + 2] = static_cast<uint8_t>((in[i] >> 16) & 0xff);
            out[j + 3] = static_cast<uint8_t>((in[i] >> 24) & 0xff);
            out[j + 4] = static_cast<uint8_t>((in[i] >> 32) & 0xff);
            out[j + 5] = static_cast<uint8_t>((in[i] >> 40) & 0xff);
            out[j + 6] = static_cast<uint8_t>((in[i] >> 48) & 0xff);
            out[j + 7] = static_cast<uint8_t>((in[i] >> 56) & 0xff);
        }
    }

    void MD5::bytesToUInt32s(uint32_t* out, const uint8_t* in, uint32_t len) {
        for (uint32_t i = 0, j = 0; j < len; i++, j += 4)
            out[i] = static_cast<uint32_t>(in[j]) |
            (static_cast<uint32_t>(in[j + 1]) << 8) |
            (static_cast<uint32_t>(in[j + 2]) << 16) |
            (static_cast<uint32_t>(in[j + 3]) << 24);
    }

}
}