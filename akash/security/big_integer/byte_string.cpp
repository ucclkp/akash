// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "byte_string.h"

#include <cassert>


namespace utl {

    void ByteString::exor(
        const uint8_t* a, size_t la,
        const uint8_t* b, size_t lb, uint8_t* r)
    {
        const uint8_t* max;
        size_t l_min, l_max;
        if (la < lb) {
            max = b;
            l_min = la;
            l_max = lb;
        } else {
            max = a;
            l_min = lb;
            l_max = la;
        }

        size_t i;
        for (i = 0; i < l_min; ++i) {
            r[i] = (a[i] ^ b[i]);
        }

        for (; i < l_max; ++i) {
            r[i] = max[i];
        }
    }

    void ByteString::div2(const uint8_t* a, size_t la, uint8_t* r) {
        uint8_t rem = 0;
        for (size_t i = 0; i < la; ++i) {
            uint8_t tmp = a[i];
            r[i] = (tmp >> 1) | (rem << 7);
            rem = tmp & 0x01;
        }
    }

    uint8_t ByteString::getBit(const uint8_t* a, size_t idx) {
        auto pos = idx / 8;
        auto off = idx % 8;
        return (a[pos] >> (7 - off)) & 1;
    }

    void ByteString::inc(const uint8_t* a, size_t la, size_t s, uint8_t* r) {
        if (la == 0) {
            return;
        }
        if (s > la) {
            assert(false);
            return;
        }

        auto ls = la - s;
        uint8_t over = 1;
        for (size_t i = la - 1; i >= ls; --i) {
            uint16_t tmp = a[i] + over;
            r[i] = tmp & 0xFF;
            over = tmp >> 8;
        }

        for (size_t i = 0; i < ls; ++i) {
            r[i] = a[i];
        }
    }

    void ByteString::len64(size_t la, uint8_t* r) {
        uint64_t iv_len = la * 8;
        for (int i = 0; i < 8; ++i) {
            r[i] = uint8_t(iv_len >> ((7 - i) * 8));
        }
    }

}
