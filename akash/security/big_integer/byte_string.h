// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_SECURITY_BIG_INTEGER_BYTE_STRING_H_
#define AKASH_SECURITY_BIG_INTEGER_BYTE_STRING_H_

#include <cstdint>
#include <cstddef>


namespace utl {

    class ByteString {
    public:
        /**
         * 求 a, b 两序列的异或序列。
         * 若两序列长度不等，则左端对齐求结果，多出部分不变。
         * r 的长度应等于 a, b 两序列长度的较大者。
         */
        static void exor(
            const uint8_t* a, size_t la,
            const uint8_t* b, size_t lb, uint8_t* r);

        /**
         * 求序列 a 除以 2 的结果。
         * r 的长度应等于 la。
         */
        static void div2(const uint8_t* a, size_t la, uint8_t* r);

        /**
         * 获取序列 a 的指定位。
         * 最左端的位索引为 0。
         */
        static uint8_t getBit(const uint8_t* a, size_t idx);

        /**
         * 将序列 a 从右端开始的 s 字节加 1，最高进位舍弃。
         * la 不能小于 s。r 的长度应等于 la。
         */
        static void inc(const uint8_t* a, size_t la, size_t s, uint8_t* r);

        /**
         * 求某序列字节长度 la 的位长的 8 字节表示。
         * r 的长度应等于 8。
         */
        static void len64(size_t la, uint8_t* r);
    };

}

#endif  // AKASH_SECURITY_BIG_INTEGER_BYTE_STRING_H_
