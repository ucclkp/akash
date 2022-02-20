// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "big_integer_unit_test.h"

#include <cmath>

#include "utils/strings/int_conv.hpp"
#include "utils/log.h"
#include "akash/security/big_integer/big_integer.h"
#include "akash/security/big_integer/byte_string.h"


namespace {

    using Digit = utl::IntArray::Digit;

    bool testToInt64(int64_t left) {
        auto test = utl::BigInteger::from64(left);
        return test.toInt64() == left;
    }

    bool testAdd(int64_t left, int64_t right) {
        auto test = utl::BigInteger::from64(left);
        test.add(utl::BigInteger::from64(right));
        return test.toInt64() == left + right;
    }

    bool testSub(int64_t left, int64_t right) {
        auto test = utl::BigInteger::from64(left);
        test.sub(utl::BigInteger::from64(right));
        return test.toInt64() == left - right;
    }

    bool testMul(int32_t left, int32_t right) {
        auto test = utl::BigInteger::from32(left);
        test.mul(utl::BigInteger::from32(right));
        return test.toInt64() == int64_t(left) * int64_t(right);
    }

    bool testDiv(int64_t left, int64_t right) {
        auto test = utl::BigInteger::from64(left);
        test.div(utl::BigInteger::from64(right));
        return test.toInt64() == left / right;
    }

    bool testAdds(int64_t left, Digit right) {
        auto test = utl::BigInteger::from64(left);
        test.add(right);
        return test.toInt64() == left + right;
    }

    bool testSubs(int64_t left, Digit right) {
        auto test = utl::BigInteger::from64(left);
        test.sub(right);
        return test.toInt64() == left - right;
    }

    bool testMuls(int32_t left, Digit right) {
        auto test = utl::BigInteger::from32(left);
        test.mul(right);
        return test.toInt64() == int64_t(left) * int64_t(right);
    }

    bool testDivs(int64_t left, Digit right) {
        auto test = utl::BigInteger::from64(left);
        test.div(right);
        return test.toInt64() == left / right;
    }

    bool testDivOverflow() {
        auto test = utl::BigInteger::from64(INT64_MIN);
        test.div(utl::BigInteger::from32(-1));
        return test.isBeyondInt64();
    }

    bool testMod(int64_t left, int64_t right) {
        auto test = utl::BigInteger::from64(left);
        test.mod(utl::BigInteger::from64(right));
        return test.toInt64() == left % right;
    }

    /*bool testPow(int64_t left, int64_t exp) {
        auto test = utl::BigInteger::from64(left);
        test.pow(utl::BigInteger::from64(exp));
        return test.toInt64() == int64_t(std::pow(left, exp));
    }*/

    bool testPow(int64_t left, Digit exp) {
        auto test = utl::BigInteger::from64(left);
        test.pow(exp);
        return test.toInt64() == int64_t(std::pow(left, exp));
    }

    bool testPowMod(int64_t left, int64_t exp, int64_t rem) {
        auto test = utl::BigInteger::from64(left);
        test.powMod(utl::BigInteger::from64(exp), utl::BigInteger::from64(rem));
        return test.toInt64() == int64_t(std::pow(left, exp)) % rem;
    }

    bool testRoot(int64_t base, uint32_t b) {
        auto test = utl::BigInteger::from64(base);
        test.root(b);
        return test.toInt64() == int64_t(std::sqrt(base));
    }

    bool testAbs(int64_t left) {
        auto test = utl::BigInteger::from64(left);
        test.abs();
        return test.toInt64() == std::abs(left);
    }

    bool testInv(int64_t left) {
        auto test = utl::BigInteger::from64(left);
        test.inv();
        return test.toInt64() == -left;
    }

    bool testShl(int64_t left, uint32_t off) {
        auto test = utl::BigInteger::from64(left);
        test.shl(off);
        return test.toInt64() == left << off;
    }

    bool testShr(int64_t left, uint32_t off) {
        auto test = utl::BigInteger::from64(left);
        test.shr(off);
        return test.toInt64() == left >> off;
    }

    bool testBeyondInt64() {
        auto test = utl::BigInteger::from64(INT64_MAX);
        if (test.isBeyondInt64()) return false;

        test.add(utl::BigInteger::ONE);
        if (!test.isBeyondInt64()) return false;

        test = utl::BigInteger::from64(INT64_MIN);
        if (test.isBeyondInt64()) return false;

        test.add(utl::BigInteger::from32(-1));
        return test.isBeyondInt64();
    }

    bool testToString(int64_t left) {
        std::string result;
        auto test = utl::BigInteger::from64(left);
        test.toString(10, &result);
        return result == std::to_string(left);
    }

    bool testToStringHex(int64_t left) {
        std::string result;
        auto test = utl::BigInteger::from64(left);
        test.toString(16, &result);
        return result == utl::itos8(left, 16);
    }

    bool testFromStringHex(const std::string& str) {
        std::string result;
        auto test = utl::BigInteger::fromString(str, 16);
        test.toString(16, &result);
        return result == str;
    }

}

namespace utl {
namespace test {

    void TEST_BIG_INTEGER() {
        for (int i = 0; i < 5000; ++i) {
            auto k = BigInteger::fromRandom(i);
            std::string text_k;
            k.toString(16, &text_k);

            auto test1 = BigInteger::fromBytesLE(k.getBytesLE());
            std::string text1_t;
            test1.toString(16, &text1_t);

            auto test2 = BigInteger::fromString(text_k, 16);
            std::string text2_t;
            test2.toString(16, &text2_t);

            ubassert(text_k == text1_t);
            ubassert(text_k == text2_t);
        }

        // To int64
        ubassert(testToInt64(-1));
        ubassert(testToInt64(0));
        ubassert(testToInt64(1));
        ubassert(testToInt64(2));
        ubassert(testToInt64(10));
        ubassert(testToInt64(128));
        ubassert(testToInt64(-128));
        ubassert(testToInt64(65536));
        ubassert(testToInt64(-65536));
        ubassert(testToInt64(654984684858));
        ubassert(testToInt64(-654984684858));

        // Add
        ubassert(testAdd(0, 0));
        ubassert(testAdd(0, 1));
        ubassert(testAdd(1, 1));
        ubassert(testAdd(-1, 0));
        ubassert(testAdd(-1, 1));
        ubassert(testAdd(-1, -1));
        ubassert(testAdd(127, 1));
        ubassert(testAdd(-1, 128));
        ubassert(testAdd(1, -128));
        ubassert(testAdd(128, 0));
        ubassert(testAdd(128, 128));
        ubassert(testAdd(128, -128));
        ubassert(testAdd(-128, 128));
        ubassert(testAdd(-128, -128));
        ubassert(testAdd(5649856, 345346536));
        ubassert(testAdd(-5649856, 345346536));

        // Adds
        ubassert(testAdds(0, 0));
        ubassert(testAdds(0, 1));
        ubassert(testAdds(1, 1));
        ubassert(testAdds(-1, 0));
        ubassert(testAdds(-1, 1));
        ubassert(testAdds(127, 1));
        ubassert(testAdds(-1, 128));
        ubassert(testAdds(128, 0));
        ubassert(testAdds(128, 128));
        ubassert(testAdds(-128, 128));
        ubassert(testAdds(5649856, 345346536));
        ubassert(testAdds(-5649856, 345346536));

        // Sub
        ubassert(testSub(0, 0));
        ubassert(testSub(0, 1));
        ubassert(testSub(1, 0));
        ubassert(testSub(1, 1));
        ubassert(testSub(-1, 1));
        ubassert(testSub(1, -1));
        ubassert(testSub(-1, -1));
        ubassert(testSub(-128, -1));
        ubassert(testSub(-128, 1));
        ubassert(testSub(128, 127));
        ubassert(testSub(128, -127));
        ubassert(testSub(128, -129));
        ubassert(testSub(3458386, 345609497));
        ubassert(testSub(11134583866, 345609497));

        // Subs
        ubassert(testSubs(0, 0));
        ubassert(testSubs(0, 1));
        ubassert(testSubs(1, 0));
        ubassert(testSubs(1, 1));
        ubassert(testSubs(-1, 1));
        ubassert(testSubs(-128, 1));
        ubassert(testSubs(128, 127));
        ubassert(testSubs(3458386, 345609497));
        ubassert(testSubs(11134583866, 345609497));

        // Mul
        ubassert(testMul(0, 0));
        ubassert(testMul(1, 0));
        ubassert(testMul(-1, 0));
        ubassert(testMul(0, 1));
        ubassert(testMul(1, 1));
        ubassert(testMul(-1, 1));
        ubassert(testMul(1, -1));
        ubassert(testMul(-1, -1));
        ubassert(testMul(16, 16));
        ubassert(testMul(16, 16));
        ubassert(testMul(64, 2));
        ubassert(testMul(64, -2));
        ubassert(testMul(32768, 2));
        ubassert(testMul(32768, -2));
        ubassert(testMul(65536, 65535));
        ubassert(testMul(4568456, 234234));
        ubassert(testMul(-4568456, 234234));
        ubassert(testMul(4568456, -234234));
        ubassert(testMul(-4568456, -234234));

        // Muls
        ubassert(testMuls(0, 0));
        ubassert(testMuls(1, 0));
        ubassert(testMuls(-1, 0));
        ubassert(testMuls(0, 1));
        ubassert(testMuls(1, 1));
        ubassert(testMuls(-1, 1));
        ubassert(testMuls(16, 16));
        ubassert(testMuls(16, 16));
        ubassert(testMuls(64, 2));
        ubassert(testMuls(32768, 2));
        ubassert(testMuls(65536, 65535));
        ubassert(testMuls(4568456, 234234));
        ubassert(testMuls(-4568456, 234234));

        // Div
        ubassert(testDivOverflow());
        ubassert(testDiv(0, 1));
        ubassert(testDiv(1, 1));
        ubassert(testDiv(1, -1));
        ubassert(testDiv(0, 2));
        ubassert(testDiv(1, 2));
        ubassert(testDiv(2, 2));
        ubassert(testDiv(-2, 2));
        ubassert(testDiv(-2, -2));
        ubassert(testDiv(128, 2));
        ubassert(testDiv(256, 2));
        ubassert(testDiv(256, 3));
        ubassert(testDiv(1024, 2));
        ubassert(testDiv(65536, 2));
        ubassert(testDiv(65537, 2));
        ubassert(testDiv(65539, 2));
        ubassert(testDiv(65535, 65536));
        ubassert(testDiv(65536, 65535));
        ubassert(testDiv(65536, 65537));
        ubassert(testDiv(65537, 65536));
        ubassert(testDiv(1048612, 2));
        ubassert(testDiv(int64_t(INT32_MAX) + 1, 2));
        ubassert(testDiv(int64_t(INT32_MAX) + 1, 255));
        ubassert(testDiv(int64_t(INT32_MAX) + 347, 2));
        ubassert(testDiv(int64_t(INT32_MAX) + 346459, 2));
        ubassert(testDiv(99000000, 9900));
        ubassert(testDiv(-99000000, 9900));
        ubassert(testDiv(1, 345885486));
        ubassert(testDiv(5484984645, 345885486));
        ubassert(testDiv(-5484984645, 345885486));
        ubassert(testDiv(5484984645, -345885486));
        ubassert(testDiv(200000000000, 20000000001));
        ubassert(testDiv(0, -20000000001));
        ubassert(testDiv(200000000000, -20000000001));
        ubassert(testDiv(4534444444, 453));
        ubassert(testDiv(INT32_MIN, -1));
        ubassert(testDiv(INT32_MIN, 2));
        ubassert(testDiv(INT32_MAX, 2));
        ubassert(testDiv(int64_t(INT32_MAX) + 1, -1));
        ubassert(testDiv(int64_t(INT32_MAX) + 1, 3));
        ubassert(testDiv(int64_t(INT32_MAX) + 1, INT32_MAX - 1));
        ubassert(testDiv(int64_t(INT32_MAX), 2));
        ubassert(testDiv(94856794756945, 1));
        ubassert(testDiv(94856794756945, 94856794756945));
        ubassert(testDiv(94856794756944, 94856794756945));
        ubassert(testDiv(94856794756945 / 2, 94856794756945));
        ubassert(testDiv(119025, 346));

        // Divs
        ubassert(testDivs(0, 1));
        ubassert(testDivs(1, 1));
        ubassert(testDivs(0, 2));
        ubassert(testDivs(1, 2));
        ubassert(testDivs(2, 2));
        ubassert(testDivs(-2, 2));
        ubassert(testDivs(128, 2));
        ubassert(testDivs(256, 2));
        ubassert(testDivs(256, 3));
        ubassert(testDivs(1024, 2));
        ubassert(testDivs(65536, 2));
        ubassert(testDivs(65537, 2));
        ubassert(testDivs(65539, 2));
        ubassert(testDivs(65535, 65536));
        ubassert(testDivs(65536, 65535));
        ubassert(testDivs(65536, 65537));
        ubassert(testDivs(65537, 65536));
        ubassert(testDivs(1048612, 2));
        ubassert(testDivs(int64_t(INT32_MAX) + 1, 2));
        ubassert(testDivs(int64_t(INT32_MAX) + 1, 255));
        ubassert(testDivs(int64_t(INT32_MAX) + 347, 2));
        ubassert(testDivs(int64_t(INT32_MAX) + 346459, 2));
        ubassert(testDivs(99000000, 9900));
        ubassert(testDivs(-99000000, 9900));
        ubassert(testDivs(1, 345885486));
        ubassert(testDivs(5484984645, 345885486));
        ubassert(testDivs(-5484984645, 345885486));
        ubassert(testDivs(4534444444, 453));
        ubassert(testDivs(INT32_MIN, 2));
        ubassert(testDivs(INT32_MAX, 2));
        ubassert(testDivs(int64_t(INT32_MAX) + 1, 3));
        ubassert(testDivs(int64_t(INT32_MAX) + 1, INT32_MAX - 1));
        ubassert(testDivs(int64_t(INT32_MAX), 2));
        ubassert(testDivs(94856794756945, 1));
        ubassert(testDivs(94856794756945, 948567947));
        ubassert(testDivs(94856794756944, 948567947));
        ubassert(testDivs(94856794756945 / 2, 948567947));
        ubassert(testDivs(119025, 346));

        // Abs
        ubassert(testAbs(0));
        ubassert(testAbs(1));
        ubassert(testAbs(-1));
        ubassert(testAbs(128));
        ubassert(testAbs(-128));
        ubassert(testAbs(548745845888));
        ubassert(testAbs(-548745845888));
        ubassert(testAbs(-65536));

        // Inv
        ubassert(testInv(0));
        ubassert(testInv(1));
        ubassert(testInv(-1));
        ubassert(testInv(128));
        ubassert(testInv(-128));
        ubassert(testInv(548745845888));
        ubassert(testInv(-548745845888));
        ubassert(testInv(-65536));

        // Mod
        ubassert(testMod(0, 1));
        ubassert(testMod(1, 1));
        ubassert(testMod(1, 2));
        ubassert(testMod(2, 2));
        ubassert(testMod(-2, 2));
        ubassert(testMod(2, -2));
        ubassert(testMod(-2, -2));
        ubassert(testMod(4, 2));
        ubassert(testMod(8, 2));
        ubassert(testMod(16, 2));
        ubassert(testMod(32, 2));
        ubassert(testMod(64, 2));
        ubassert(testMod(128, 2));
        ubassert(testMod(128, 128));
        ubassert(testMod(1024, 2));
        ubassert(testMod(65536, 128));
        ubassert(testMod(65536, 65535));
        ubassert(testMod(65536, 65537));
        ubassert(testMod(99000000, 9900));
        ubassert(testMod(200000000000, -20000000001));
        ubassert(testMod(356987398567394, 65537));
        ubassert(testMod(356987398567394, 2303840586945));
        ubassert(testMod(94856794756945, 1));
        ubassert(testMod(94856794756945, 94856794756945));
        ubassert(testMod(94856794756944, 94856794756945));
        ubassert(testMod(94856794756945 / 2, 94856794756945));
        ubassert(testMod(INT32_MIN, -1));
        ubassert(testMod(INT32_MIN, 2));
        ubassert(testMod(INT32_MAX, 2));
        ubassert(testMod(int64_t(INT32_MAX) + 1, -1));
        ubassert(testMod(int64_t(INT32_MAX) + 1, 3));
        ubassert(testMod(int64_t(INT32_MAX) + 1, INT32_MAX - 1));
        ubassert(testMod(int64_t(INT32_MAX), 2));

        // Pow
        ubassert(testPow(0, 1));
        ubassert(testPow(1, 1));
        ubassert(testPow(0, 10));
        ubassert(testPow(1, 10));
        ubassert(testPow(0, 5648576));
        ubassert(testPow(1, 5648576));
        ubassert(testPow(2, 1));
        ubassert(testPow(2, 2));
        ubassert(testPow(2, 10));
        ubassert(testPow(2, 11));
        ubassert(testPow(16, 2));
        ubassert(testPow(16, 10));
        ubassert(testPow(348937, 2));
        ubassert(testPow(-348937, 1));
        ubassert(testPow(-348937, 2));
        ubassert(testPow(-34893, 3));
        ubassert(testPow(-348, 6));
        ubassert(testPow(2, 8));
        ubassert(testPow(2, 10));
        ubassert(testPow(2, 15));
        ubassert(testPow(2, 16));
        ubassert(testPow(2, 20));
        ubassert(testPow(2, 31));
        ubassert(testPow(2, 32));
        ubassert(testPow(2, 62));

        // Pow and Mod
        ubassert(testPowMod(0, 1, 1));
        ubassert(testPowMod(0, 1, 2));
        ubassert(testPowMod(1, 1, 2));
        ubassert(testPowMod(-1, 1, 2));
        ubassert(testPowMod(-1, 1, 1));
        ubassert(testPowMod(2, 1, 3));
        ubassert(testPowMod(2, 2, 5));
        ubassert(testPowMod(2, 3, 7));
        ubassert(testPowMod(2, 4, 9));
        ubassert(testPowMod(2, 5, 11));
        ubassert(testPowMod(2, 6, 13));
        ubassert(testPowMod(2, 7, 15));
        ubassert(testPowMod(2, 8, 17));
        ubassert(testPowMod(2, 9, 19));
        ubassert(testPowMod(2, 10, 21));
        ubassert(testPowMod(2, 11, 23));
        ubassert(testPowMod(2, 12, 25));
        ubassert(testPowMod(2, 13, 27));
        ubassert(testPowMod(2, 14, 29));
        ubassert(testPowMod(2, 15, 31));
        ubassert(testPowMod(2, 16, 33));
        ubassert(testPowMod(2, 17, 35));
        ubassert(testPowMod(2, 31, 63));
        ubassert(testPowMod(2, 63, 64));
        ubassert(testPowMod(345, 5, 346));
        ubassert(testPowMod(345, 5, 344));
        ubassert(testPowMod(3450, 2, 3451));
        ubassert(testPowMod(3451, 2, 3452));

        // Sqrt
        ubassert(testRoot(4, 2));
        ubassert(testRoot(9, 2));
        ubassert(testRoot(456897, 2));

        // Shl
        /*ubassert(testShl(0, 0));
        ubassert(testShl(0, 1));
        ubassert(testShl(0, 10));
        ubassert(testShl(0, 100));
        ubassert(testShl(1, 0));
        ubassert(testShl(1, 1));
        ubassert(testShl(1, 2));
        ubassert(testShl(1, 10));
        ubassert(testShl(1, 16));
        ubassert(testShl(3, 4));
        ubassert(testShl(3, 7));
        ubassert(testShl(65536, 5));
        ubassert(testShl(34537485, 3));*/

        // Shr
        /*ubassert(testShr(0, 0));
        ubassert(testShr(0, 1));
        ubassert(testShr(0, 10));
        ubassert(testShr(0, 100));
        ubassert(testShr(1, 0));
        ubassert(testShr(1, 1));
        ubassert(testShr(1, 2));
        ubassert(testShr(1, 10));
        ubassert(testShr(1, 16));
        ubassert(testShr(3, 4));
        ubassert(testShr(3, 7));
        ubassert(testShr(65536, 5));
        ubassert(testShr(34537485, 3));*/

        // Beyond int64
        ubassert(testBeyondInt64());

        // To string
        ubassert(testToString(0));
        ubassert(testToString(1));
        ubassert(testToString(-1));
        ubassert(testToString(2));
        ubassert(testToString(10));
        ubassert(testToString(65535));
        ubassert(testToString(65536));
        ubassert(testToString(-65535));
        ubassert(testToString(-65536));
        ubassert(testToString(100000));
        ubassert(testToString(-100000));
        ubassert(testToString(INT64_MIN));
        ubassert(testToString(INT64_MAX));

        // To string hex
        ubassert(testToStringHex(0));
        ubassert(testToStringHex(1));
        //ubassert(testToStringHex(-1));
        ubassert(testToStringHex(2));
        ubassert(testToStringHex(10));
        ubassert(testToStringHex(65535));
        ubassert(testToStringHex(65536));
        //ubassert(testToStringHex(-65535));
        //ubassert(testToStringHex(-65536));
        ubassert(testToStringHex(100000));
        //ubassert(testToStringHex(-100000));
        //ubassert(testToStringHex(INT64_MIN));
        ubassert(testToStringHex(INT64_MAX));

        // From string hex
        ubassert(testFromStringHex("0"));
        ubassert(testFromStringHex("FFF"));
        ubassert(testFromStringHex("FFFFFFFF"));
        ubassert(testFromStringHex("FFFEFFFF"));
        ubassert(testFromStringHex("8FFEFFFF"));
        ubassert(testFromStringHex("349876536"));
        ubassert(testFromStringHex("456FFFFFFFF"));

        /*auto i = utl::BigInteger::ONE;
        for (auto z = utl::BigInteger::TWO; z.compare(utl::BigInteger::fromU64(99999)) != 0;) {
            i.mul(z);
            z.add(utl::BigInteger::ONE);
        }*/

        /*string8 out;
        if (i.toString(10, &out)) {
            LOG(Log::INFO) << utl::UTF8ToUTF16(out);
        }*/

        {
            auto init = BigInteger::TWO;
            init.pow(1023);
            if (!init.isOdd()) {
                init.add(1);
            }

            int i = 0;
            while (!init.isPrime2(BigInteger::TWO)) {
                init.add(2);
                ++i;
            }

            //      Debug   Release
            // 28:  12.7s   1.6s
            // 30:  5.4s    2.0s
            LOG(Log::INFO) << "Prime retry: " << i;
        }
    }

    void TEST_BYTE_STRING() {
        {
            uint8_t a[] { 0x01, 0x00, 0x64, 0xEB, 0x99 };
            uint8_t b[] { 0x52, 0x0F, 0xF2, 0x11, 0x30, 0x7F };
            uint8_t r[sizeof b];
            ByteString::exor(a, sizeof a, b, sizeof b, r);

            uint8_t t[]{ 0x01 ^ 0x52, 0x00 ^ 0x0F, 0x64 ^ 0xF2, 0xEB ^ 0x11, 0x99 ^ 0x30, 0x7F };
            ubassert(std::memcmp(r, t, sizeof t) == 0);
        }

        {
            uint8_t a[]{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
            uint8_t r[sizeof a];
            ByteString::inc(a, sizeof a, 1, r);

            uint8_t t[]{ 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };
            ubassert(std::memcmp(r, t, sizeof t) == 0);
        }
    }

}
}
