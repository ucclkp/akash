// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "big_integer_unit_test.h"

#include <cmath>

#include "utils/convert.h"
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
        return result == utl::toString8Hex(left);
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

            DCHECK(text_k == text1_t);
            DCHECK(text_k == text2_t);
        }

        // To int64
        DCHECK(testToInt64(-1));
        DCHECK(testToInt64(0));
        DCHECK(testToInt64(1));
        DCHECK(testToInt64(2));
        DCHECK(testToInt64(10));
        DCHECK(testToInt64(128));
        DCHECK(testToInt64(-128));
        DCHECK(testToInt64(65536));
        DCHECK(testToInt64(-65536));
        DCHECK(testToInt64(654984684858));
        DCHECK(testToInt64(-654984684858));

        // Add
        DCHECK(testAdd(0, 0));
        DCHECK(testAdd(0, 1));
        DCHECK(testAdd(1, 1));
        DCHECK(testAdd(-1, 0));
        DCHECK(testAdd(-1, 1));
        DCHECK(testAdd(-1, -1));
        DCHECK(testAdd(127, 1));
        DCHECK(testAdd(-1, 128));
        DCHECK(testAdd(1, -128));
        DCHECK(testAdd(128, 0));
        DCHECK(testAdd(128, 128));
        DCHECK(testAdd(128, -128));
        DCHECK(testAdd(-128, 128));
        DCHECK(testAdd(-128, -128));
        DCHECK(testAdd(5649856, 345346536));
        DCHECK(testAdd(-5649856, 345346536));

        // Adds
        DCHECK(testAdds(0, 0));
        DCHECK(testAdds(0, 1));
        DCHECK(testAdds(1, 1));
        DCHECK(testAdds(-1, 0));
        DCHECK(testAdds(-1, 1));
        DCHECK(testAdds(127, 1));
        DCHECK(testAdds(-1, 128));
        DCHECK(testAdds(128, 0));
        DCHECK(testAdds(128, 128));
        DCHECK(testAdds(-128, 128));
        DCHECK(testAdds(5649856, 345346536));
        DCHECK(testAdds(-5649856, 345346536));

        // Sub
        DCHECK(testSub(0, 0));
        DCHECK(testSub(0, 1));
        DCHECK(testSub(1, 0));
        DCHECK(testSub(1, 1));
        DCHECK(testSub(-1, 1));
        DCHECK(testSub(1, -1));
        DCHECK(testSub(-1, -1));
        DCHECK(testSub(-128, -1));
        DCHECK(testSub(-128, 1));
        DCHECK(testSub(128, 127));
        DCHECK(testSub(128, -127));
        DCHECK(testSub(128, -129));
        DCHECK(testSub(3458386, 345609497));
        DCHECK(testSub(11134583866, 345609497));

        // Subs
        DCHECK(testSubs(0, 0));
        DCHECK(testSubs(0, 1));
        DCHECK(testSubs(1, 0));
        DCHECK(testSubs(1, 1));
        DCHECK(testSubs(-1, 1));
        DCHECK(testSubs(-128, 1));
        DCHECK(testSubs(128, 127));
        DCHECK(testSubs(3458386, 345609497));
        DCHECK(testSubs(11134583866, 345609497));

        // Mul
        DCHECK(testMul(0, 0));
        DCHECK(testMul(1, 0));
        DCHECK(testMul(-1, 0));
        DCHECK(testMul(0, 1));
        DCHECK(testMul(1, 1));
        DCHECK(testMul(-1, 1));
        DCHECK(testMul(1, -1));
        DCHECK(testMul(-1, -1));
        DCHECK(testMul(16, 16));
        DCHECK(testMul(16, 16));
        DCHECK(testMul(64, 2));
        DCHECK(testMul(64, -2));
        DCHECK(testMul(32768, 2));
        DCHECK(testMul(32768, -2));
        DCHECK(testMul(65536, 65535));
        DCHECK(testMul(4568456, 234234));
        DCHECK(testMul(-4568456, 234234));
        DCHECK(testMul(4568456, -234234));
        DCHECK(testMul(-4568456, -234234));

        // Muls
        DCHECK(testMuls(0, 0));
        DCHECK(testMuls(1, 0));
        DCHECK(testMuls(-1, 0));
        DCHECK(testMuls(0, 1));
        DCHECK(testMuls(1, 1));
        DCHECK(testMuls(-1, 1));
        DCHECK(testMuls(16, 16));
        DCHECK(testMuls(16, 16));
        DCHECK(testMuls(64, 2));
        DCHECK(testMuls(32768, 2));
        DCHECK(testMuls(65536, 65535));
        DCHECK(testMuls(4568456, 234234));
        DCHECK(testMuls(-4568456, 234234));

        // Div
        DCHECK(testDivOverflow());
        DCHECK(testDiv(0, 1));
        DCHECK(testDiv(1, 1));
        DCHECK(testDiv(1, -1));
        DCHECK(testDiv(0, 2));
        DCHECK(testDiv(1, 2));
        DCHECK(testDiv(2, 2));
        DCHECK(testDiv(-2, 2));
        DCHECK(testDiv(-2, -2));
        DCHECK(testDiv(128, 2));
        DCHECK(testDiv(256, 2));
        DCHECK(testDiv(256, 3));
        DCHECK(testDiv(1024, 2));
        DCHECK(testDiv(65536, 2));
        DCHECK(testDiv(65537, 2));
        DCHECK(testDiv(65539, 2));
        DCHECK(testDiv(65535, 65536));
        DCHECK(testDiv(65536, 65535));
        DCHECK(testDiv(65536, 65537));
        DCHECK(testDiv(65537, 65536));
        DCHECK(testDiv(1048612, 2));
        DCHECK(testDiv(int64_t(INT32_MAX) + 1, 2));
        DCHECK(testDiv(int64_t(INT32_MAX) + 1, 255));
        DCHECK(testDiv(int64_t(INT32_MAX) + 347, 2));
        DCHECK(testDiv(int64_t(INT32_MAX) + 346459, 2));
        DCHECK(testDiv(99000000, 9900));
        DCHECK(testDiv(-99000000, 9900));
        DCHECK(testDiv(1, 345885486));
        DCHECK(testDiv(5484984645, 345885486));
        DCHECK(testDiv(-5484984645, 345885486));
        DCHECK(testDiv(5484984645, -345885486));
        DCHECK(testDiv(200000000000, 20000000001));
        DCHECK(testDiv(0, -20000000001));
        DCHECK(testDiv(200000000000, -20000000001));
        DCHECK(testDiv(4534444444, 453));
        DCHECK(testDiv(INT32_MIN, -1));
        DCHECK(testDiv(INT32_MIN, 2));
        DCHECK(testDiv(INT32_MAX, 2));
        DCHECK(testDiv(int64_t(INT32_MAX) + 1, -1));
        DCHECK(testDiv(int64_t(INT32_MAX) + 1, 3));
        DCHECK(testDiv(int64_t(INT32_MAX) + 1, INT32_MAX - 1));
        DCHECK(testDiv(int64_t(INT32_MAX), 2));
        DCHECK(testDiv(94856794756945, 1));
        DCHECK(testDiv(94856794756945, 94856794756945));
        DCHECK(testDiv(94856794756944, 94856794756945));
        DCHECK(testDiv(94856794756945 / 2, 94856794756945));
        DCHECK(testDiv(119025, 346));

        // Divs
        DCHECK(testDivs(0, 1));
        DCHECK(testDivs(1, 1));
        DCHECK(testDivs(0, 2));
        DCHECK(testDivs(1, 2));
        DCHECK(testDivs(2, 2));
        DCHECK(testDivs(-2, 2));
        DCHECK(testDivs(128, 2));
        DCHECK(testDivs(256, 2));
        DCHECK(testDivs(256, 3));
        DCHECK(testDivs(1024, 2));
        DCHECK(testDivs(65536, 2));
        DCHECK(testDivs(65537, 2));
        DCHECK(testDivs(65539, 2));
        DCHECK(testDivs(65535, 65536));
        DCHECK(testDivs(65536, 65535));
        DCHECK(testDivs(65536, 65537));
        DCHECK(testDivs(65537, 65536));
        DCHECK(testDivs(1048612, 2));
        DCHECK(testDivs(int64_t(INT32_MAX) + 1, 2));
        DCHECK(testDivs(int64_t(INT32_MAX) + 1, 255));
        DCHECK(testDivs(int64_t(INT32_MAX) + 347, 2));
        DCHECK(testDivs(int64_t(INT32_MAX) + 346459, 2));
        DCHECK(testDivs(99000000, 9900));
        DCHECK(testDivs(-99000000, 9900));
        DCHECK(testDivs(1, 345885486));
        DCHECK(testDivs(5484984645, 345885486));
        DCHECK(testDivs(-5484984645, 345885486));
        DCHECK(testDivs(4534444444, 453));
        DCHECK(testDivs(INT32_MIN, 2));
        DCHECK(testDivs(INT32_MAX, 2));
        DCHECK(testDivs(int64_t(INT32_MAX) + 1, 3));
        DCHECK(testDivs(int64_t(INT32_MAX) + 1, INT32_MAX - 1));
        DCHECK(testDivs(int64_t(INT32_MAX), 2));
        DCHECK(testDivs(94856794756945, 1));
        DCHECK(testDivs(94856794756945, 948567947));
        DCHECK(testDivs(94856794756944, 948567947));
        DCHECK(testDivs(94856794756945 / 2, 948567947));
        DCHECK(testDivs(119025, 346));

        // Abs
        DCHECK(testAbs(0));
        DCHECK(testAbs(1));
        DCHECK(testAbs(-1));
        DCHECK(testAbs(128));
        DCHECK(testAbs(-128));
        DCHECK(testAbs(548745845888));
        DCHECK(testAbs(-548745845888));
        DCHECK(testAbs(-65536));

        // Inv
        DCHECK(testInv(0));
        DCHECK(testInv(1));
        DCHECK(testInv(-1));
        DCHECK(testInv(128));
        DCHECK(testInv(-128));
        DCHECK(testInv(548745845888));
        DCHECK(testInv(-548745845888));
        DCHECK(testInv(-65536));

        // Mod
        DCHECK(testMod(0, 1));
        DCHECK(testMod(1, 1));
        DCHECK(testMod(1, 2));
        DCHECK(testMod(2, 2));
        DCHECK(testMod(-2, 2));
        DCHECK(testMod(2, -2));
        DCHECK(testMod(-2, -2));
        DCHECK(testMod(4, 2));
        DCHECK(testMod(8, 2));
        DCHECK(testMod(16, 2));
        DCHECK(testMod(32, 2));
        DCHECK(testMod(64, 2));
        DCHECK(testMod(128, 2));
        DCHECK(testMod(128, 128));
        DCHECK(testMod(1024, 2));
        DCHECK(testMod(65536, 128));
        DCHECK(testMod(65536, 65535));
        DCHECK(testMod(65536, 65537));
        DCHECK(testMod(99000000, 9900));
        DCHECK(testMod(200000000000, -20000000001));
        DCHECK(testMod(356987398567394, 65537));
        DCHECK(testMod(356987398567394, 2303840586945));
        DCHECK(testMod(94856794756945, 1));
        DCHECK(testMod(94856794756945, 94856794756945));
        DCHECK(testMod(94856794756944, 94856794756945));
        DCHECK(testMod(94856794756945 / 2, 94856794756945));
        DCHECK(testMod(INT32_MIN, -1));
        DCHECK(testMod(INT32_MIN, 2));
        DCHECK(testMod(INT32_MAX, 2));
        DCHECK(testMod(int64_t(INT32_MAX) + 1, -1));
        DCHECK(testMod(int64_t(INT32_MAX) + 1, 3));
        DCHECK(testMod(int64_t(INT32_MAX) + 1, INT32_MAX - 1));
        DCHECK(testMod(int64_t(INT32_MAX), 2));

        // Pow
        DCHECK(testPow(0, 1));
        DCHECK(testPow(1, 1));
        DCHECK(testPow(0, 10));
        DCHECK(testPow(1, 10));
        DCHECK(testPow(0, 5648576));
        DCHECK(testPow(1, 5648576));
        DCHECK(testPow(2, 1));
        DCHECK(testPow(2, 2));
        DCHECK(testPow(2, 10));
        DCHECK(testPow(2, 11));
        DCHECK(testPow(16, 2));
        DCHECK(testPow(16, 10));
        DCHECK(testPow(348937, 2));
        DCHECK(testPow(-348937, 1));
        DCHECK(testPow(-348937, 2));
        DCHECK(testPow(-34893, 3));
        DCHECK(testPow(-348, 6));
        DCHECK(testPow(2, 8));
        DCHECK(testPow(2, 10));
        DCHECK(testPow(2, 15));
        DCHECK(testPow(2, 16));
        DCHECK(testPow(2, 20));
        DCHECK(testPow(2, 31));
        DCHECK(testPow(2, 32));
        DCHECK(testPow(2, 62));

        // Pow and Mod
        DCHECK(testPowMod(0, 1, 1));
        DCHECK(testPowMod(0, 1, 2));
        DCHECK(testPowMod(1, 1, 2));
        DCHECK(testPowMod(-1, 1, 2));
        DCHECK(testPowMod(-1, 1, 1));
        DCHECK(testPowMod(2, 1, 3));
        DCHECK(testPowMod(2, 2, 5));
        DCHECK(testPowMod(2, 3, 7));
        DCHECK(testPowMod(2, 4, 9));
        DCHECK(testPowMod(2, 5, 11));
        DCHECK(testPowMod(2, 6, 13));
        DCHECK(testPowMod(2, 7, 15));
        DCHECK(testPowMod(2, 8, 17));
        DCHECK(testPowMod(2, 9, 19));
        DCHECK(testPowMod(2, 10, 21));
        DCHECK(testPowMod(2, 11, 23));
        DCHECK(testPowMod(2, 12, 25));
        DCHECK(testPowMod(2, 13, 27));
        DCHECK(testPowMod(2, 14, 29));
        DCHECK(testPowMod(2, 15, 31));
        DCHECK(testPowMod(2, 16, 33));
        DCHECK(testPowMod(2, 17, 35));
        DCHECK(testPowMod(2, 31, 63));
        DCHECK(testPowMod(2, 63, 64));
        DCHECK(testPowMod(345, 5, 346));
        DCHECK(testPowMod(345, 5, 344));
        DCHECK(testPowMod(3450, 2, 3451));
        DCHECK(testPowMod(3451, 2, 3452));

        // Sqrt
        DCHECK(testRoot(4, 2));
        DCHECK(testRoot(9, 2));
        DCHECK(testRoot(456897, 2));

        // Shl
        /*DCHECK(testShl(0, 0));
        DCHECK(testShl(0, 1));
        DCHECK(testShl(0, 10));
        DCHECK(testShl(0, 100));
        DCHECK(testShl(1, 0));
        DCHECK(testShl(1, 1));
        DCHECK(testShl(1, 2));
        DCHECK(testShl(1, 10));
        DCHECK(testShl(1, 16));
        DCHECK(testShl(3, 4));
        DCHECK(testShl(3, 7));
        DCHECK(testShl(65536, 5));
        DCHECK(testShl(34537485, 3));*/

        // Shr
        /*DCHECK(testShr(0, 0));
        DCHECK(testShr(0, 1));
        DCHECK(testShr(0, 10));
        DCHECK(testShr(0, 100));
        DCHECK(testShr(1, 0));
        DCHECK(testShr(1, 1));
        DCHECK(testShr(1, 2));
        DCHECK(testShr(1, 10));
        DCHECK(testShr(1, 16));
        DCHECK(testShr(3, 4));
        DCHECK(testShr(3, 7));
        DCHECK(testShr(65536, 5));
        DCHECK(testShr(34537485, 3));*/

        // Beyond int64
        DCHECK(testBeyondInt64());

        // To string
        DCHECK(testToString(0));
        DCHECK(testToString(1));
        DCHECK(testToString(-1));
        DCHECK(testToString(2));
        DCHECK(testToString(10));
        DCHECK(testToString(65535));
        DCHECK(testToString(65536));
        DCHECK(testToString(-65535));
        DCHECK(testToString(-65536));
        DCHECK(testToString(100000));
        DCHECK(testToString(-100000));
        DCHECK(testToString(INT64_MIN));
        DCHECK(testToString(INT64_MAX));

        // To string hex
        DCHECK(testToStringHex(0));
        DCHECK(testToStringHex(1));
        //DCHECK(testToStringHex(-1));
        DCHECK(testToStringHex(2));
        DCHECK(testToStringHex(10));
        DCHECK(testToStringHex(65535));
        DCHECK(testToStringHex(65536));
        //DCHECK(testToStringHex(-65535));
        //DCHECK(testToStringHex(-65536));
        DCHECK(testToStringHex(100000));
        //DCHECK(testToStringHex(-100000));
        //DCHECK(testToStringHex(INT64_MIN));
        DCHECK(testToStringHex(INT64_MAX));

        // From string hex
        DCHECK(testFromStringHex("0"));
        DCHECK(testFromStringHex("FFF"));
        DCHECK(testFromStringHex("FFFFFFFF"));
        DCHECK(testFromStringHex("FFFEFFFF"));
        DCHECK(testFromStringHex("8FFEFFFF"));
        DCHECK(testFromStringHex("349876536"));
        DCHECK(testFromStringHex("456FFFFFFFF"));

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
            DCHECK(std::memcmp(r, t, sizeof t) == 0);
        }

        {
            uint8_t a[]{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
            uint8_t r[sizeof a];
            ByteString::inc(a, sizeof a, 1, r);

            uint8_t t[]{ 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };
            DCHECK(std::memcmp(r, t, sizeof t) == 0);
        }
    }

}
}
