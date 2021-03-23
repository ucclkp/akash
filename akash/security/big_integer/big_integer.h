#ifndef AKASH_SECURITY_BIG_INTEGER_BIG_INTEGER_H_
#define AKASH_SECURITY_BIG_INTEGER_BIG_INTEGER_H_

#include <string>

#include "akash/security/big_integer/int_array.h"


namespace utl {

    // 按照图书：BigNum Math: Implementing Cryptographic Multiple Precision Arithmetic
    // 中的代码编写而成，书中代码来自 LibTomMath 库
    class BigInteger {
    public:
        using Digit = IntArray::Digit;
        using Word = IntArray::Word;

        // Digit 的可用二进制位数
        const static Digit kDigitBitCount = 32;

        // Word 的可用二进制位数
        const static Digit kWordBitCount = 64;

        // kBase 的以2为底的指数
        const static Digit kBaseBitCount = 28;

        // 采用的基（即进制数），必须是2的幂
        const static Digit kBase = 1 << kBaseBitCount;

        // 用于将 (n % kBase) 转换为 (n & kBaseMask)
        const static Digit kBaseMask = kBase - 1;

        const static int kDelta = 1 << (kWordBitCount - 2 * kBaseBitCount);

        static const BigInteger ZERO;
        static const BigInteger ONE;
        static const BigInteger TWO;

        static BigInteger from32(int32_t i);
        static BigInteger from64(int64_t i);
        static BigInteger fromU32(uint32_t i);
        static BigInteger fromU64(uint64_t i);
        static BigInteger fromRandom(uint32_t bit_count);
        static BigInteger fromRandom(const BigInteger& min, const BigInteger& max);
        static BigInteger fromString(const std::string& str, int radix);
        static BigInteger fromBytesBE(const std::string& bytes);
        static BigInteger fromBytesLE(const std::string& bytes);

        BigInteger();

        void zero();
        void swap(BigInteger& rhs);
        void destroy();

        void setInt32(int32_t i);
        void setInt64(int64_t i);
        void setUInt32(uint32_t i);
        void setUInt64(uint64_t i);
        void setBit(uint32_t idx, uint8_t val);

        BigInteger& add(const BigInteger& rhs);
        BigInteger& sub(const BigInteger& rhs);
        BigInteger& mul(const BigInteger& rhs);
        BigInteger& div(const BigInteger& rhs);
        BigInteger& mod(const BigInteger& rhs);
        BigInteger& modP(const BigInteger& rhs);

        BigInteger& add(Digit b);
        BigInteger& sub(Digit b);
        BigInteger& mul(Digit b);
        BigInteger& div(Digit b);

        BigInteger& pow(Digit exp);
        void pow(const BigInteger& exp);
        BigInteger& powMod(const BigInteger& exp, const BigInteger& m);
        BigInteger& abs();
        BigInteger& inv();
        BigInteger& shl(int offset);
        BigInteger& shr(int offset);

        BigInteger& mul2();
        BigInteger& mul2exp(int exp);
        BigInteger& div2();
        BigInteger& div2exp(int exp);
        BigInteger& mod2exp(int exp);
        BigInteger& exp2();
        BigInteger& zweiExp(Digit exp);
        BigInteger& root(Digit b);
        BigInteger& inc(uint32_t b);

        BigInteger& ond(const BigInteger& rhs);
        BigInteger& exor(const BigInteger& rhs);

        BigInteger gcd(const BigInteger& rhs) const;
        BigInteger lcm(const BigInteger& rhs) const;
        // {out} = 1/{this} mod {rhs}
        // {out}*{this} = 1 (mod{rhs})
        // {rhs} >= 2, 0 < {this} < {rhs}
        BigInteger invmod(const BigInteger& rhs) const;

        int compare(const BigInteger& rhs) const;

        BigInteger operator+(const BigInteger& rhs) const;
        BigInteger operator-(const BigInteger& rhs) const;
        BigInteger operator*(const BigInteger& rhs) const;
        BigInteger operator/(const BigInteger& rhs) const;
        BigInteger operator%(const BigInteger& rhs) const;
        BigInteger operator&(const BigInteger& rhs) const;
        BigInteger operator^(const BigInteger& rhs) const;

        BigInteger operator+(Digit b) const;
        BigInteger operator-(Digit b) const;
        BigInteger operator*(Digit b) const;
        BigInteger operator/(Digit b) const;

        bool operator>(const BigInteger& rhs) const;
        bool operator>=(const BigInteger& rhs) const;
        bool operator<(const BigInteger& rhs) const;
        bool operator<=(const BigInteger& rhs) const;
        bool operator==(const BigInteger& rhs) const;

        int64_t toInt64() const;
        uint64_t toUInt64() const;
        void toString(int radix, std::string* str) const;

        int getBitCount() const;
        int getByteCount() const;
        uint8_t getBit(uint32_t idx) const;
        std::string getBytesBE() const;
        std::string getBytesLE() const;

        // 从最高位开始，获取第 idx 个 count 位的大数
        // 未测试
        BigInteger getBitsMSB(uint32_t idx, uint32_t count) const;

        bool isOdd() const;
        bool isZero() const;
        bool isMinus() const;
        bool isBeyondInt64() const;
        bool isBeyondUInt64() const;

        // b > 1
        bool isPrime(const BigInteger& b) const;
        // b > 1
        bool isPrime2(const BigInteger& b) const;

    private:
        static void setDigitItl(IntArray* a, Digit d);
        static int getBitCountItl(const IntArray& a);
        static int getLSBZeroCount(const IntArray& a);

        static void lowAdd(const IntArray& l, const IntArray& r, IntArray* result);
        static void lowSub(const IntArray& l, const IntArray& r, IntArray* result);
        static void lowMulDigs(const IntArray& l, const IntArray& r, int digs, IntArray* result);
        static void lowMulHighDigs(const IntArray& l, const IntArray& r, int digs, IntArray* result);
        static void lowFastMulDigs(const IntArray& l, const IntArray& r, int digs, IntArray* result);
        static void lowSqr(const IntArray& a, IntArray* result);
        static void lowFastSqr(const IntArray& a, IntArray* result);
        static void lowExptmod(const IntArray& g, const IntArray& x, const IntArray& p, IntArray* y, int red_mode);
        static void montgomeryCalNorm(IntArray* a, const IntArray& b);
        static void lowFastExptmod(const IntArray& g, const IntArray& x, const IntArray& p, IntArray* y, int red_mode);

        static void karatsubaMul(const IntArray& l, const IntArray& r, IntArray* result);
        static void toomMul(const IntArray& l, const IntArray& r, IntArray* result);

        static void karatsubaSqr(const IntArray& a, IntArray* result);
        static void toomSqr(const IntArray& a, IntArray* result);

        static int cmpUnsItl(const IntArray& l, const IntArray& r);
        static int cmpItl(const IntArray& l, const IntArray& r);

        static void addItl(const IntArray& l, const IntArray& r, IntArray* result);
        static void subItl(const IntArray& l, const IntArray& r, IntArray* result);
        static void mul2Itl(const IntArray& l, IntArray* result);
        static void div2Itl(const IntArray& l, IntArray* result);
        static void shlItl(int offset, IntArray* result);
        static void shrItl(int offset, IntArray* result);
        static void mul2dItl(const IntArray& l, int exp, IntArray* result);
        static void div2dItl(const IntArray& l, int exp, IntArray* result, IntArray* rem);
        static void mod2dItl(const IntArray& l, int exp, IntArray* result);
        static void mulItl(const IntArray& l, const IntArray& r, IntArray* result);
        static void sqrItl(const IntArray& a, IntArray* result);
        static void exptdItl(const IntArray& a, Digit b, IntArray* result);
        static void zweiExptItl(Digit b, IntArray* result);
        static void exptmodItl(const IntArray& g, const IntArray& x, const IntArray& p, IntArray* y);
        static void divItl(const IntArray& a, const IntArray& b, IntArray* c, IntArray* d);
        static void modItl(const IntArray& a, const IntArray& b, IntArray* c);

        static int cmpdItl(const IntArray& l, Digit r);
        static void adddItl(const IntArray& a, Digit b, IntArray* c);
        static void subdItl(const IntArray& a, Digit b, IntArray* c);
        static void muldItl(const IntArray& a, Digit b, IntArray* c);
        static void div3Itl(const IntArray& a, IntArray* b, Digit* c);
        static void divdItl(const IntArray& a, Digit b, IntArray* c, Digit* d);
        static void rootdItl(IntArray& a, Digit b, IntArray* c);

        static void andItl(const IntArray& l, const IntArray& r, IntArray* result);
        static void xorItl(const IntArray& l, const IntArray& r, IntArray* result);

        // 0 <= x < m^2, m > 1
        static void reduce(IntArray* x, const IntArray& m, const IntArray& mu);
        static void reduceSetup(const IntArray& b, IntArray* mu);

        // 0 <= x < n^2, n > 1
        static void montgomeryReduce(IntArray* x, const IntArray& n, Digit rho);
        static void fastMontgomeryReduce(IntArray* x, const IntArray& n, Digit rho);
        static void montgomerySetup(const IntArray& n, Digit* rho);

        // 0 <= x < n^2, n > 1, 0 < k < Base
        static void drReduce(IntArray* x, const IntArray& n, Digit k);
        static void drSetup(const IntArray& n, Digit* k);
        static bool drIsModulus(const IntArray& n);

        // a >=0, n > 1, 0 < d < Base, (n + d) = 2exp
        static void reduce2k(IntArray* a, const IntArray& n, Digit d);
        static void reduce2kSetup(const IntArray& a, Digit* d);
        static bool reduceIs2k(const IntArray& a);

        // a >=0, n > 1, (n + d) = 2exp
        static void reduce2kl(IntArray* a, const IntArray& n, const IntArray& d);
        static void reduce2klSetup(const IntArray& a, IntArray* d);
        static bool reduceIs2kl(const IntArray& a);

        static bool invmodFast(const IntArray& a, const IntArray& b, IntArray* c);
        static bool invmodSlow(const IntArray& a, const IntArray& b, IntArray* c);

        static void readFromStringItl(const std::string& str, int radix, IntArray* a);
        static void toStringItl(const IntArray& a, int radix, std::string* str);

        static void gcdItl(const IntArray& a, const IntArray& b, IntArray* c);
        static void lcmItl(const IntArray& a, const IntArray& b, IntArray* c);

        // 将 a 的低 s 位加 1，丢弃最高进位
        static void incItl(uint32_t s, IntArray* a);

        // c = 1/a mod b
        // (a, b) = 1, b >= 2, 0 < a < b
        static bool invmodItl(const IntArray& a, const IntArray& b, IntArray* c);

        static bool isPowOf2(Digit b, int* p);

        IntArray int_;
    };

}

#endif  // AKASH_SECURITY_BIG_INTEGER_BIG_INTEGER_H_