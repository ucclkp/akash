#include "big_integer.h"

#include <random>

#include "utils/log.h"
#include "utils/numbers.hpp"

#define MP_WARRAY  65536

#define TOOM_MUL_CUTOFF  800
#define KARATSUBA_MUL_CUTOFF  70

#define TOOM_SQR_CUTOFF  800
#define KARATSUBA_SQR_CUTOFF  70

#define TAB_SIZE  256

#define MP_MIN(a, b)  (((a) <= (b)) ? (a) : (b))
#define MP_MAX(a, b)  (((a) >= (b)) ? (a) : (b))


namespace {

    const char kBase64CharMap[]{
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
        'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
        'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
        'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
        'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
        'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
        'u', 'v', 'w', 'x', 'y', 'z', '+', '/',
    };

}


namespace utl {

    const BigInteger BigInteger::ZERO = fromU32(0);
    const BigInteger BigInteger::ONE = fromU32(1);
    const BigInteger BigInteger::TWO = fromU32(2);

    BigInteger BigInteger::from32(int32_t i) {
        BigInteger bi;
        bi.setInt32(i);
        return bi;
    }

    BigInteger BigInteger::from64(int64_t i) {
        BigInteger bi;
        bi.setInt64(i);
        return bi;
    }

    BigInteger BigInteger::fromU32(uint32_t i) {
        BigInteger bi;
        bi.setUInt32(i);
        return bi;
    }

    BigInteger BigInteger::fromU64(uint64_t i) {
        BigInteger bi;
        bi.setUInt64(i);
        return bi;
    }

    BigInteger BigInteger::fromRandom(uint32_t bit_count) {
        uint32_t unit_count = bit_count / kBaseBitCount;
        uint32_t rem_count = bit_count % kBaseBitCount;

        auto max = std::numeric_limits<Digit>::max() & kBaseMask;

        std::random_device rd;
        std::default_random_engine en(rd());
        std::uniform_int_distribution<Digit> dig_dist(0U, max);

        BigInteger result;
        result.int_.grow(unit_count + 1);
        result.int_.used_ = unit_count + 1;

        uint32_t i;
        for (i = 0; i < unit_count; ++i) {
            result.int_.buf_[i] = dig_dist(en);
        }

        if (rem_count) {
            auto rem_max = (Digit(1) << rem_count) - 1;
            std::uniform_int_distribution<Digit> rem_dist(0U, rem_max);
            Digit rem = rem_dist(en);
            rem |= Digit(1) << (rem_count - 1);
            result.int_.buf_[i] = rem;
        } else {
            if (unit_count > 0) {
                result.int_.buf_[i - 1] |= Digit(1) << (kBaseBitCount - 1);
            }
        }

        result.int_.shrink();
        return result;
    }

    BigInteger BigInteger::fromRandom(const BigInteger& min, const BigInteger& max) {
        BigInteger mid(max - min);
        auto digit_max = std::numeric_limits<Digit>::max() & kBaseMask;
        auto mid_used = mid.int_.used_;

        BigInteger result;
        result.int_.grow(mid_used);
        result.int_.used_ = mid_used;

        std::random_device rd;
        std::default_random_engine en(rd());
        std::uniform_int_distribution<Digit> dig_dist(0U, digit_max);

        for (int i = 0; i < mid_used - 1; ++i) {
            result.int_.buf_[i] = dig_dist(en);
        }

        if (mid_used > 0) {
            std::uniform_int_distribution<Digit> rem_dist(0U, mid.int_.buf_[mid_used - 1]);
            result.int_.buf_[mid_used - 1] = rem_dist(en);
        }
        result.int_.shrink();
        result.add(min);
        return result;
    }

    BigInteger BigInteger::fromString(const std::string& str, int radix) {
        BigInteger tmp;
        readFromStringItl(str, radix, &tmp.int_);
        return tmp;
    }

    BigInteger BigInteger::fromBytesBE(const std::string& bytes) {
        std::string tmp(bytes);
        std::reverse(tmp.begin(), tmp.end());
        return fromBytesLE(tmp);
    }

    BigInteger BigInteger::fromBytesLE(const std::string& bytes) {
        int byte_cnt = num_cast<int>(bytes.size());
        int total_bits = byte_cnt * 8;
        int total_base = (total_bits + kBaseBitCount - 1) / kBaseBitCount;

        BigInteger r;
        auto& tint = r.int_;
        tint.grow(total_base);
        tint.used_ = total_base;

        int rem = 0;
        int idx = 0;
        for (int i = 0; i < total_base; ++i) {
            if (rem > 0) {
                if (rem >= int(kBaseBitCount)) {
                    tint.buf_[i] |= uint8_t(bytes[idx]) >> (8 - rem);
                    rem -= kBaseBitCount;
                    continue;
                }
                tint.buf_[i] |= uint8_t(bytes[idx]) >> (8 - rem);
                ++idx;
            }

            int j;
            for (j = 0; j < (int(kBaseBitCount) - rem) / 8; ++j, ++idx) {
                if (idx >= byte_cnt) {
                    tint.shrink();
                    return r;
                }
                tint.buf_[i] |= Digit(uint8_t(bytes[idx])) << (j * 8 + rem);
            }

            int cur_rem = (kBaseBitCount - rem) % 8;
            if (cur_rem > 0) {
                if (idx >= byte_cnt) {
                    tint.shrink();
                    return r;
                }
                tint.buf_[i] |= Digit(uint8_t(bytes[idx]) & ((1 << cur_rem) - 1)) << (j * 8 + rem);
                rem = 8 - cur_rem;
            } else {
                rem = 0;
            }
        }

        tint.shrink();
        return r;
    }

    BigInteger::BigInteger() {
    }

    void BigInteger::zero() {
        int_.zero();
    }

    void BigInteger::swap(BigInteger& rhs) {
        int_.swap(&rhs.int_);
    }

    void BigInteger::destroy() {
        int_.destroy();
    }

    void BigInteger::setInt32(int32_t i) {
        if (i >= 0) {
            setUInt32(static_cast<uint32_t>(i));
        } else {
            setUInt32(~static_cast<uint32_t>(i) + 1);
            inv();
        }
    }

    void BigInteger::setInt64(int64_t i) {
        if (i >= 0) {
            setUInt64(static_cast<uint64_t>(i));
        } else {
            setUInt64(~static_cast<uint64_t>(i) + 1);
            inv();
        }
    }

    void BigInteger::setUInt32(uint32_t i) {
        int_.zero();
        for (int n = 0; n < 8; ++n) {
            mul2dItl(int_, 4, &int_);
            int_.buf_[0] |= (i >> 28) & 15;
            i <<= 4;
            ++int_.used_;
        }
        int_.shrink();
    }

    void BigInteger::setUInt64(uint64_t i) {
        int_.zero();
        for (int n = 0; n < 16; ++n) {
            mul2dItl(int_, 4, &int_);
            int_.buf_[0] |= (i >> 60) & 15;
            i <<= 4;
            ++int_.used_;
        }
        int_.shrink();
    }

    void BigInteger::setBit(uint32_t idx, uint8_t val) {
        auto pos = idx / kBaseBitCount;
        auto off = idx % kBaseBitCount;
        if (int(pos) >= int_.used_) {
            int_.grow(pos + 1);
            int_.used_ = pos + 1;
        }
        if (val & 1) {
            int_.buf_[pos] |= Digit(1) << off;
        } else {
            int_.buf_[pos] &= ~(Digit(1) << off);
            int_.shrink();
        }
    }

    BigInteger& BigInteger::add(const BigInteger& rhs) {
        addItl(int_, rhs.int_, &int_);
        return *this;
    }

    BigInteger& BigInteger::sub(const BigInteger& rhs) {
        subItl(int_, rhs.int_, &int_);
        return *this;
    }

    BigInteger& BigInteger::mul(const BigInteger& rhs) {
        mulItl(int_, rhs.int_, &int_);
        return *this;
    }

    BigInteger& BigInteger::div(const BigInteger& rhs) {
        divItl(int_, rhs.int_, &int_, nullptr);
        return *this;
    }

    BigInteger& BigInteger::mod(const BigInteger& rhs) {
        modItl(int_, rhs.int_, &int_);
        return *this;
    }

    BigInteger& BigInteger::modP(const BigInteger& rhs) {
        modItl(int_, rhs.int_, &int_);
        if (int_.is_minus_) {
            addItl(int_, rhs.int_, &int_);
        }
        return *this;
    }

    BigInteger& BigInteger::add(Digit b) {
        adddItl(int_, b, &int_);
        return *this;
    }

    BigInteger& BigInteger::sub(Digit b) {
        subdItl(int_, b, &int_);
        return *this;
    }

    BigInteger& BigInteger::mul(Digit b) {
        muldItl(int_, b, &int_);
        return *this;
    }

    BigInteger& BigInteger::div(Digit b) {
        divdItl(int_, b, &int_, nullptr);
        return *this;
    }

    BigInteger& BigInteger::pow(Digit exp) {
        exptdItl(int_, exp, &int_);
        return *this;
    }

    void BigInteger::pow(const BigInteger& exp) {
        // TODO:
    }

    BigInteger& BigInteger::powMod(const BigInteger& exp, const BigInteger& m) {
        exptmodItl(int_, exp.int_, m.int_, &int_);
        return *this;
    }

    BigInteger& BigInteger::abs() {
        int_.abs();
        return *this;
    }

    BigInteger& BigInteger::inv() {
        int_.inv();
        return *this;
    }

    BigInteger& BigInteger::shl(int offset) {
        shlItl(offset, &int_);
        return *this;
    }

    BigInteger& BigInteger::shr(int offset) {
        shrItl(offset, &int_);
        return *this;
    }

    BigInteger& BigInteger::mul2() {
        mul2Itl(int_, &int_);
        return *this;
    }

    BigInteger& BigInteger::mul2exp(int exp) {
        mul2dItl(int_, exp, &int_);
        return *this;
    }

    BigInteger& BigInteger::div2() {
        div2Itl(int_, &int_);
        return *this;
    }

    BigInteger& BigInteger::div2exp(int exp) {
        div2dItl(int_, exp, &int_, nullptr);
        return *this;
    }

    BigInteger& BigInteger::mod2exp(int exp) {
        mod2dItl(int_, exp, &int_);
        return *this;
    }

    BigInteger& BigInteger::exp2() {
        sqrItl(int_, &int_);
        return *this;
    }

    BigInteger& BigInteger::zweiExp(Digit exp) {
        zweiExptItl(exp, &int_);
        return *this;
    }

    BigInteger& BigInteger::root(Digit b) {
        rootdItl(int_, b, &int_);
        return *this;
    }

    BigInteger& BigInteger::inc(uint32_t b) {
        incItl(b, &int_);
        return *this;
    }

    BigInteger& BigInteger::ond(const BigInteger& rhs) {
        andItl(int_, rhs.int_, &int_);
        return *this;
    }

    BigInteger& BigInteger::exor(const BigInteger& rhs) {
        xorItl(int_, rhs.int_, &int_);
        return *this;
    }

    BigInteger BigInteger::gcd(const BigInteger& rhs) const {
        BigInteger tmp;
        gcdItl(int_, rhs.int_, &tmp.int_);
        return tmp;
    }

    BigInteger BigInteger::lcm(const BigInteger& rhs) const {
        BigInteger tmp;
        lcmItl(int_, rhs.int_, &tmp.int_);
        return tmp;
    }

    BigInteger BigInteger::invmod(const BigInteger& rhs) const {
        BigInteger tmp;
        if (!invmodItl(int_, rhs.int_, &tmp.int_)) {
            ubassert(false);
        }
        return tmp;
    }

    int BigInteger::compare(const BigInteger& rhs) const {
        return cmpItl(int_, rhs.int_);
    }

    BigInteger BigInteger::operator+(const BigInteger& rhs) const {
        BigInteger tmp(*this);
        tmp.add(rhs);
        return tmp;
    }

    BigInteger BigInteger::operator-(const BigInteger& rhs) const {
        BigInteger tmp(*this);
        tmp.sub(rhs);
        return tmp;
    }

    BigInteger BigInteger::operator*(const BigInteger& rhs) const {
        BigInteger tmp(*this);
        tmp.mul(rhs);
        return tmp;
    }

    BigInteger BigInteger::operator/(const BigInteger& rhs) const {
        BigInteger tmp(*this);
        tmp.div(rhs);
        return tmp;
    }

    BigInteger BigInteger::operator%(const BigInteger& rhs) const {
        BigInteger tmp(*this);
        tmp.mod(rhs);
        return tmp;
    }

    BigInteger BigInteger::operator&(const BigInteger& rhs) const {
        BigInteger tmp(*this);
        tmp.ond(rhs);
        return tmp;
    }

    BigInteger BigInteger::operator^(const BigInteger& rhs) const {
        BigInteger tmp(*this);
        tmp.exor(rhs);
        return tmp;
    }

    BigInteger BigInteger::operator+(Digit b) const {
        BigInteger tmp(*this);
        tmp.add(b);
        return tmp;
    }

    BigInteger BigInteger::operator-(Digit b) const {
        BigInteger tmp(*this);
        tmp.sub(b);
        return tmp;
    }

    BigInteger BigInteger::operator*(Digit b) const {
        BigInteger tmp(*this);
        tmp.mul(b);
        return tmp;
    }

    BigInteger BigInteger::operator/(Digit b) const {
        BigInteger tmp(*this);
        tmp.div(b);
        return tmp;
    }

    bool BigInteger::operator>(const BigInteger& rhs) const {
        return compare(rhs) > 0;
    }

    bool BigInteger::operator>=(const BigInteger& rhs) const {
        return compare(rhs) >= 0;
    }

    bool BigInteger::operator<(const BigInteger& rhs) const {
        return compare(rhs) < 0;
    }

    bool BigInteger::operator<=(const BigInteger& rhs) const {
        return compare(rhs) <= 0;
    }

    bool BigInteger::operator==(const BigInteger& rhs) const {
        return compare(rhs) == 0;
    }

    int64_t BigInteger::toInt64() const {
        uint64_t val = toUInt64();
        if (int_.isMinus()) {
            return static_cast<int64_t>(~val + 1);
        }
        return static_cast<int64_t>(val);
    }

    uint64_t BigInteger::toUInt64() const {
        uint64_t result = 0;
        int remain = 64;
        for (int i = 0; i < int_.used_ && remain > 0; ++i) {
            if (remain - int(kBaseBitCount) >= 0) {
                remain -= int(kBaseBitCount);
                result |= uint64_t(int_.buf_[i]) << (i * kBaseBitCount);
            } else {
                result |= uint64_t(int_.buf_[i] & uint64_t((1 << remain) - 1)) << (i * kBaseBitCount);
                remain = 0;
            }
        }
        return result;
    }

    void BigInteger::toString(int radix, std::string* str) const {
        toStringItl(int_, radix, str);
    }

    int BigInteger::getBitCount() const {
        return getBitCountItl(int_);
    }

    int BigInteger::getByteCount() const {
        return (getBitCountItl(int_) + 7) / 8;
    }

    uint8_t BigInteger::getBit(uint32_t idx) const {
        auto pos = idx / kBaseBitCount;
        auto off = idx % kBaseBitCount;
        return (int_.buf_[pos] >> off) & 0x1;
    }

    std::string BigInteger::getBytesBE() const {
        auto be = getBytesLE();
        std::reverse(be.begin(), be.end());
        return be;
    }

    std::string BigInteger::getBytesLE() const {
        int rem = 0;
        uint8_t tmp = 0;
        std::string result;
        for (int i = 0; i < int_.used_; ++i) {
            if (rem > 0) {
                if (rem >= int(kBaseBitCount)) {
                    tmp |= (int_.buf_[i] & kBaseMask) << (8 - rem);
                    rem -= kBaseBitCount;
                    continue;
                }
                tmp |= (int_.buf_[i] & ((Digit(1) << rem) - 1)) << (8 - rem);
                result.push_back(tmp);
            }

            int j;
            for (j = 0; j < (int(kBaseBitCount) - rem) / 8; ++j) {
                tmp = (int_.buf_[i] >> (j * 8 + rem)) & 0xFF;
                result.push_back(tmp);
            }

            int cur_rem = (kBaseBitCount - rem) % 8;
            if (cur_rem > 0) {
                tmp = (int_.buf_[i] >> (j * 8 + rem)) & ((Digit(1) << cur_rem) - 1);
                rem = 8 - cur_rem;
            } else {
                tmp = 0;
                rem = 0;
            }

            if (i + 1 == int_.used_ && tmp > 0) {
                result.push_back(tmp);
            }
        }

        while (!result.empty() && result.back() == 0) {
            result.pop_back();
        }

        return result;
    }

    BigInteger BigInteger::getBitsMSB(uint32_t idx, uint32_t count) const {
        BigInteger out(*this);

        auto total = getBitCount();
        int skip_bit_cnt = idx * count;

        int skip_base_cnt = out.int_.used_ - (total - skip_bit_cnt + kBaseBitCount - 1) / kBaseBitCount;
        int rem_off = (total - skip_bit_cnt) % kBaseBitCount;
        for (int i = 0; i < skip_base_cnt; ++i) {
            int cur = out.int_.used_ - 1 - i;
            if (cur < 0) {
                return out;
            }
            out.int_.buf_[cur] = 0;
        }

        if (rem_off > 0) {
            int cur = out.int_.used_ - 1 - skip_base_cnt;
            if (cur < 0) {
                return out;
            }
            auto tmp = out.int_.buf_[cur];
            tmp &= (Digit(1) << rem_off) - 1;
            out.int_.buf_[cur] = tmp;
        }

        out.int_.shrink();
        out.div2exp(MP_MAX(total - count - skip_bit_cnt, 0));
        return out;
    }

    bool BigInteger::isOdd() const {
        return int_.isOdd();
    }

    bool BigInteger::isZero() const {
        return int_.isZero();
    }

    bool BigInteger::isMinus() const {
        return int_.isMinus();
    }

    bool BigInteger::isBeyondInt64() const {
        int bit_count = getBitCountItl(int_);
        if (bit_count < 64) {
            return false;
        }
        if (bit_count > 64) {
            return true;
        }

        auto val = toUInt64();

        if (!int_.is_minus_ && (val & (uint64_t(1) << 63))) {
            return true;
        }
        if (int_.is_minus_ && (val & (uint64_t(1) << 63)) && (val & ~(uint64_t(1) << 63))) {
            return true;
        }
        return false;
    }

    bool BigInteger::isBeyondUInt64() const {
        if (getBitCountItl(int_) > 64) {
            return true;
        }
        return false;
    }

    bool BigInteger::isPrime(const BigInteger& b) const {
        IntArray n1(int_);
        subdItl(n1, 1, &n1);

        IntArray r(n1);
        int s = getLSBZeroCount(r);

        div2dItl(r, s, &r, nullptr);

        IntArray y;
        exptmodItl(b.int_, r, int_, &y);

        if (cmpdItl(y, 1) != 0 && cmpItl(y, n1) != 0) {
            int j = 1;
            while (j <= (s - 1) && cmpItl(y, n1) != 0) {
                IntArray t;
                sqrItl(y, &t);
                modItl(t, int_, &y);

                if (cmpdItl(y, 1) == 0) {
                    return false;
                }
                ++j;
            }

            if (cmpItl(y, n1) != 0) {
                return false;
            }
        }
        return true;
    }

    bool BigInteger::isPrime2(const BigInteger& b) const {
        IntArray n1(b.int_);
        IntArray bi_1;
        subdItl(int_, 1, &bi_1);
        IntArray exp(bi_1);

        while (!exp.isOdd()) {
            div2Itl(exp, &exp);
            exptmodItl(n1, exp, int_, &n1);
            if (cmpItl(n1, bi_1) == 0) {
                break;
            }
            if (cmpdItl(n1, 1) == 0) {
                continue;
            }
            return false;
        }
        return true;
    }

    void BigInteger::setDigitItl(IntArray* a, Digit d) {
        a->zero();
        a->buf_[0] = d & kBaseMask;
        a->used_ = (a->buf_[0] != 0) ? 1 : 0;
    }

    int BigInteger::getBitCountItl(const IntArray& a) {
        int count = 0;
        if (a.used_ > 1) {
            count = (a.used_ - 1) * kBaseBitCount;
        } else if (a.used_ == 0) {
            return 0;
        }

        int i;
        auto top = a.buf_[a.used_ - 1];
        for (i = kBaseBitCount - 1; i >= 0; --i) {
            if (top & (Digit(1) << i)) {
                break;
            }
        }
        return count + i + 1;
    }

    int BigInteger::getLSBZeroCount(const IntArray& a) {
        for (int i = 0; i < a.used_; ++i) {
            auto d = a.buf_[i];
            if (d == 0) {
                continue;
            }
            for (int j = 0; j < int(kBaseBitCount); ++j) {
                if (d & (1 << j)) {
                    return i * int(kBaseBitCount) + j;
                }
            }
        }
        return a.used_ * int(kBaseBitCount);
    }

    void BigInteger::lowAdd(const IntArray& l, const IntArray& r, IntArray* result) {
        int i, min, max;
        const IntArray* x;
        if (l.used_ > r.used_) {
            min = r.used_;
            max = l.used_;
            x = &l;
        } else {
            min = l.used_;
            max = r.used_;
            x = &r;
        }

        if (result->alloc_ < max + 1) {
            result->grow(max + 1);
        }

        auto old_used = result->used_;
        result->used_ = max + 1;

        Digit over = 0;
        for (i = 0; i < min; ++i) {
            result->buf_[i] = l.buf_[i] + r.buf_[i] + over;
            over = result->buf_[i] >> kBaseBitCount;
            result->buf_[i] &= kBaseMask;
        }

        if (min != max) {
            for (; i < max; ++i) {
                result->buf_[i] = x->buf_[i] + over;
                over = result->buf_[i] >> kBaseBitCount;
                result->buf_[i] &= kBaseMask;
            }
        }

        result->buf_[max] = over;

        for (i = result->used_; i < old_used; ++i) {
            result->buf_[i] = 0;
        }
        result->shrink();
    }

    void BigInteger::lowSub(const IntArray& l, const IntArray& r, IntArray* result) {
        int i;
        auto min = r.used_;
        auto max = l.used_;

        if (result->alloc_ < max) {
            result->grow(max);
        }

        auto old_used = result->used_;
        result->used_ = max;

        Digit over = 0;
        for (i = 0; i < min; ++i) {
            result->buf_[i] = l.buf_[i] - r.buf_[i] - over;
            over = result->buf_[i] >> (kDigitBitCount - 1);
            result->buf_[i] &= kBaseMask;
        }

        for (; i < max; ++i) {
            result->buf_[i] = l.buf_[i] - over;
            over = result->buf_[i] >> (kDigitBitCount - 1);
            result->buf_[i] &= kBaseMask;
        }

        for (i = max; i < old_used; ++i) {
            result->buf_[i] = 0;
        }
        result->shrink();
    }

    void BigInteger::lowMulDigs(const IntArray& l, const IntArray& r, int digs, IntArray* result) {
        if (digs < MP_WARRAY &&
            MP_MIN(l.used_, r.used_) < kDelta)
        {
            lowFastMulDigs(l, r, digs, result);
            return;
        }

        IntArray t(digs);
        t.used_ = digs;

        for (int i = 0; i < l.used_; ++i) {
            Digit u = 0;
            int pb = MP_MIN(r.used_, digs - i);
            if (pb < 1) {
                break;
            }

            for (int j = 0; j < pb; ++j) {
                Word wd = t.buf_[i + j] + Word(l.buf_[i]) * r.buf_[j] + u;
                t.buf_[i + j] = wd & kBaseMask;
                u = Digit(wd >> kBaseBitCount);
            }

            if (i + pb < digs) {
                t.buf_[i + pb] = u;
            }
        }

        t.shrink();
        *result = std::move(t);
    }

    void BigInteger::lowMulHighDigs(const IntArray& l, const IntArray& r, int digs, IntArray* result) {
        IntArray t(l.used_ + r.used_ + 1);
        t.used_ = l.used_ + r.used_ + 1;

        for (int i = 0; i < l.used_; ++i) {
            int j;
            int k;
            Digit u = 0;
            for (j = digs - i, k = 0; j < r.used_; ++j, ++k) {
                Word wd = t.buf_[digs + k] + Word(l.buf_[i]) * r.buf_[digs - i + k] + u;
                t.buf_[digs + k] = wd & kBaseMask;
                u = Digit(wd >> kBaseBitCount);
            }

            t.buf_[digs + k] = u;
        }

        t.shrink();
        *result = std::move(t);
    }

    void BigInteger::lowFastMulDigs(const IntArray& l, const IntArray& r, int digs, IntArray* result) {
        Digit w[MP_WARRAY];

        if (result->alloc_ < digs) {
            result->grow(digs);
        }

        int i;
        int pa = MP_MIN(digs, l.used_ + r.used_);
        Word _w = 0;

        for (i = 0; i < pa; ++i) {
            int ty = MP_MIN(r.used_ - 1, i);
            int tx = i - ty;
            int j = MP_MIN(l.used_ - tx, ty + 1);

            auto tmpl = l.buf_ + tx;
            auto tmpr = r.buf_ + ty;
            for (int k = 0; k < j; ++k) {
                _w += Word(*tmpl++) * (*tmpr--);
            }

            w[i] = _w & kBaseMask;
            _w >>= kBaseBitCount;
        }

        int old_used = result->used_;
        result->used_ = digs;

        for (i = 0; i < pa; ++i) {
            result->buf_[i] = w[i];
        }

        for (; i < old_used; ++i) {
            result->buf_[i] = 0;
        }

        result->shrink();
    }

    void BigInteger::lowSqr(const IntArray& a, IntArray* result) {
        IntArray t(2 * a.used_ + 1);
        t.used_ = 2 * a.used_ + 1;

        for (int i = 0; i < a.used_; ++i) {
            // 算平方
            Word r = t.buf_[i << 1] + Word(a.buf_[i]) * a.buf_[i];
            t.buf_[2 * i] = r & kBaseMask;

            // 算二重积
            int j;
            Digit u = Digit(r >> kBaseBitCount);
            for (j = i + 1; j < a.used_; ++j) {
                r = 2 * Word(a.buf_[i]) * a.buf_[j] + t.buf_[i + j] + u;
                t.buf_[i + j] = r & kBaseMask;
                u = Digit(r >> kBaseBitCount);
            }

            // 算最后一个进位
            while (u > 0) {
                r = t.buf_[i + j] + u;
                t.buf_[i + j] = r & kBaseMask;
                u = Digit(r >> kBaseBitCount);
                ++j;
            }
        }

        t.shrink();
        *result = std::move(t);
    }

    void BigInteger::lowFastSqr(const IntArray& a, IntArray* result) {
        Digit W[MP_WARRAY];

        int pa = a.used_ << 1;
        if (result->alloc_ < pa) {
            result->grow(pa);
        }

        Word W1 = 0;
        for (int i = 0; i < pa; ++i) {
            Word _W = 0;
            int ty = MP_MIN(a.used_ - 1, i);
            int tx = i - ty;
            int j = MP_MIN(a.used_ - tx, ty + 1);
            j = MP_MIN(j, (ty - tx + 1) >> 1);

            auto tmpl = a.buf_ + tx;
            auto tmpr = a.buf_ + ty;
            for (int k = 0; k < j; ++k) {
                _W += Word(*tmpl++) * Word(*tmpr--);
            }

            _W = 2 * _W + W1;
            if ((i & 1) == 0) {
                _W += Word(a.buf_[i >> 1]) * a.buf_[i >> 1];
            }

            W[i] = _W & kBaseMask;
            W1 = _W >> kBaseBitCount;
        }

        int old_used = result->used_;
        result->used_ = a.used_ << 1;
        for (int i = 0; i < pa; ++i) {
            result->buf_[i] = W[i] & kBaseMask;
        }
        for (int i = pa; i < old_used; ++i) {
            result->buf_[i] = 0;
        }

        result->shrink();
    }

    void BigInteger::lowExptmod(
        const IntArray& g, const IntArray& x, const IntArray& p, IntArray* y, int red_mode)
    {
        IntArray M[TAB_SIZE];
        using reduceMethod = void(*)(IntArray*, const IntArray&, const IntArray&);
        reduceMethod redux;

        int win_size;
        int i = getBitCountItl(x);
        if (i <= 7) {
            win_size = 2;
        } else if (i <= 36) {
            win_size = 3;
        } else if (i <= 140) {
            win_size = 4;
        } else if (i <= 450) {
            win_size = 5;
        } else if (i <= 1303) {
            win_size = 6;
        } else if (i <= 3529) {
            win_size = 7;
        } else {
            win_size = 8;
        }

        IntArray mu;
        if (red_mode == 0) {
            reduceSetup(p, &mu);
            redux = reduce;
        } else {
            reduce2klSetup(p, &mu);
            redux = reduce2kl;
        }
        modItl(g, p, &M[1]);

        M[1 << (win_size - 1)] = M[1];
        for (i = 0; i < win_size - 1; ++i) {
            sqrItl(M[1 << (win_size - 1)], &M[1 << (win_size - 1)]);
            redux(&M[1 << (win_size - 1)], p, mu);
        }

        for (i = (1 << (win_size - 1)) + 1; i < (1 << win_size); ++i) {
            mulItl(M[i - 1], M[1], &M[i]);
            redux(&M[i], p, mu);
        }

        IntArray res;
        setDigitItl(&res, 1);

        int mode = 0;
        int bitcnt = 1;
        Digit buf = 0;
        int digitx = x.used_ - 1;
        int bitcpy = 0;
        int bitbuf = 0;

        for (;;) {
            if (--bitcnt == 0) {
                if (digitx == -1) {
                    break;
                }

                buf = x.buf_[digitx--];
                bitcnt = kBaseBitCount;
            }

            int _y = (buf >> (kBaseBitCount - 1)) & 1;
            buf <<= 1;

            if (mode == 0 && _y == 0) {
                continue;
            }

            if (mode == 1 && _y == 0) {
                sqrItl(res, &res);
                redux(&res, p, mu);
                continue;
            }

            ++bitcpy;
            bitbuf |= _y << (win_size - bitcpy);
            mode = 2;

            if (bitcpy == win_size) {
                for (i = 0; i < win_size; ++i) {
                    sqrItl(res, &res);
                    redux(&res, p, mu);
                }

                mulItl(res, M[bitbuf], &res);
                redux(&res, p, mu);

                bitcpy = 0;
                bitbuf = 0;
                mode = 1;
            }
        }

        if (mode == 2 && bitcpy > 0) {
            for (i = 0; i < bitcpy; ++i) {
                sqrItl(res, &res);
                redux(&res, p, mu);

                bitbuf <<= 1;
                if (bitbuf & (1 << win_size)) {
                    mulItl(res, M[1], &res);
                    redux(&res, p, mu);
                }
            }
        }

        *y = std::move(res);
    }

    void BigInteger::montgomeryCalNorm(IntArray* a, const IntArray& b) {
        int bits = getBitCountItl(b) % kBaseBitCount;
        if (b.used_ > 1) {
            zweiExptItl((b.used_ - 1)*kBaseBitCount + bits - 1, a);
        } else {
            setDigitItl(a, 1);
            bits = 1;
        }

        for (int i = bits - 1; i<int(kBaseBitCount); ++i) {
            mul2Itl(*a, a);
            if (cmpUnsItl(*a, b) >= 0) {
                lowSub(*a, b, a);
            }
        }
    }

    void BigInteger::lowFastExptmod(
        const IntArray& g, const IntArray& x, const IntArray& p, IntArray* y, int red_mode)
    {
        IntArray M[TAB_SIZE];
        using reduceMethod = void(*)(IntArray*, const IntArray&, Digit);
        reduceMethod redux;

        int win_size;
        int i = getBitCountItl(x);
        if (i <= 7) {
            win_size = 2;
        } else if (i <= 36) {
            win_size = 3;
        } else if (i <= 140) {
            win_size = 4;
        } else if (i <= 450) {
            win_size = 5;
        } else if (i <= 1303) {
            win_size = 6;
        } else if (i <= 3529) {
            win_size = 7;
        } else {
            win_size = 8;
        }

        Digit mp;
        if (red_mode == 0) {
            montgomerySetup(p, &mp);
            redux = montgomeryReduce;
        } else if (red_mode == 1) {
            drSetup(p, &mp);
            redux = drReduce;
        } else {
            reduce2kSetup(p, &mp);
            redux = reduce2k;
        }

        IntArray res;
        if (red_mode == 0) {
            montgomeryCalNorm(&res, p);

            IntArray tmp;
            mulItl(g, res, &tmp);
            modItl(tmp, p, &M[1]);
        } else {
            setDigitItl(&res, 1);
            modItl(g, p, &M[1]);
        }

        M[1 << (win_size - 1)] = M[1];
        for (i = 0; i < win_size - 1; ++i) {
            sqrItl(M[1 << (win_size - 1)], &M[1 << (win_size - 1)]);
            redux(&M[1 << (win_size - 1)], p, mp);
        }

        for (i = (1 << (win_size - 1)) + 1; i < (1 << win_size); ++i) {
            mulItl(M[i - 1], M[1], &M[i]);
            redux(&M[i], p, mp);
        }

        int mode = 0;
        int bitcnt = 1;
        Digit buf = 0;
        int digitx = x.used_ - 1;
        int bitcpy = 0;
        int bitbuf = 0;

        for (;;) {
            if (--bitcnt == 0) {
                if (digitx == -1) {
                    break;
                }

                buf = x.buf_[digitx--];
                bitcnt = kBaseBitCount;
            }

            int _y = (buf >> (kBaseBitCount - 1)) & 1;
            buf <<= 1;

            if (mode == 0 && _y == 0) {
                continue;
            }

            if (mode == 1 && _y == 0) {
                sqrItl(res, &res);
                redux(&res, p, mp);
                continue;
            }

            ++bitcpy;
            bitbuf |= _y << (win_size - bitcpy);
            mode = 2;

            if (bitcpy == win_size) {
                for (i = 0; i < win_size; ++i) {
                    sqrItl(res, &res);
                    redux(&res, p, mp);
                }

                mulItl(res, M[bitbuf], &res);
                redux(&res, p, mp);

                bitcpy = 0;
                bitbuf = 0;
                mode = 1;
            }
        }

        if (mode == 2 && bitcpy > 0) {
            for (i = 0; i < bitcpy; ++i) {
                sqrItl(res, &res);
                redux(&res, p, mp);

                bitbuf <<= 1;
                if (bitbuf & (1 << win_size)) {
                    mulItl(res, M[1], &res);
                    redux(&res, p, mp);
                }
            }
        }

        if (red_mode == 0) {
            redux(&res, p, mp);
        }

        *y = std::move(res);
    }

    void BigInteger::karatsubaMul(const IntArray& l, const IntArray& r, IntArray* result) {
        int B = MP_MIN(l.used_, r.used_);
        B >>= 1;

        IntArray x0(B), x1(l.used_ - B), y0(B), y1(r.used_ - B);
        IntArray t1(B * 2), x0y0(B * 2), x1y1(B * 2);

        x0.used_ = y0.used_ = B;
        x1.used_ = l.used_ - B;
        y1.used_ = r.used_ - B;

        for (int i = 0; i < B; ++i) {
            x0.buf_[i] = l.buf_[i];
            y0.buf_[i] = r.buf_[i];
        }

        for (int i = B, idx = 0; i < l.used_; ++i, ++idx) {
            x1.buf_[idx] = l.buf_[i];
        }

        for (int i = B, idx = 0; i < r.used_; ++i, ++idx) {
            y1.buf_[idx] = r.buf_[i];
        }

        x0.shrink();
        y0.shrink();

        mulItl(x0, y0, &x0y0);
        mulItl(x1, y1, &x1y1);

        lowAdd(x1, x0, &t1);
        lowAdd(y1, y0, &x0);
        mulItl(t1, x0, &t1);

        addItl(x0y0, x1y1, &x0);
        lowSub(t1, x0, &t1);

        shlItl(B, &t1);
        shlItl(B * 2, &x1y1);

        addItl(x0y0, t1, &t1);
        addItl(t1, x1y1, result);
    }

    void BigInteger::toomMul(const IntArray& l, const IntArray& r, IntArray* result) {
        IntArray w0, w1, w2, w3, w4, tmp1, tmp2, a0, b0;
        int B = MP_MIN(l.used_, r.used_) / 3;

        mod2dItl(l, kBaseBitCount*B, &a0);

        IntArray a1(l);
        shrItl(B, &a1);
        mod2dItl(a1, kBaseBitCount*B, &a1);

        IntArray a2(l);
        shrItl(B * 2, &a2);
        mod2dItl(r, kBaseBitCount*B, &b0);

        IntArray b1(r);
        shrItl(B, &b1);
        mod2dItl(b1, kBaseBitCount*B, &b1);

        IntArray b2(r);
        shrItl(B * 2, &b2);

        mulItl(a0, b0, &w0);
        mulItl(a2, b2, &w4);
        mul2Itl(a0, &tmp1);
        addItl(tmp1, a1, &tmp1);
        mul2Itl(tmp1, &tmp1);
        addItl(tmp1, a2, &tmp1);
        mul2Itl(b0, &tmp2);
        addItl(tmp2, b1, &tmp2);
        mul2Itl(tmp2, &tmp2);
        addItl(tmp2, b2, &tmp2);
        mulItl(tmp1, tmp2, &w1);

        mul2Itl(a2, &tmp1);
        addItl(tmp1, a1, &tmp1);
        mul2Itl(tmp1, &tmp1);
        addItl(tmp1, a0, &tmp1);

        mul2Itl(b2, &tmp2);
        addItl(tmp2, b1, &tmp2);
        mul2Itl(tmp2, &tmp2);
        addItl(tmp2, b0, &tmp2);
        mulItl(tmp1, tmp2, &w3);

        addItl(a2, a1, &tmp1);
        addItl(tmp1, a0, &tmp1);
        addItl(b2, b1, &tmp2);
        addItl(tmp2, b0, &tmp2);
        mulItl(tmp1, tmp2, &w2);

        // 解方程
        subItl(w1, w4, &w1);
        subItl(w3, w0, &w3);
        div2Itl(w1, &w1);
        div2Itl(w3, &w3);
        subItl(w2, w0, &w2);
        subItl(w2, w4, &w2);
        subItl(w1, w2, &w1);
        subItl(w3, w2, &w3);
        mul2dItl(w0, 3, &tmp1);
        subItl(w1, tmp1, &w1);
        mul2dItl(w4, 3, &tmp1);
        subItl(w3, tmp1, &w3);
        muldItl(w2, 3, &w2);
        subItl(w2, w1, &w2);
        subItl(w2, w3, &w2);
        subItl(w1, w2, &w3);
        subItl(w3, w2, &w3);
        div3Itl(w1, &w1, nullptr);
        div3Itl(w3, &w3, nullptr);

        shlItl(B, &w1);
        shlItl(B * 2, &w2);
        shlItl(B * 3, &w3);
        shlItl(B * 4, &w4);

        addItl(w0, w1, result);
        addItl(w2, w3, &tmp1);
        addItl(w4, tmp1, &tmp1);
        addItl(tmp1, *result, result);
    }

    void BigInteger::karatsubaSqr(const IntArray& a, IntArray* result) {
        int B = a.used_ >> 1;
        IntArray x0(B), x1(a.used_ - B), t1(a.used_ << 1), t2(a.used_ << 1), x0x0(B << 1), x1x1((a.used_ - B) << 1);

        for (int i = 0; i < B; ++i) {
            x0.buf_[i] = a.buf_[i];
        }

        for (int i = B, idx = 0; i < a.used_; ++i, ++idx) {
            x1.buf_[idx] = a.buf_[i];
        }

        x0.used_ = B;
        x1.used_ = a.used_ - B;

        x0.shrink();

        sqrItl(x0, &x0x0);
        sqrItl(x1, &x1x1);

        lowAdd(x1, x0, &t1);
        sqrItl(t1, &t1);

        lowAdd(x0x0, x1x1, &t2);
        lowSub(t1, t2, &t1);

        shlItl(B, &t1);
        shlItl(B << 1, &x1x1);

        addItl(x0x0, t1, &t1);
        addItl(t1, x1x1, result);
    }

    void BigInteger::toomSqr(const IntArray& a, IntArray* result) {
        // TODO:
        karatsubaSqr(a, result);
    }

    int BigInteger::cmpUnsItl(const IntArray& l, const IntArray& r) {
        if (l.used_ > r.used_) {
            return 1;
        }
        if (l.used_ < r.used_) {
            return -1;
        }
        for (int i = l.used_ - 1; i >= 0; --i) {
            if (l.buf_[i] > r.buf_[i]) {
                return 1;
            }
            if (l.buf_[i] < r.buf_[i]) {
                return -1;
            }
        }
        return 0;
    }

    int BigInteger::cmpItl(const IntArray& l, const IntArray& r) {
        if (!l.is_minus_ && r.is_minus_) {
            return 1;
        }
        if (l.is_minus_ && !r.is_minus_) {
            return -1;
        }
        if (l.is_minus_) {
            return cmpUnsItl(r, l);
        }
        return cmpUnsItl(l, r);
    }

    void BigInteger::addItl(const IntArray& l, const IntArray& r, IntArray* result) {
        if (l.is_minus_ == r.is_minus_) {
            result->is_minus_ = l.is_minus_;
            lowAdd(l, r, result);
        } else {
            if (cmpUnsItl(l, r) < 0) {
                result->is_minus_ = r.is_minus_;
                lowSub(r, l, result);
            } else {
                result->is_minus_ = l.is_minus_;
                lowSub(l, r, result);
            }
        }
    }

    void BigInteger::subItl(const IntArray& l, const IntArray& r, IntArray* result) {
        if (l.is_minus_ != r.is_minus_) {
            result->is_minus_ = l.is_minus_;
            lowAdd(l, r, result);
        } else {
            if (cmpUnsItl(l, r) >= 0) {
                result->is_minus_ = l.is_minus_;
                lowSub(l, r, result);
            } else {
                result->is_minus_ = !l.is_minus_;
                lowSub(r, l, result);
            }
        }
    }

    void BigInteger::mul2Itl(const IntArray& l, IntArray* result) {
        if (result->alloc_ < l.used_ + 1) {
            result->grow(l.used_ + 1);
        }
        auto old_used = result->used_;
        result->used_ = l.used_;

        int i;
        Digit prev = 0;
        for (i = 0; i < l.used_; ++i) {
            Digit rr = l.buf_[i] >> (kBaseBitCount - 1);
            result->buf_[i] = ((l.buf_[i] << 1) | prev) & kBaseMask;
            prev = rr;
        }

        if (prev != 0) {
            result->buf_[i] = prev;
            ++(result->used_);
        }

        for (i = result->used_; i < old_used; ++i) {
            result->buf_[i] = 0;
        }

        result->is_minus_ = l.is_minus_;
    }

    void BigInteger::div2Itl(const IntArray& l, IntArray* result) {
        if (result->alloc_ < l.used_) {
            result->grow(l.used_);
        }
        auto old_used = result->used_;
        result->used_ = l.used_;

        Digit prev = 0;
        for (int i = result->used_ - 1; i >= 0; --i) {
            Digit rr = l.buf_[i] & 1;
            result->buf_[i] = (l.buf_[i] >> 1) | (prev << (kBaseBitCount - 1));
            prev = rr;
        }

        for (int i = result->used_; i < old_used; ++i) {
            result->buf_[i] = 0;
        }

        result->is_minus_ = l.is_minus_;
        result->shrink();
    }

    void BigInteger::shlItl(int offset, IntArray* result) {
        if (offset <= 0) {
            return;
        }
        if (result->alloc_ < result->used_ + offset) {
            result->grow(result->used_ + offset);
        }

        result->used_ += offset;
        int i = result->used_ - 1;
        int j = result->used_ - 1 - offset;
        int k;
        for (k = result->used_ - 1; k >= offset; --k) {
            result->buf_[i] = result->buf_[j];
            --i;
            --j;
        }

        for (k = 0; k < offset; ++k) {
            result->buf_[k] = 0;
        }
    }

    void BigInteger::shrItl(int offset, IntArray* result) {
        if (offset <= 0) {
            return;
        }
        if (result->used_ <= offset) {
            result->zero();
            return;
        }

        int i = 0;
        int j = offset;
        int k;
        for (k = 0; k < result->used_ - offset; ++k) {
            result->buf_[i] = result->buf_[j];
            ++i;
            ++j;
        }

        for (; k < result->used_; ++k) {
            result->buf_[k] = 0;
        }
        result->used_ -= offset;
    }

    void BigInteger::mul2dItl(const IntArray& l, int exp, IntArray* result) {
        if (&l != result) {
            *result = l;
        }

        if (result->alloc_ < result->used_ + exp / int(kBaseBitCount) + 1) {
            result->grow(result->used_ + exp / kBaseBitCount + 1);
        }

        if (exp >= kBaseBitCount) {
            shlItl(exp / kBaseBitCount, result);
        }

        Digit d = exp % kBaseBitCount;
        if (d != 0) {
            Digit mask = (1 << d) - 1;
            Digit r = 0;
            for (int i = 0; i < result->used_; ++i) {
                Digit rr = (result->buf_[i] >> (kBaseBitCount - d)) & mask;
                result->buf_[i] = ((result->buf_[i] << d) | r) & kBaseMask;
                r = rr;
            }

            if (r > 0) {
                result->buf_[result->used_] = r;
                ++(result->used_);
            }
        }
    }

    void BigInteger::div2dItl(const IntArray& l, int exp, IntArray* result, IntArray* rem) {
        if (exp <= 0) {
            *result = l;
            if (rem) {
                rem->zero();
            }
            return;
        }

        *result = l;
        if (rem) {
            mod2dItl(l, exp, rem);
        }

        if (exp >= kBaseBitCount) {
            shrItl(exp / kBaseBitCount, result);
        }

        Digit k = exp % kBaseBitCount;
        if (k != 0) {
            Digit mask = (1 << k) - 1;
            Digit r = 0;
            for (int i = result->used_ - 1; i >= 0; --i) {
                Digit rr = result->buf_[i] & mask;
                result->buf_[i] = (result->buf_[i] >> k) | (r << (kBaseBitCount - k));
                r = rr;
            }
        }
        result->shrink();
    }

    void BigInteger::mod2dItl(const IntArray& l, int exp, IntArray* result) {
        if (exp <= 0) {
            result->zero();
            return;
        }

        if (exp > l.used_ * int(kBaseBitCount)) {
            *result = l;
            return;
        }

        *result = l;
        for (int i = (exp + (kBaseBitCount - 1)) / kBaseBitCount; i <= result->used_; ++i) {
            result->buf_[i] = 0;
        }

        Digit k = exp % kBaseBitCount;
        result->buf_[exp / kBaseBitCount] &= (1 << k) - 1;
        result->shrink();
    }

    void BigInteger::mulItl(const IntArray& l, const IntArray& r, IntArray* result) {
        bool is_minus = (l.is_minus_ != r.is_minus_);

        if (MP_MIN(l.used_, r.used_) >= TOOM_MUL_CUTOFF) {
            toomMul(l, r, result);
        } else if (MP_MIN(l.used_, r.used_) >= KARATSUBA_MUL_CUTOFF) {
            karatsubaMul(l, r, result);
        } else {
            int digs = l.used_ + r.used_ + 1;
            if (digs < MP_WARRAY && MP_MIN(l.used_, r.used_) <= kDelta) {
                lowFastMulDigs(l, r, digs, result);
            } else {
                lowMulDigs(l, r, digs, result);
            }
        }
        result->is_minus_ = is_minus;
    }

    void BigInteger::sqrItl(const IntArray& a, IntArray* result) {
        if (a.used_ >= TOOM_SQR_CUTOFF) {
            toomSqr(a, result);
        } else if (a.used_ >= KARATSUBA_SQR_CUTOFF) {
            karatsubaSqr(a, result);
        } else {
            int digs = a.used_ + result->used_ + 1;
            if (digs < MP_WARRAY && a.used_ <= kDelta) {
                lowFastSqr(a, result);
            } else {
                lowSqr(a, result);
            }
        }
        result->is_minus_ = false;
    }

    void BigInteger::exptdItl(const IntArray& a, Digit b, IntArray* result) {
        IntArray g(a);

        setDigitItl(result, 1);
        for (int i = 0; i<int(kBaseBitCount); ++i) {
            sqrItl(*result, result);
            if ((b & Digit(Digit(1) << (kBaseBitCount - 1))) != 0) {
                mulItl(*result, g, result);
            }
            b <<= 1;
        }
    }

    void BigInteger::zweiExptItl(Digit b, IntArray* result) {
        result->zero();

        result->grow(b / kBaseBitCount + 1);
        result->used_ = b / kBaseBitCount + 1;
        result->buf_[b / kBaseBitCount] = Digit(1) << (b % kBaseBitCount);
    }

    void BigInteger::exptmodItl(
        const IntArray& g, const IntArray& x, const IntArray& p, IntArray* y)
    {
        if (p.is_minus_) {
            uthrow("");
            return;
        }
        if (x.is_minus_) {
            IntArray tmpG;
            if (!invmodItl(g, p, &tmpG)) {
                uthrow("");
                return;
            }

            IntArray tmpX(x);
            tmpX.abs();

            exptmodItl(tmpG, tmpX, p, y);
            return;
        }

        if (reduceIs2kl(p)) {
            lowExptmod(g, x, p, y, 1);
            return;
        }

        int mode = drIsModulus(p) ? 1 : 0;
        if (mode == 0) {
            mode = reduceIs2k(p) ? 2 : 0;
        }

        if (p.isOdd() || mode != 0) {
            lowFastExptmod(g, x, p, y, mode);
            return;
        }

        lowExptmod(g, x, p, y, 0);
    }

    void BigInteger::divItl(
        const IntArray& a, const IntArray& b, IntArray* c, IntArray* d)
    {
        if (b.isZero()) {
            uthrow("");
            return;
        }

        if (cmpUnsItl(a, b) == -1) {
            if (d) {
                *d = a;
            }
            if (c) {
                c->zero();
            }
            return;
        }

        IntArray q(a.used_ + 2);
        q.used_ = a.used_ + 2;

        IntArray t1, t2;
        IntArray x(a), y(b);

        bool neg = a.is_minus_ != b.is_minus_;
        x.is_minus_ = y.is_minus_ = false;

        int norm = getBitCountItl(y) % kBaseBitCount;
        if (norm < int(kBaseBitCount - 1)) {
            norm = kBaseBitCount - 1 - norm;
            mul2dItl(x, norm, &x);
            mul2dItl(y, norm, &y);
        } else {
            norm = 0;
        }

        int n = x.used_ - 1;
        int t = y.used_ - 1;

        shlItl(n - t, &y);
        while (cmpItl(x, y) >= 0) {
            ++(q.buf_[n - t]);
            subItl(x, y, &x);
        }

        shrItl(n - t, &y);
        for (int i = n; i >= t + 1; --i) {
            if (i > x.used_) {
                continue;
            }

            if (x.buf_[i] == y.buf_[t]) {
                q.buf_[i - t - 1] = kBaseMask;
            } else {
                Word tmp = Word(x.buf_[i]) << kBaseBitCount;
                tmp |= Word(x.buf_[i - 1]);
                tmp /= Word(y.buf_[t]);
                if (tmp > Word(kBaseMask)) {
                    tmp = kBaseMask;
                }
                q.buf_[i - t - 1] = tmp & Word(kBaseMask);
            }

            q.buf_[i - t - 1] = (q.buf_[i - t - 1] + 1) & kBaseMask;
            do {
                q.buf_[i - t - 1] = (q.buf_[i - t - 1] - 1) & kBaseMask;

                t1.zero();
                t1.buf_[0] = (t - 1 < 0) ? 0 : y.buf_[t - 1];
                t1.buf_[1] = y.buf_[t];
                t1.used_ = 2;
                muldItl(t1, q.buf_[i - t - 1], &t1);

                t2.buf_[0] = (i - 2 < 0) ? 0 : x.buf_[i - 2];
                t2.buf_[1] = (i - 1 < 0) ? 0 : x.buf_[i - 1];
                t2.buf_[2] = x.buf_[i];
                t2.used_ = 3;
            } while (cmpUnsItl(t1, t2) > 0);

            muldItl(y, q.buf_[i - t - 1], &t1);
            shlItl(i - t - 1, &t1);
            subItl(x, t1, &x);

            if (x.is_minus_) {
                t1 = y;
                shlItl(i - t - 1, &t1);
                addItl(x, t1, &x);
                q.buf_[i - t - 1] = (q.buf_[i - t - 1] - 1U) & kBaseMask;
            }
        }

        x.is_minus_ = (x.used_ != 0) ? a.is_minus_ : false;
        if (c) {
            q.shrink();
            *c = std::move(q);
            c->is_minus_ = neg;
        }
        if (d) {
            div2dItl(x, norm, &x, nullptr);
            *d = std::move(x);
        }
    }

    void BigInteger::modItl(const IntArray& a, const IntArray& b, IntArray* c) {
        divItl(a, b, nullptr, c);
    }

    int BigInteger::cmpdItl(const IntArray& l, Digit r) {
        if (l.is_minus_) {
            return -1;
        }
        if (l.used_ > 1) {
            return 1;
        }
        if (l.used_ == 0) {
            if (r > 0)  return -1;
            return 0;
        }

        if (l.buf_[0] > r) return 1;
        if (l.buf_[0] < r) return -1;

        return 0;
    }

    void BigInteger::adddItl(const IntArray& a, Digit b, IntArray* c) {
        if (c->alloc_ < a.used_ + 1) {
            c->grow(a.used_ + 1);
        }

        if (a.is_minus_ && (a.used_ > 1 || a.buf_[0] >= b)) {
            const_cast<IntArray&>(a).is_minus_ = false;
            subdItl(a, b, c);
            const_cast<IntArray&>(a).is_minus_ = c->is_minus_ = true;
            c->shrink();
            return;
        }

        int i;
        auto old_used = c->used_;

        if (!a.is_minus_) {
            Digit mu = b;
            for (i = 0; i < a.used_; ++i) {
                c->buf_[i] = a.buf_[i] + mu;
                mu = c->buf_[i] >> kBaseBitCount;
                c->buf_[i] &= kBaseMask;
            }

            c->buf_[i] = mu;
            ++i;
            c->used_ = a.used_ + 1;
        } else {
            c->used_ = 1;
            if (a.used_ == 1) {
                c->buf_[0] = b - a.buf_[0];
            } else {
                c->buf_[0] = b;
            }
            i = 1;
        }

        while (i < old_used) {
            c->buf_[i] = 0;
            ++i;
        }
        c->is_minus_ = false;
        c->shrink();
    }

    void BigInteger::subdItl(const IntArray& a, Digit b, IntArray* c) {
        if (c->alloc_ < a.used_ + 1) {
            c->grow(a.used_ + 1);
        }

        if (a.is_minus_) {
            const_cast<IntArray&>(a).is_minus_ = false;
            adddItl(a, b, c);
            const_cast<IntArray&>(a).is_minus_ = c->is_minus_ = true;
            c->shrink();
            return;
        }

        int i;
        auto old_used = c->used_;

        if (a.used_ > 1 || a.buf_[0] >= b) {
            Digit over = b;
            for (i = 0; i < a.used_; ++i) {
                c->buf_[i] = a.buf_[i] - over;
                over = c->buf_[i] >> (kDigitBitCount - 1);
                c->buf_[i] &= kBaseMask;
            }
            c->used_ = a.used_;
            c->is_minus_ = false;
        } else {
            c->used_ = 1;
            c->is_minus_ = true;
            if (a.used_ == 1) {
                c->buf_[0] = b - a.buf_[0];
            } else {
                c->buf_[0] = b;
            }
            i = 1;
        }

        while (i < old_used) {
            c->buf_[i] = 0;
            ++i;
        }
        c->shrink();
    }

    void BigInteger::muldItl(const IntArray& a, Digit b, IntArray* c) {
        if (c->alloc_ < a.used_ + 1) {
            c->grow(a.used_ + 1);
        }

        auto old_used = c->used_;
        c->is_minus_ = a.is_minus_;

        int i;
        Digit u = 0;
        for (i = 0; i < a.used_; ++i) {
            auto r = Word(u) + Word(a.buf_[i]) * b;
            c->buf_[i] = r & kBaseMask;
            u = Digit(r >> kBaseBitCount);
        }

        c->buf_[i] = u;
        ++i;

        while (i < old_used) {
            c->buf_[i] = 0;
            ++i;
        }

        c->used_ = a.used_ + 1;
        c->shrink();
    }

    void BigInteger::div3Itl(const IntArray& a, IntArray* b, Digit* c) {
        // TODO:
        divdItl(a, 3, b, c);
    }

    void BigInteger::divdItl(const IntArray& a, Digit b, IntArray* c, Digit* d) {
        if (b == 0) {
            uthrow("");
            return;
        }

        if (b == 1 || a.isZero()) {
            if (d) {
                *d = 0;
            }
            if (c) {
                *c = a;
            }
            return;
        }

        int i;
        if (isPowOf2(b, &i)) {
            if (d) {
                *d = a.buf_[0] & ((Digit(1) << i) - 1);
            }
            if (c) {
                div2dItl(a, i, c, nullptr);
            }
            return;
        }

        Word w = 0;
        IntArray q(a.used_);
        q.used_ = a.used_;
        q.is_minus_ = a.is_minus_;
        for (i = a.used_ - 1; i >= 0; --i) {
            Digit t;
            w = (w << kBaseBitCount) | Word(a.buf_[i]);
            if (w >= b) {
                t = Digit(w / b);
                w -= Word(t)*b;
            } else {
                t = 0;
            }
            q.buf_[i] = t;
        }

        if (d) {
            *d = Digit(w);
        }
        if (c) {
            q.shrink();
            *c = std::move(q);
        }
    }

    void BigInteger::rootdItl(IntArray& a, Digit b, IntArray* c) {
        if ((b & 1) == 0 && a.is_minus_) {
            uthrow("");
            return;
        }

        IntArray t1, t2, t3;
        bool neg = a.is_minus_;
        a.is_minus_ = false;

        setDigitItl(&t2, 2);
        do {
            t1 = t2;
            exptdItl(t1, b - 1, &t3);
            mulItl(t3, t1, &t2);
            subItl(t2, a, &t2);
            muldItl(t3, b, &t3);
            divItl(t2, t3, &t3, nullptr);
            subItl(t1, t3, &t2);
        } while (cmpItl(t1, t2) != 0);

        for (;;) {
            exptdItl(t1, b, &t2);
            if (cmpItl(t2, a) > 0) {
                subdItl(t1, 1, &t1);
            } else {
                break;
            }
        }

        a.is_minus_ = neg;
        *c = std::move(t1);
        c->is_minus_ = neg;
    }

    void BigInteger::andItl(const IntArray& l, const IntArray& r, IntArray* result) {
        int i, min;
        if (l.used_ > r.used_) {
            min = r.used_;
        } else {
            min = l.used_;
        }

        if (result->used_ < min) {
            result->grow(min);
        }
        int old_used = result->used_;
        result->used_ = min;

        for (i = 0; i < min; ++i) {
            result->buf_[i] = l.buf_[i] & r.buf_[i];
        }

        for (; i < old_used; ++i) {
            result->buf_[i] = 0;
        }
        result->shrink();
    }

    void BigInteger::xorItl(const IntArray& l, const IntArray& r, IntArray* result) {
        int i, min, max;
        const IntArray* x;
        if (l.used_ > r.used_) {
            min = r.used_;
            max = l.used_;
            x = &l;
        } else {
            min = l.used_;
            max = r.used_;
            x = &r;
        }

        if (result->used_ < max) {
            result->grow(max);
        }
        int old_used = result->used_;
        result->used_ = max;

        for (i = 0; i < min; ++i) {
            result->buf_[i] = l.buf_[i] ^ r.buf_[i];
        }
        for (; i < max; ++i) {
            result->buf_[i] = x->buf_[i] ^ 0U;
        }

        for (; i < old_used; ++i) {
            result->buf_[i] = 0;
        }
        result->shrink();
    }

    void BigInteger::reduce(IntArray* x, const IntArray& m, const IntArray& mu) {
        /*{
            auto b = m;
            sqrItl(b, &b);
            if (cmpUnsItl(*x, b) > 0) {
                DCHECK(false);
            }
        }*/

        bool neg = x->is_minus_;
        x->is_minus_ = false;

        int um = m.used_;
        IntArray q(*x);

        shrItl(um - 1, &q);

        if (Digit(um) > (Digit(1) << (kBaseBitCount - 1))) {
            mulItl(q, mu, &q);
        } else {
            lowMulHighDigs(q, mu, um, &q);
        }

        shrItl(um + 1, &q);
        mod2dItl(*x, kBaseBitCount * (um + 1), x);
        lowMulDigs(q, m, um + 1, &q);

        subItl(*x, q, x);

        if (x->is_minus_) {
            setDigitItl(&q, 1);
            shlItl(um + 1, &q);
            addItl(*x, q, x);
        }

        while (cmpItl(*x, m) >= 0) {
            lowSub(*x, m, x);
        }

        x->is_minus_ = x->isZero() ? false : neg;
    }

    void BigInteger::reduceSetup(const IntArray& b, IntArray* mu) {
        zweiExptItl(b.used_ * 2 * kBaseBitCount, mu);
        divItl(*mu, b, mu, nullptr);
    }

    void BigInteger::montgomeryReduce(IntArray* x, const IntArray& n, Digit rho) {
        int digs = (n.used_ << 1) + 1;
        if (digs < MP_WARRAY && n.used_ < kDelta) {
            fastMontgomeryReduce(x, n, rho);
            return;
        }

        if (x->alloc_ < digs) {
            x->grow(digs);
        }
        x->used_ = digs;

        for (int i = 0; i < n.used_; ++i) {
            int j;
            Digit mu = Word(x->buf_[i]) * rho & kBaseMask;
            Digit u = 0;
            for (j = 0; j < n.used_; ++j) {
                Word r = Word(mu) * n.buf_[j] + x->buf_[i + j] + u;
                x->buf_[i + j] = r & kBaseMask;
                u = Digit(r >> kBaseBitCount);
            }

            while (u > 0) {
                x->buf_[i + j] += u;
                u = x->buf_[i + j] >> kBaseBitCount;
                x->buf_[i + j] &= kBaseMask;
                ++j;
            }
        }

        x->shrink();
        shrItl(n.used_, x);

        if (cmpUnsItl(*x, n) >= 0) {
            lowSub(*x, n, x);
        }
    }

    void BigInteger::fastMontgomeryReduce(IntArray* x, const IntArray& n, Digit rho) {
        Word W[MP_WARRAY];
        int old_used = x->used_;
        if (x->alloc_ < n.used_ + 1) {
            x->grow(n.used_ + 1);
        }

        int i;
        for (i = 0; i < x->used_; ++i) {
            W[i] = x->buf_[i];
        }
        for (; i <= n.used_ * 2; ++i) {
            W[i] = 0;
        }

        for (i = 0; i < n.used_; ++i) {
            Digit mu = (W[i] & kBaseMask) * rho & kBaseMask;
            for (int j = 0; j < n.used_; ++j) {
                W[i + j] += Word(mu) * n.buf_[j];
            }
            W[i + 1] += W[i] >> kBaseBitCount;
        }

        for (; i <= n.used_ * 2 + 1; ++i) {
            W[i + 1] += W[i] >> kBaseBitCount;
        }
        for (i = 0; i < n.used_ + 1; ++i) {
            x->buf_[i] = W[i + n.used_] & kBaseMask;
        }

        for (; i < old_used; ++i) {
            x->buf_[i] = 0;
        }

        x->used_ = n.used_ + 1;
        x->shrink();

        if (cmpUnsItl(*x, n) >= 0) {
            lowSub(*x, n, x);
        }
    }

    void BigInteger::montgomerySetup(const IntArray& n, Digit* rho) {
        Digit b = n.buf_[0];
        if ((b & 1) == 0) {
            uthrow("");
            return;
        }

        Digit x = (((b + 2) & 4) << 1) + b;
        x *= 2 - b * x;
        if (kBaseBitCount > 8) {
            x *= 2 - b * x;
            if (kBaseBitCount > 16) {
                x *= 2 - b * x;
                if (kBaseBitCount > 32) {
                    x *= 2 - b * x;
                }
            }
        }

        *rho = ((Word(1) << kBaseBitCount) - x) & kBaseMask;
    }

    void BigInteger::drReduce(IntArray* x, const IntArray& n, Digit k) {
        int m = n.used_;
        if (x->alloc_ < m * 2) {
            x->grow(m * 2);
        }

        for (;;) {
            Digit mu = 0;
            for (int i = 0; i < m; ++i) {
                Word r = Word(x->buf_[m + i]) * k + x->buf_[i] + mu;
                x->buf_[i] = r & kBaseMask;
                mu = Digit(r >> kBaseBitCount);
            }

            x->buf_[m] = mu;

            for (int i = m + 1; i < x->used_; ++i) {
                x->buf_[i] = 0;
            }

            x->shrink();

            if (cmpUnsItl(*x, n) >= 0) {
                lowSub(*x, n, x);
            } else {
                break;
            }
        }
    }

    void BigInteger::drSetup(const IntArray& n, Digit* k) {
        *k = kBase - n.buf_[0];
    }

    bool BigInteger::drIsModulus(const IntArray& n) {
        if (n.used_ < 2) {
            return false;
        }

        for (int i = 1; i < n.used_; ++i) {
            if (n.buf_[i] != kBaseMask) {
                return false;
            }
        }
        return true;
    }

    void BigInteger::reduce2k(IntArray* a, const IntArray& n, Digit d) {
        int p = getBitCountItl(n);
        IntArray q;

        for (;;) {
            div2dItl(*a, p, &q, a);
            if (d != 1) {
                muldItl(q, d, &q);
            }

            lowAdd(*a, q, a);
            if (cmpUnsItl(*a, n) >= 0) {
                lowSub(*a, n, a);
            } else {
                break;
            }
        }
    }

    void BigInteger::reduce2kSetup(const IntArray& a, Digit* d) {
        IntArray tmp;

        int p = getBitCountItl(a);
        zweiExptItl(p, &tmp);

        lowSub(tmp, a, &tmp);
        *d = tmp.buf_[0];
    }

    bool BigInteger::reduceIs2k(const IntArray& a) {
        if (a.used_ == 0) {
            return false;
        }
        if (a.used_ == 1) {
            return true;
        }
        if (a.used_ > 1) {
            int j = getBitCountItl(a);
            Digit k = 1;
            int l = 1;

            for (int i = kBaseBitCount; i < j; ++i) {
                if ((a.buf_[l] & k) == 0) {
                    return false;
                }
                k <<= 1;
                if (k > kBaseMask) {
                    ++l;
                    k = 1;
                }
            }
        }
        return true;
    }

    void BigInteger::reduce2kl(IntArray* a, const IntArray& n, const IntArray& d) {
        int p = getBitCountItl(n);
        IntArray q;

        for (;;) {
            div2dItl(*a, p, &q, a);
            mulItl(q, d, &q);

            lowAdd(*a, q, a);
            if (cmpUnsItl(*a, n) >= 0) {
                lowSub(*a, n, a);
            } else {
                break;
            }
        }
    }

    void BigInteger::reduce2klSetup(const IntArray& a, IntArray* d) {
        IntArray tmp;

        int p = getBitCountItl(a);
        zweiExptItl(p, &tmp);

        lowSub(tmp, a, d);
    }

    bool BigInteger::reduceIs2kl(const IntArray& a) {
        if (a.used_ == 0) {
            return false;
        }
        if (a.used_ == 1) {
            return true;
        }
        if (a.used_ > 1) {
            int j = 0;
            for (int i = 0; i < a.used_; ++i) {
                if (a.buf_[i] > kBaseMask) {
                    ++j;
                }
            }
            return j >= a.used_ / 2;
        }
        return true;
    }

    bool BigInteger::invmodFast(const IntArray& a, const IntArray& b, IntArray* c) {
        if (!b.isOdd()) {
            return false;
        }

        IntArray x(b);

        IntArray y;
        modItl(a, b, &y);

        IntArray u(x);
        IntArray v(y);

        IntArray B, D;
        setDigitItl(&D, 1);

        do {
            while (!u.isOdd()) {
                div2Itl(u, &u);
                if (B.isOdd()) {
                    subItl(B, x, &B);
                }

                div2Itl(B, &B);
            }

            while (!v.isOdd()) {
                div2Itl(v, &v);
                if (D.isOdd()) {
                    subItl(D, x, &D);
                }

                div2Itl(D, &D);
            }

            if (cmpItl(u, v) >= 0) {
                subItl(u, v, &u);
                subItl(B, D, &B);
            } else {
                subItl(v, u, &v);
                subItl(D, B, &D);
            }
        } while (!u.isZero());

        if (cmpdItl(v, 1) != 0) {
            return false;
        }

        auto neg = a.is_minus_;
        while (D.is_minus_) {
            addItl(D, b, &D);
        }

        *c = std::move(D);
        c->is_minus_ = neg;
        return true;
    }

    bool BigInteger::invmodSlow(const IntArray& a, const IntArray& b, IntArray* c) {
        if (b.is_minus_ || b.isZero()) {
            return false;
        }

        IntArray x;
        modItl(a, b, &x);

        IntArray y(b);
        if (!x.isOdd() && !y.isOdd()) {
            return false;
        }

        IntArray u(x);
        IntArray v(y);

        IntArray A, B, C, D;
        setDigitItl(&A, 1);
        setDigitItl(&D, 1);

        do {
            while (!u.isOdd()) {
                div2Itl(u, &u);
                if (A.isOdd() || B.isOdd()) {
                    addItl(A, y, &A);
                    subItl(B, x, &B);
                }

                div2Itl(A, &A);
                div2Itl(B, &B);
            }

            while (!v.isOdd()) {
                div2Itl(v, &v);
                if (C.isOdd() || D.isOdd()) {
                    addItl(C, y, &C);
                    subItl(D, x, &D);
                }

                div2Itl(C, &C);
                div2Itl(D, &D);
            }

            if (cmpItl(u, v) >= 0) {
                subItl(u, v, &u);
                subItl(A, C, &A);
                subItl(B, D, &B);
            } else {
                subItl(v, u, &v);
                subItl(C, A, &C);
                subItl(D, B, &D);
            }
        } while (!u.isZero());

        if (cmpdItl(v, 1) != 0) {
            return false;
        }

        while (cmpdItl(C, 0) < 0) {
            addItl(C, b, &C);
        }
        while (cmpUnsItl(C, b) >= 0) {
            subItl(C, b, &C);
        }

        *c = std::move(C);
        return true;
    }

    void BigInteger::readFromStringItl(const std::string& str, int radix, IntArray* a) {
        if (radix < 2 || radix > 64) {
            uthrow("");
            return;
        }

        a->zero();

        bool neg = false;
        bool first_d = false;
        int length = int(str.length());

        for (int i = 0; i < length; ++i) {
            auto sch = str[i];
            if (sch == ' ') {
                continue;
            }

            if (!first_d) {
                first_d = true;
                neg = (sch == '-');
                if (neg) {
                    continue;
                }
            }

            int j;
            bool hit = false;
            char ch = (radix < 36) ? ::toupper(sch) : sch;
            for (j = 0; j < 64; ++j) {
                if (ch == kBase64CharMap[j]) {
                    hit = true;
                    break;
                }
            }

            if (!hit) {
                uthrow("");
            }

            if (j < radix) {
                muldItl(*a, radix, a);
                adddItl(*a, j, a);
            } else {
                break;
            }
        }

        if (!a->isZero()) {
            a->is_minus_ = neg;
        }
    }

    void BigInteger::toStringItl(const IntArray& a, int radix, std::string* str) {
        if (radix < 2 || radix > 64) {
            uthrow("");
            return;
        }
        if (a.isZero()) {
            str->push_back('0');
            return;
        }

        int begin = 0;
        IntArray t(a);
        if (t.is_minus_) {
            begin = 1;
            str->push_back('-');
            t.is_minus_ = false;
        }

        Digit d;
        while (!t.isZero()) {
            divdItl(t, radix, &t, &d);
            str->push_back(kBase64CharMap[d]);
        }

        std::reverse(str->begin() + begin, str->end());
    }

    void BigInteger::gcdItl(const IntArray& a, const IntArray& b, IntArray* c) {
        if (a.isZero()) {
            *c = b;
            c->abs();
            return;
        }
        if (b.isZero()) {
            *c = a;
            c->abs();
            return;
        }

        IntArray u(a);
        IntArray v(b);

        u.is_minus_ = v.is_minus_ = false;

        auto u_lsb = getLSBZeroCount(u);
        auto v_lsb = getLSBZeroCount(v);
        int k = MP_MIN(u_lsb, v_lsb);

        if (k > 0) {
            div2dItl(u, k, &u, nullptr);
            div2dItl(v, k, &v, nullptr);
        }

        if (u_lsb != k) {
            div2dItl(u, u_lsb - k, &u, nullptr);
        }
        if (v_lsb != k) {
            div2dItl(v, v_lsb - k, &v, nullptr);
        }

        while (!v.isZero()) {
            if (cmpUnsItl(u, v) == 1) {
                u.swap(&v);
            }

            lowSub(v, u, &v);
            div2dItl(v, getLSBZeroCount(v), &v, nullptr);
        }

        mul2dItl(u, k, c);
        c->is_minus_ = false;
    }

    void BigInteger::lcmItl(const IntArray& a, const IntArray& b, IntArray* c) {
        IntArray t1, t2;

        gcdItl(a, b, &t1);
        if (cmpUnsItl(a, b) == -1) {
            divItl(a, t1, &t2, nullptr);
            mulItl(b, t2, c);
        } else {
            divItl(b, t1, &t2, nullptr);
            mulItl(a, t2, c);
        }

        c->is_minus_ = false;
    }

    void BigInteger::incItl(uint32_t s, IntArray* a) {
        if ((a->buf_[0] & 1) == 0) {
            a->buf_[0] += 1;
            return;
        }

        int length = getBitCountItl(*a);
        s = MP_MIN(length, int(s));

        int b_count = s / kBaseBitCount;
        int off = s % kBaseBitCount;

        Digit u = 1;
        for (int i = 0; i < b_count; ++i) {
            a->buf_[i] += u;
            u = a->buf_[i] >> kBaseBitCount;
            a->buf_[i] &= kBaseMask;
            if (u == 0) {
                return;
            }
        }

        if (off > 0) {
            Digit mask = (Digit(1) << off) - 1;
            Digit tmp = a->buf_[b_count] & mask;
            ++tmp;
            tmp &= mask;
            a->buf_[b_count] &= ~mask;
            a->buf_[b_count] |= tmp;
        }
    }

    bool BigInteger::invmodItl(const IntArray& a, const IntArray& b, IntArray* c) {
        if (b.is_minus_ || b.isZero() || a.isZero()) {
            uthrow("");
            return false;
        }
        if (b.isOdd()) {
            //return invmodFast(a, b, c);
        }
        return invmodSlow(a, b, c);
    }

    bool BigInteger::isPowOf2(Digit b, int* p) {
        for (int i = 0; i < kBaseBitCount; ++i) {
            if (b == Digit(1) << i) {
                *p = i;
                return true;
            }
        }
        return false;
    }

}