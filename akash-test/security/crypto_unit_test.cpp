// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash-test/security/crypto_unit_test.h"

#include <algorithm>
#include <iomanip>

#include "utils/log.h"
#include "akash/security/crypto/aes.h"
#include "akash/security/crypto/ecdp.h"
#include "akash/security/crypto/aead.h"
#include "akash/security/crypto/rsa.h"


using stringu8 = std::basic_string<uint8_t>;

namespace {

    std::string swapHexStrBytes(const std::string& in) {
        std::string out;
        for (size_t i = 0; i < in.length(); i += 2) {
            if (i + 1 < in.length()) {
                out.insert(out.begin(), in[i + 1]);
            }
            out.insert(out.begin(), in[i]);
        }
        return out;
    }

    // 获取字符串的字面值字节数组。
    // 该方法假定输入为大端模式，且输入字符串长度为偶数。
    stringu8 getStrBytes(const std::string& in) {
        stringu8 out;
        for (size_t i = 0; i < in.length(); i += 2) {
            int result;
            std::istringstream ss(in.substr(i, 2));
            if (!(ss >> std::hex >> result)) {
                return {};
            }
            out.push_back(result);
        }
        return out;
    }

    // 获取字节数组的字符串字面值。
    // 该方法将按照输入的字节数组顺序输出字符串。
    std::string getBytesStr(const uint8_t* in, size_t len) {
        std::string out;
        std::ostringstream ss;
        for (size_t i = 0; i < len; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << int(in[i]);
        }
        return ss.str();
    }

}


namespace akash {
namespace test {

    int TEST_AES() {
        //uint8_t key[] { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
        //uint8_t key[] { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
        uint8_t key[] { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
        uint8_t input[] { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };

        uint8_t cipher[4 * crypto::AES::Nb];
        crypto::AES::encrypt(input, cipher, key, sizeof(key));

        uint8_t plain[4 * crypto::AES::Nb];
        crypto::AES::decrypt(cipher, plain, key, sizeof(key));

        for (int i = 0; i < 16; ++i) {
            DCHECK(plain[i] == input[i]);
        }

        return 0;
    }

    int TEST_RSA() {
        auto p = crypto::RSA::getPrime();
        auto q = crypto::RSA::getPrime();
        auto n = p * q;
        auto fn = p.sub(utl::BigInteger::ONE) * q.sub(utl::BigInteger::ONE);

        // 确定公钥指数 e
        auto e = utl::BigInteger::fromRandom(utl::BigInteger::TWO, fn - utl::BigInteger::ONE);
        while (!(e.gcd(fn) == utl::BigInteger::ONE)) {
            e = utl::BigInteger::fromRandom(utl::BigInteger::TWO, fn - utl::BigInteger::ONE);
        }

        // 确定私钥指数 d
        auto d = e.invmod(fn);

        p.destroy();
        q.destroy();

        int M = 2233;
        auto C = utl::BigInteger::fromU32(M).powMod(e, n);
        auto M1 = C.powMod(d, n);

        return M1 == utl::BigInteger::from32(2233);
    }

    void TEST_ECDP_X25519() {
        auto k = utl::BigInteger::fromString(swapHexStrBytes(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"), 16);

        k.setBit(255, 0);
        k.setBit(254, 1);
        k.setBit(2, 0);
        k.setBit(1, 0);
        k.setBit(0, 0);

        auto u = utl::BigInteger::fromString(swapHexStrBytes(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"), 16);
        u.setBit(255, 0);

        uint32_t A;
        uint8_t cofactor, Up;
        utl::BigInteger p, order, Vp, result;
        crypto::ECDP::curve25519(&p, &A, &order, &cofactor, &Up, &Vp);

        crypto::ECDP::X25519(p, k, u, &result);

        std::string out;
        result.toString(16, &out);
        std::transform(out.begin(), out.end(), out.begin(), ::tolower);

        DCHECK(swapHexStrBytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742") == out);
    }

    void TEST_ECDP_X448() {
        auto k = utl::BigInteger::fromString(swapHexStrBytes(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121"
            "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"), 16);

        k.setBit(447, 1);
        k.setBit(1, 0);
        k.setBit(0, 0);

        auto u = utl::BigInteger::fromString(swapHexStrBytes(
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9"
            "814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086"), 16);

        uint32_t A;
        uint8_t cofactor, Up;
        utl::BigInteger p, order, Vp, result;
        crypto::ECDP::curve448(&p, &A, &order, &cofactor, &Up, &Vp);

        crypto::ECDP::X448(p, k, u, &result);

        std::string out;
        result.toString(16, &out);
        std::transform(out.begin(), out.end(), out.begin(), ::tolower);

        DCHECK(swapHexStrBytes("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f"
            "e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f") == out);
    }

    void TEST_AEAD_AES_GCM() {
        {
            // 128
            stringu8 K = getStrBytes("1672c3537afa82004c6b8a46f6f0d026");
            stringu8 IV = getStrBytes("05");
            uint8_t T[128 / 8];
            crypto::GCM::GCM_AE(
                K.data(), K.length(), IV.data(), IV.length(),
                nullptr, 0, nullptr, 0, nullptr, T, sizeof T);
            DCHECK(getBytesStr(T, sizeof T) == "8e2ad721f9455f74d8b53d3141f27e8e");

            DCHECK(crypto::GCM::GCM_AD(
                K.data(), K.length(), IV.data(), IV.length(),
                nullptr, 0, nullptr, 0, T, sizeof T, nullptr));
        }

        {
            // 128
            stringu8 K = getStrBytes("11754cd72aec309bf52f7687212e8957");
            stringu8 IV = getStrBytes("3c819d9a9bed087615030b65");
            uint8_t T[128 / 8];
            crypto::GCM::GCM_AE(
                K.data(), K.length(), IV.data(), IV.length(),
                nullptr, 0, nullptr, 0, nullptr, T, sizeof T);
            DCHECK(getBytesStr(T, sizeof T) == "250327c674aaf477aef2675748cf6971");

            stringu8 P;
            DCHECK(crypto::GCM::GCM_AD(
                K.data(), K.length(), IV.data(), IV.length(),
                nullptr, 0, nullptr, 0, T, sizeof T, nullptr));
        }

        {
            // 128
            stringu8 K = getStrBytes("919134056cdababe692a2fdd0ee0c30f");
            stringu8 IV = getStrBytes("a952082329230002c3261f1b");
            uint8_t T[32 / 8];
            crypto::GCM::GCM_AE(
                K.data(), K.length(), IV.data(), IV.length(),
                nullptr, 0, nullptr, 0, nullptr, T, sizeof T);
            DCHECK(getBytesStr(T, sizeof T) == "01eaee77");

            stringu8 P;
            DCHECK(crypto::GCM::GCM_AD(
                K.data(), K.length(), IV.data(), IV.length(),
                nullptr, 0, nullptr, 0, T, sizeof T, nullptr));
        }

        {
            // 128
            stringu8 K = getStrBytes("77be63708971c4e240d1cb79e8d77feb");
            stringu8 IV = getStrBytes("e0e00f19fed7ba0136a797f3");
            stringu8 A = getStrBytes("7a43ec1d9c0a5a78a0b16533a6213cab");
            uint8_t T[128 / 8];
            crypto::GCM::GCM_AE(
                K.data(), K.length(), IV.data(), IV.length(),
                nullptr, 0, A.data(), A.length(), nullptr, T, sizeof T);
            DCHECK(getBytesStr(T, sizeof T) == "209fcc8d3675ed938e9c7166709dd946");

            DCHECK(crypto::GCM::GCM_AD(
                K.data(), K.length(), IV.data(), IV.length(),
                nullptr, 0, A.data(), A.length(), T, sizeof T, nullptr));
        }

        {
            // 128
            stringu8 K = getStrBytes("7fddb57453c241d03efbed3ac44e371c");
            stringu8 IV = getStrBytes("ee283a3fc75575e33efd4887");
            stringu8 P = getStrBytes("d5de42b461646c255c87bd2962d3b9a2");
            stringu8 C(P.length(), 0);
            uint8_t T[128 / 8];
            crypto::GCM::GCM_AE(
                K.data(), K.length(), IV.data(), IV.length(),
                P.data(), P.length(), nullptr, 0, &*C.begin(), T, sizeof T);
            DCHECK(getBytesStr(C.data(), P.length()) == "2ccda4a5415cb91e135c2a0f78c9b2fd");
            DCHECK(getBytesStr(T, sizeof T) == "b36d1df9b9d5e596f83e8b7f52971cb3");

            stringu8 _P(C.length(), 0);
            DCHECK(crypto::GCM::GCM_AD(
                K.data(), K.length(), IV.data(), IV.length(),
                C.data(), C.length(), nullptr, 0, T, sizeof T, &*_P.begin()));
            DCHECK(_P == P);
        }

        {
            // 128
            stringu8 K = getStrBytes("f006f4956684f328f893a59fae41998a");
            stringu8 IV = getStrBytes("ab50a8b652b4fd4b792244b98ab1641810dea5a52797b4a63c52f4"
                "1b9351c6ba6ba2d4fb9d70f774ce00d162cdd8b1c8a142c234fde075d609ed8b5b79de5ce7c9"
                "c4cf4c6258f6ea1543b8ef3e72dc1789c5aeb7aaf3a2a5400bd6b1ecdf19aa4da528c171aa43"
                "5824d985a0c76707a6be0c6402bf9122186a56a50fb7a3828e");
            stringu8 P = getStrBytes("f4d0de42ce1268e0421134dde7");
            stringu8 A = getStrBytes("c5962f9fdfdb9cce9a49fae4d6d328ad100acbadefc1774d83e2441"
                "9a66f5856ac4f023ca84faa9ee73df6c73cbbf8e60622333e2238bdd235baf5bc9bc1d304f98"
                "b2f9a8176e03ac2d6c75f32e5e19ace32d9b3eb132ae9786c");
            stringu8 C(P.length(), 0);
            uint8_t T[120 / 8];
            crypto::GCM::GCM_AE(
                K.data(), K.length(), IV.data(), IV.length(),
                P.data(), P.length(), A.data(), A.length(), &*C.begin(), T, sizeof T);
            DCHECK(getBytesStr(C.data(), P.length()) == "a9585fbd04deab91dc70563e2c");
            DCHECK(getBytesStr(T, sizeof T) == "c77dbf78cecc6bbb1881950a3a6c3d");

            stringu8 _P(C.length(), 0);
            DCHECK(crypto::GCM::GCM_AD(
                K.data(), K.length(), IV.data(), IV.length(),
                C.data(), C.length(), A.data(), A.length(), T, sizeof T, &*_P.begin()));
            DCHECK(_P == P);
        }

        {
            // 192
            stringu8 K = getStrBytes("aa740abfadcda779220d3b406c5d7ec09a77fe9d94104539");
            stringu8 IV = getStrBytes("ab2265b4c168955561f04315");
            uint8_t T[128 / 8];
            crypto::GCM::GCM_AE(
                K.data(), K.length(), IV.data(), IV.length(),
                nullptr, 0, nullptr, 0, nullptr, T, sizeof T);
            DCHECK(getBytesStr(T, sizeof T) == "f149e2b5f0adaa9842ca5f45b768a8fc");

            stringu8 P;
            DCHECK(crypto::GCM::GCM_AD(
                K.data(), K.length(), IV.data(), IV.length(),
                nullptr, 0, nullptr, 0, T, sizeof T, nullptr));
        }

        {
            // 192
            stringu8 K = getStrBytes("4ef6d69f2859df52f3bd89536ae4678a6c8a66dcd2de0297");
            stringu8 IV = getStrBytes("9ef13db6492bd861f8d413b6fa128f50c712845f5fd8f237c11e6b"
                "195658b7bc6ff8554b51e8c686a1f57bd51aa0e0db2dda6e336881dbc918a9a322577356f2ba"
                "3fcc9d8378b252980c44eda96b6bdb59b279ebb6a805937289e8e15c58d83e3eca25dcd639aa"
                "b485d59e446ca9eedec60ecf25e956ce8c75bc1c425175dd43");
            stringu8 P = getStrBytes("e331dffcc7aac724e6272c8a00f1fade12711eada6ef880abb952c8db3bc7b0d");
            stringu8 A = getStrBytes("5b2710cb83de39632a10ff86262ee75ce2fa10a18a14d3cb9774ab3"
                "adc585bb316e95c77daa30ab94f54883161fa95ba4f7914a847b4c3f6555192b8593ca7e9f80"
                "6354689a7cc73123c58292c5e08824bc8e69713e3a4ef53cd");
            stringu8 C(P.length(), 0);
            uint8_t T[104 / 8];
            crypto::GCM::GCM_AE(
                K.data(), K.length(), IV.data(), IV.length(),
                P.data(), P.length(), A.data(), A.length(), &*C.begin(), T, sizeof T);
            DCHECK(getBytesStr(C.data(), C.length())
                == "f2ddf592fe3789008d022557c6436acb471700de1fc5a8dd8fa4c315a2ae8e4c");
            DCHECK(getBytesStr(T, sizeof T) == "eb67fb25cc6eabccea2fe4f150");

            stringu8 _P(C.length(), 0);
            DCHECK(crypto::GCM::GCM_AD(
                K.data(), K.length(), IV.data(), IV.length(),
                C.data(), C.length(), A.data(), A.length(), T, sizeof T, &*_P.begin()));
        }

        {
            // 256
            stringu8 K = getStrBytes("b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4");
            stringu8 IV = getStrBytes("516c33929df5a3284ff463d7");
            uint8_t T[128 / 8];
            crypto::GCM::GCM_AE(
                K.data(), K.length(), IV.data(), IV.length(),
                nullptr, 0, nullptr, 0, nullptr, T, sizeof T);
            DCHECK(getBytesStr(T, sizeof T) == "bdc1ac884d332457a1d2664f168c76f0");

            DCHECK(crypto::GCM::GCM_AD(
                K.data(), K.length(), IV.data(), IV.length(),
                nullptr, 0, nullptr, 0, T, sizeof T, nullptr));
        }

        {
            // 256
            stringu8 K = getStrBytes("a554516e925009dd856f192213e5376bd072078aeb5d3af971b68cc57f8aa0be");
            stringu8 IV = getStrBytes("26eb2f8c2a9fe5ce6af93be63cf3e670c5f0208933127327ec4869"
                "3e2ee37e92a0af1c688102fd7b4bb62be1ddd5ba0b8a6ed47137987af768f007857edb2a7465"
                "ac0ca7a729846966a46d732445c4524d8ccd18233e25e4ea70cfb31b03d2a564f0948247058e"
                "2ac3f963b816315f183efd80c7117e93b4f8592b4901eb6aa5");
            stringu8 P = getStrBytes("948ac5bf639d55b4d9e46a8846c697e7d1b9456b9c3f77c891d5aca"
                "323f18ae78ff8736b8178f91d7fce4041495f616289db79");
            stringu8 A = getStrBytes("7d2f9b880afbad746bf58c81e31a8e8f88999eb0c6c630ec35db43f"
                "1e0952fc7d9bc86154832afd154bc49ffe5e67a1d144b89b7e74a36fdeac8e95b8d9c3b220ef"
                "71f38611edc32ac7d9c01a9bb3ec48bc1aaf1dd79921759b6");
            stringu8 C(P.length(), 0);
            uint8_t T[32 / 8];
            crypto::GCM::GCM_AE(
                K.data(), K.length(), IV.data(), IV.length(),
                P.data(), P.length(), A.data(), A.length(), &*C.begin(), T, sizeof T);
            DCHECK(getBytesStr(C.data(), C.length())
                == "c366146de8b58d3cce004c62a60b24bca3814d3d11ded76bb9f7d47"
                "c41191b7e3a7444700bd93fefdf54252cb7cf6041038ca8");
            DCHECK(getBytesStr(T, sizeof T) == "5016d92a");

            stringu8 _P(C.length(), 0);
            DCHECK(crypto::GCM::GCM_AD(
                K.data(), K.length(), IV.data(), IV.length(),
                C.data(), C.length(), A.data(), A.length(), T, sizeof T, &*_P.begin()));
        }
    }

}
}