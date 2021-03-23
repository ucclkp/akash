// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_SECURITY_DIGEST_MD5_H_
#define AKASH_SECURITY_DIGEST_MD5_H_

#include <cstdint>
#include <string>


namespace akash {
namespace digest {

    enum MD5Result {
        md5Success = 0,
        md5Null,            // Null pointer parameter
        md5StateError,      // called Input after FinalBits or Result
        md5BadParam         // passed a bad parameter
    };


    /**
     * 根据 RFC1321 实现的 MD5 算法
     * https://tools.ietf.org/html/rfc1321
     */
    class MD5 {
    public:
        static std::string cal(const std::string& str);
        static std::string cal(const std::string& str, size_t block_size);

        void init();
        int update(const uint8_t* bytes, size_t length);
        int finalBits(uint8_t bits, unsigned int length);
        int result(uint8_t digest[16]);

    private:
        MD5() = default;

        struct Context {
            uint32_t state[4];
            uint64_t count;
            uint8_t buffer[64];

            bool computed;
            int corrupted;
        };

        void finalize(uint8_t pad_byte, uint8_t ex_bit_length);

        static void transform(uint32_t state[4], uint8_t block[64]);

        static void UInt32sToBytes(uint8_t* out, const uint32_t* in, uint32_t len);
        static void UInt64sToBytes(uint8_t* out, const uint64_t* in, uint32_t len);
        static void bytesToUInt32s(uint32_t* out, const uint8_t* in, uint32_t len);

        Context context_;
    };

}
}

#endif  // AKASH_SECURITY_DIGEST_MD5_H_
