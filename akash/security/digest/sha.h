// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_SECURITY_DIGEST_SHA1_H_
#define AKASH_SECURITY_DIGEST_SHA1_H_

#include <cstdint>


namespace akash {
namespace digest {

    /**
     * 根据 RFC6234 实现的 SHA 相关算法
     * https://tools.ietf.org/html/rfc6234
     *
     * 代码主体来自上方链接，仅做细微修改。
     */

    enum class SHAVersion {
        SHA1, SHA224, SHA256, SHA384, SHA512
    };

    enum SHAResult {
        shaSuccess = 0,
        shaNull,            // Null pointer parameter
        shaInputTooLong,    // input data too long
        shaStateError,      // called Input after FinalBits or Result
        shaBadParam         // passed a bad parameter
    };


    class SHA1 {
    public:
        static const int kHashSize = 20;
        static const int kHashSizeBits = 160;
        static const int kMsgBlockSize = 64;

        SHA1() = default;

        void init();
        int update(const uint8_t* bytes, unsigned int length);
        int finalBits(uint8_t bits, unsigned int length);
        int result(uint8_t msg_digest[kHashSize]);

    private:
        struct Context {
            uint32_t intermediate_hash[kHashSize / 4]; // Message Digest

            uint32_t length_high;               // Message length in bits
            uint32_t length_low;                // Message length in bits

            int_least16_t msg_block_index;      // Message_Block array index
                                                // 512-bit message blocks
            uint8_t msg_block[kMsgBlockSize];

            bool computed;                  // Is the hash computed?
            int corrupted;                  // Cumulative corruption code
        };

        static void processMessageBlock(Context* context);
        static void finalize(Context* context, uint8_t pad_byte);
        static void padMessage(Context* context, uint8_t pad_byte);

        Context context_;
    };


    class SHA224 {
    public:
        static const int kHashSize = 28;
        static const int kLargeHashSize = 32;
        static const int kHashSizeBits = 224;
        static const int kMsgBlockSize = 64;

        SHA224() = default;

        void init();
        int update(const uint8_t* bytes, unsigned int length);
        int finalBits(uint8_t bits, unsigned int length);
        int result(uint8_t msg_digest[kHashSize]);

    private:
        struct Context {
            uint32_t intermediate_hash[kLargeHashSize / 4]; // Message Digest

            uint32_t length_high;               // Message length in bits
            uint32_t length_low;                // Message length in bits

            int_least16_t msg_block_index;      // Message_Block array index
                                                // 512-bit message blocks
            uint8_t msg_block[kMsgBlockSize];
            bool computed;                   // Is the hash computed?
            int corrupted;                   // Cumulative corruption code
        };

        static void processMessageBlock(Context* context);
        static void finalize(Context* context, uint8_t pad_byte);
        static void padMessage(Context* context, uint8_t pad_byte);

        Context context_;
    };


    class SHA256 {
    public:
        static const int kHashSize = 32;
        static const int kHashSizeBits = 256;
        static const int kMsgBlockSize = 64;

        SHA256() = default;

        void init();
        int update(const uint8_t* bytes, unsigned int length);
        int finalBits(uint8_t bits, unsigned int length);
        int result(uint8_t msg_digest[kHashSize]);

    private:
        struct Context {
            uint32_t intermediate_hash[kHashSize / 4]; // Message Digest

            uint32_t length_high;               // Message length in bits
            uint32_t length_low;                // Message length in bits

            int_least16_t msg_block_index;      // Message_Block array index
                                                // 512-bit message blocks
            uint8_t msg_block[kMsgBlockSize];
            bool computed;                   // Is the hash computed?
            int corrupted;                   // Cumulative corruption code
        };

        static void processMessageBlock(Context* context);
        static void finalize(Context* context, uint8_t pad_byte);
        static void padMessage(Context* context, uint8_t pad_byte);

        Context context_;
    };


    class SHA384 {
    public:
        static const int kHashSize = 48;
        static const int kLargeHashSize = 64;
        static const int kHashSizeBits = 384;
        static const int kMsgBlockSize = 128;

        SHA384() = default;

        void init();
        int update(const uint8_t* bytes, unsigned int length);
        int finalBits(uint8_t bits, unsigned int length);
        int result(uint8_t msg_digest[kHashSize]);

    private:
        struct Context {
            uint64_t intermediate_hash[kLargeHashSize / 8]; // Message Digest
            uint64_t length_high, length_low;   // Message length in bits

            int_least16_t msg_block_index;  // Message_Block array index
                                                // 1024-bit message blocks
            uint8_t msg_block[kMsgBlockSize];

            bool computed;                   // Is the hash computed?
            int corrupted;                  // Cumulative corruption code
        };

        static void processMessageBlock(Context* context);
        static void finalize(Context* context, uint8_t pad_byte);
        static void padMessage(Context* context, uint8_t pad_byte);

        Context context_;
    };


    class SHA512 {
    public:
        static const int kHashSize = 64;
        static const int kHashSizeBits = 512;
        static const int kMsgBlockSize = 128;

        SHA512() = default;

        void init();
        int update(const uint8_t* bytes, unsigned int length);
        int finalBits(uint8_t bits, unsigned int length);
        int result(uint8_t msg_digest[kHashSize]);

    private:
        struct Context {
            uint64_t intermediate_hash[kHashSize / 8]; // Message Digest
            uint64_t length_high, length_low;   // Message length in bits

            int_least16_t msg_block_index;      // Message_Block array index
                                                // 1024-bit message blocks
            uint8_t msg_block[kMsgBlockSize];

            bool computed;                   // Is the hash computed?
            int corrupted;                  // Cumulative corruption code
        };

        static void processMessageBlock(Context* context);
        static void finalize(Context* context, uint8_t pad_byte);
        static void padMessage(Context* context, uint8_t pad_byte);

        Context context_;
    };


    class USHA {
    public:
        static const int kMaxHashSize = SHA512::kHashSize;
        static const int kMaxMsgBlockSize = SHA512::kMsgBlockSize;

        USHA() = default;

        int init(SHAVersion which);
        int update(const uint8_t* bytes, unsigned int length);
        int finalBits(uint8_t bits, unsigned int length);
        int result(uint8_t msg_digest[kMaxHashSize]);

        static int USHABlockSize(SHAVersion which);
        static int USHAHashSize(SHAVersion which);
        static int USHAHashSizeBits(SHAVersion which);
        static const char* USHAHashName(SHAVersion which);

    private:
        struct Context {
            SHAVersion which_sha;
            union {
                SHA1 sha1;
                SHA224 sha224;
                SHA256 sha256;
                SHA384 sha384;
                SHA512 sha512;
            } ctx;
        };

        Context context_;
    };


    class HMAC {
    public:
        HMAC() = default;

        /*
         * HMAC Keyed-Hashing for Message Authentication, RFC 2104,
         * for all SHAs.
         * This interface allows a fixed-length text input to be used.
         */
        static int calculate(
            SHAVersion which,
            const unsigned char* text,     // pointer to data stream
            int text_len,                  // length of data stream
            const unsigned char* key,      // pointer to authentication key
            int key_len,                   // length of authentication key
            uint8_t digest[USHA::kMaxHashSize]); // caller digest to fill in

        /*
         * HMAC Keyed-Hashing for Message Authentication, RFC 2104,
         * for all SHAs.
         * This interface allows any length of text input to be used.
         */
        int init(SHAVersion which, const unsigned char* key, int key_len);
        int update(const unsigned char* text, int text_len);
        int finalBits(uint8_t bits, unsigned int bit_count);
        int result(uint8_t digest[USHA::kMaxHashSize]);

    private:
        struct Context {
            SHAVersion which_sha;
            int hashSize;               // hash size of SHA being used
            int blockSize;              // block size of SHA being used
            USHA sha;
            unsigned char k_opad[USHA::kMaxMsgBlockSize];
            // outer padding - key XORd with opad
            bool computed;              // Is the MAC computed?
            int corrupted;              // Cumulative corruption code
        };

        Context context_;
    };


    class HKDF {
    public:
        HKDF() = default;

        /*
         * HKDF HMAC-based Extract-and-Expand Key Derivation Function,
         * RFC 5869, for all SHAs.
         */
        static int calculate(
            SHAVersion which, const unsigned char* salt,
            int salt_len, const unsigned char* ikm, int ikm_len,
            const unsigned char* info, int info_len,
            uint8_t okm[], int okm_len);
        static int hkdfExtract(
            SHAVersion which, const unsigned char* salt,
            int salt_len, const unsigned char* ikm,
            int ikm_len, uint8_t prk[USHA::kMaxHashSize]);
        static int hkdfExpand(
            SHAVersion which, const uint8_t prk[],
            int prk_len, const unsigned char* info,
            int info_len, uint8_t okm[], int okm_len);

        /*
         * HKDF HMAC-based Extract-and-Expand Key Derivation Function,
         * RFC 5869, for all SHAs.
         * This interface allows any length of text input to be used.
         */
        int init(
            SHAVersion which,
            const unsigned char* salt, int salt_len);
        int update(const unsigned char* ikm, int ikm_len);
        int finalBits(uint8_t ikm_bits, unsigned int ikm_bit_count);
        int result(
            uint8_t prk[USHA::kMaxHashSize],
            const unsigned char* info, int info_len,
            uint8_t okm[USHA::kMaxHashSize], int okm_len);

    private:
        struct Context {
            SHAVersion which_sha;
            HMAC hmac;
            int hashSize;               // hash size of SHA being used
            unsigned char prk[USHA::kMaxHashSize];
            // pseudo-random key - output of input
            bool computed;              // Is the key material computed?
            int corrupted;              // Cumulative corruption code
        };

        Context context_;
    };

}
}

#endif  // AKASH_SECURITY_DIGEST_SHA1_H_
