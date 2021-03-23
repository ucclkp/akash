// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/security/digest/sha.h"

#include "sha_private.h"

/* Define the SHA shift, rotate left and rotate right macros */
#define SHA512_SHR(bits,word)  (((uint64_t)(word)) >> (bits))
#define SHA512_ROTR(bits,word) ((((uint64_t)(word)) >> (bits)) | \
                                (((uint64_t)(word)) << (64-(bits))))

/*
 * Define the SHA SIGMA and sigma macros
 *
 *  SHA512_ROTR(28,word) ^ SHA512_ROTR(34,word) ^ SHA512_ROTR(39,word)
 */
#define SHA512_SIGMA0(word)   \
 (SHA512_ROTR(28,word) ^ SHA512_ROTR(34,word) ^ SHA512_ROTR(39,word))
#define SHA512_SIGMA1(word)   \
 (SHA512_ROTR(14,word) ^ SHA512_ROTR(18,word) ^ SHA512_ROTR(41,word))
#define SHA512_sigma0(word)   \
 (SHA512_ROTR( 1,word) ^ SHA512_ROTR( 8,word) ^ SHA512_SHR( 7,word))
#define SHA512_sigma1(word)   \
 (SHA512_ROTR(19,word) ^ SHA512_ROTR(61,word) ^ SHA512_SHR( 6,word))


namespace akash {
namespace digest {

    /*
     * init
     *
     * Description:
     *   This function will initialize the Context in preparation
     *   for computing a new SHA384 message digest.
     *
     */
    void SHA384::init() {
        context_.msg_block_index = 0;
        context_.length_high = context_.length_low = 0;

        context_.intermediate_hash[0] = 0xCBBB9D5DC1059ED8ll;
        context_.intermediate_hash[1] = 0x629A292A367CD507ll;
        context_.intermediate_hash[2] = 0x9159015A3070DD17ll;
        context_.intermediate_hash[3] = 0x152FECD8F70E5939ll;
        context_.intermediate_hash[4] = 0x67332667FFC00B31ll;
        context_.intermediate_hash[5] = 0x8EB44A8768581511ll;
        context_.intermediate_hash[6] = 0xDB0C2E0D64F98FA7ll;
        context_.intermediate_hash[7] = 0x47B5481DBEFA4FA4ll;

        context_.computed = false;
        context_.corrupted = shaSuccess;
    }

    /*
     * update
     *
     * Description:
     *   This function accepts an array of octets as the next portion
     *   of the message.
     *
     * Parameters:
     *   bytes[ ]: [in]
     *     An array of octets representing the next portion of
     *     the message.
     *   length: [in]
     *     The length of the message in {bytes}.
     *
     * Returns:
     *   sha Error Code.
     *
     */
    int SHA384::update(const uint8_t* bytes, unsigned int length) {
        if (!length) return shaSuccess;
        if (!bytes) return shaNull;
        if (context_.corrupted) return context_.corrupted;
        if (context_.computed) return context_.corrupted = shaStateError;

        while (length--) {
            context_.msg_block[context_.msg_block_index++] = *bytes;

            if ((SHAAddLength64(context_, 8) == shaSuccess) &&
                (context_.msg_block_index == kMsgBlockSize))
                processMessageBlock(&context_);

            bytes++;
        }

        return context_.corrupted;
    }

    /*
     * finalBits
     *
     * Description:
     *   This function will add in any final bits of the message.
     *
     * Parameters:
     *   bits: [in]
     *     The final bits of the message, in the upper portion of the
     *     byte.  (Use 0b###00000 instead of 0b00000### to input the
     *     three bits ###.)
     *   length: [in]
     *     The number of bits in {bits}, between 1 and 7.
     *
     * Returns:
     *   sha Error Code.
     *
     */
    int SHA384::finalBits(uint8_t bits, unsigned int length) {
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

        if (!length) return shaSuccess;
        if (context_.corrupted) return context_.corrupted;
        if (context_.computed) return context_.corrupted = shaStateError;
        if (length >= 8) return context_.corrupted = shaBadParam;

        SHAAddLength64(context_, length);
        finalize(&context_, uint8_t((bits & masks[length]) | markbit[length]));

        return context_.corrupted;
    }

    /*
     * result
     *
     * Description:
     *   This function will return the 384-bit message digest
     *   into the msg_digest array provided by the caller.
     *   NOTE:
     *    The first octet of hash is stored in the element with index 0,
     *    the last octet of hash in the element with index 47.
     *
     * Parameters:
     *   msg_digest[ ]: [out]
     *     Where the digest is returned.
     *
     * Returns:
     *   sha Error Code.
     *
     */
    int SHA384::result(uint8_t msg_digest[kHashSize]) {
        if (!msg_digest) return shaNull;
        if (context_.corrupted) return context_.corrupted;

        if (!context_.computed)
            finalize(&context_, 0x80);

        for (int i = 0; i < kHashSize; ++i)
            msg_digest[i] = uint8_t(context_.intermediate_hash[i >> 3] >> 8 * (7 - (i % 8)));

        return shaSuccess;
    }

    /*
     * processMessageBlock
     *
     * Description:
     *   This helper function will process the next 1024 bits of the
     *   message stored in the Message_Block array.
     *
     * Parameters:
     *   context: [in/out]
     *     The SHA context to update.
     *
     * Returns:
     *   Nothing.
     *
     * Comments:
     *   Many of the variable names in this code, especially the
     *   single character names, were used because those were the
     *   names used in the Secure Hash Standard.
     *
     *
     */
    void SHA384::processMessageBlock(Context* context) {
        /* Constants defined in FIPS 180-3, section 4.2.3 */
        static const uint64_t K[80] = {
            0x428A2F98D728AE22ull, 0x7137449123EF65CDull, 0xB5C0FBCFEC4D3B2Full,
            0xE9B5DBA58189DBBCull, 0x3956C25BF348B538ull, 0x59F111F1B605D019ull,
            0x923F82A4AF194F9Bull, 0xAB1C5ED5DA6D8118ull, 0xD807AA98A3030242ull,
            0x12835B0145706FBEull, 0x243185BE4EE4B28Cull, 0x550C7DC3D5FFB4E2ull,
            0x72BE5D74F27B896Full, 0x80DEB1FE3B1696B1ull, 0x9BDC06A725C71235ull,
            0xC19BF174CF692694ull, 0xE49B69C19EF14AD2ull, 0xEFBE4786384F25E3ull,
            0x0FC19DC68B8CD5B5ull, 0x240CA1CC77AC9C65ull, 0x2DE92C6F592B0275ull,
            0x4A7484AA6EA6E483ull, 0x5CB0A9DCBD41FBD4ull, 0x76F988DA831153B5ull,
            0x983E5152EE66DFABull, 0xA831C66D2DB43210ull, 0xB00327C898FB213Full,
            0xBF597FC7BEEF0EE4ull, 0xC6E00BF33DA88FC2ull, 0xD5A79147930AA725ull,
            0x06CA6351E003826Full, 0x142929670A0E6E70ull, 0x27B70A8546D22FFCull,
            0x2E1B21385C26C926ull, 0x4D2C6DFC5AC42AEDull, 0x53380D139D95B3DFull,
            0x650A73548BAF63DEull, 0x766A0ABB3C77B2A8ull, 0x81C2C92E47EDAEE6ull,
            0x92722C851482353Bull, 0xA2BFE8A14CF10364ull, 0xA81A664BBC423001ull,
            0xC24B8B70D0F89791ull, 0xC76C51A30654BE30ull, 0xD192E819D6EF5218ull,
            0xD69906245565A910ull, 0xF40E35855771202Aull, 0x106AA07032BBD1B8ull,
            0x19A4C116B8D2D0C8ull, 0x1E376C085141AB53ull, 0x2748774CDF8EEB99ull,
            0x34B0BCB5E19B48A8ull, 0x391C0CB3C5C95A63ull, 0x4ED8AA4AE3418ACBull,
            0x5B9CCA4F7763E373ull, 0x682E6FF3D6B2B8A3ull, 0x748F82EE5DEFB2FCull,
            0x78A5636F43172F60ull, 0x84C87814A1F0AB72ull, 0x8CC702081A6439ECull,
            0x90BEFFFA23631E28ull, 0xA4506CEBDE82BDE9ull, 0xBEF9A3F7B2C67915ull,
            0xC67178F2E372532Bull, 0xCA273ECEEA26619Cull, 0xD186B8C721C0C207ull,
            0xEADA7DD6CDE0EB1Eull, 0xF57D4F7FEE6ED178ull, 0x06F067AA72176FBAull,
            0x0A637DC5A2C898A6ull, 0x113F9804BEF90DAEull, 0x1B710B35131C471Bull,
            0x28DB77F523047D84ull, 0x32CAAB7B40C72493ull, 0x3C9EBE0A15C9BEBCull,
            0x431D67C49C100D4Cull, 0x4CC5D4BECB3E42B6ull, 0x597F299CFC657E2Aull,
            0x5FCB6FAB3AD6FAECull, 0x6C44198C4A475817ull
        };
        int        t, t8;                   /* Loop counter */
        uint64_t   W[80];                   /* Word sequence */

        /*
         * Initialize the first 16 words in the array W
         */
        for (t = t8 = 0; t < 16; t++, t8 += 8)
            W[t] = (uint64_t(context->msg_block[t8]) << 56) |
            (uint64_t(context->msg_block[t8 + 1]) << 48) |
            (uint64_t(context->msg_block[t8 + 2]) << 40) |
            (uint64_t(context->msg_block[t8 + 3]) << 32) |
            (uint64_t(context->msg_block[t8 + 4]) << 24) |
            (uint64_t(context->msg_block[t8 + 5]) << 16) |
            (uint64_t(context->msg_block[t8 + 6]) << 8) |
            uint64_t(context->msg_block[t8 + 7]);

        for (t = 16; t < 80; t++)
            W[t] = SHA512_sigma1(W[t - 2]) + W[t - 7] +
            SHA512_sigma0(W[t - 15]) + W[t - 16];

        /* Word buffers */
        uint64_t A = context->intermediate_hash[0];
        uint64_t B = context->intermediate_hash[1];
        uint64_t C = context->intermediate_hash[2];
        uint64_t D = context->intermediate_hash[3];
        uint64_t E = context->intermediate_hash[4];
        uint64_t F = context->intermediate_hash[5];
        uint64_t G = context->intermediate_hash[6];
        uint64_t H = context->intermediate_hash[7];

        for (t = 0; t < 80; t++) {
            /* Temporary word value */
            uint64_t temp1 = H + SHA512_SIGMA1(E) + SHA_Ch(E, F, G) + K[t] + W[t];
            uint64_t temp2 = SHA512_SIGMA0(A) + SHA_Maj(A, B, C);
            H = G;
            G = F;
            F = E;
            E = D + temp1;
            D = C;
            C = B;
            B = A;
            A = temp1 + temp2;
        }

        context->intermediate_hash[0] += A;
        context->intermediate_hash[1] += B;
        context->intermediate_hash[2] += C;
        context->intermediate_hash[3] += D;
        context->intermediate_hash[4] += E;
        context->intermediate_hash[5] += F;
        context->intermediate_hash[6] += G;
        context->intermediate_hash[7] += H;

        context->msg_block_index = 0;
    }

    /*
     * finalize
     *
     * Description:
     *   This helper function finishes off the digest calculations.
     *
     * Parameters:
     *   context: [in/out]
     *     The SHA context to update.
     *   pad_byte: [in]
     *     The last byte to add to the message block before the 0-padding
     *     and length.  This will contain the last bits of the message
     *     followed by another single bit.  If the message was an
     *     exact multiple of 8-bits long, pad_byte will be 0x80.
     *
     * Returns:
     *   sha Error Code.
     *
     */
    void SHA384::finalize(Context* context, uint8_t pad_byte) {
        padMessage(context, pad_byte);
        /* message may be sensitive, clear it out */
        for (int i = 0; i < kMsgBlockSize; ++i)
            context->msg_block[i] = 0;

        context->length_high = context->length_low = 0;
        context->computed = true;
    }

    /*
     * padMessage
     *
     * Description:
     *   According to the standard, the message must be padded to the next
     *   even multiple of 1024 bits.  The first padding bit must be a '1'.
     *   The last 128 bits represent the length of the original message.
     *   All bits in between should be 0.  This helper function will
     *   pad the message according to those rules by filling the
     *   Message_Block array accordingly.  When it returns, it can be
     *   assumed that the message digest has been computed.
     *
     * Parameters:
     *   context: [in/out]
     *     The context to pad.
     *   pad_byte: [in]
     *     The last byte to add to the message block before the 0-padding
     *     and length.  This will contain the last bits of the message
     *     followed by another single bit.  If the message was an
     *     exact multiple of 8-bits long, pad_byte will be 0x80.
     *
     * Returns:
     *   Nothing.
     *
     */
    void SHA384::padMessage(Context* context, uint8_t pad_byte) {
        /*
         * Check to see if the current message block is too small to hold
         * the initial padding bits and length.  If so, we will pad the
         * block, process it, and then continue padding into a second
         * block.
         */
        if (context->msg_block_index >= (kMsgBlockSize - 16)) {
            context->msg_block[context->msg_block_index++] = pad_byte;
            while (context->msg_block_index < kMsgBlockSize)
                context->msg_block[context->msg_block_index++] = 0;

            processMessageBlock(context);
        } else
            context->msg_block[context->msg_block_index++] = pad_byte;

        while (context->msg_block_index < (kMsgBlockSize - 16))
            context->msg_block[context->msg_block_index++] = 0;

        /*
         * Store the message length as the last 16 octets
         */
        context->msg_block[112] = uint8_t(context->length_high >> 56);
        context->msg_block[113] = uint8_t(context->length_high >> 48);
        context->msg_block[114] = uint8_t(context->length_high >> 40);
        context->msg_block[115] = uint8_t(context->length_high >> 32);
        context->msg_block[116] = uint8_t(context->length_high >> 24);
        context->msg_block[117] = uint8_t(context->length_high >> 16);
        context->msg_block[118] = uint8_t(context->length_high >> 8);
        context->msg_block[119] = uint8_t(context->length_high);

        context->msg_block[120] = uint8_t(context->length_low >> 56);
        context->msg_block[121] = uint8_t(context->length_low >> 48);
        context->msg_block[122] = uint8_t(context->length_low >> 40);
        context->msg_block[123] = uint8_t(context->length_low >> 32);
        context->msg_block[124] = uint8_t(context->length_low >> 24);
        context->msg_block[125] = uint8_t(context->length_low >> 16);
        context->msg_block[126] = uint8_t(context->length_low >> 8);
        context->msg_block[127] = uint8_t(context->length_low);

        processMessageBlock(context);
    }

}
}