// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/security/digest/sha.h"

#include "sha_private.h"

/* Define the SHA shift, rotate left, and rotate right macros */
#define SHA256_SHR(bits,word)      ((word) >> (bits))
#define SHA256_ROTL(bits,word)                         \
  (((word) << (bits)) | ((word) >> (32-(bits))))
#define SHA256_ROTR(bits,word)                         \
  (((word) >> (bits)) | ((word) << (32-(bits))))

/* Define the SHA SIGMA and sigma macros */
#define SHA256_SIGMA0(word)   \
  (SHA256_ROTR( 2,word) ^ SHA256_ROTR(13,word) ^ SHA256_ROTR(22,word))
#define SHA256_SIGMA1(word)   \
  (SHA256_ROTR( 6,word) ^ SHA256_ROTR(11,word) ^ SHA256_ROTR(25,word))
#define SHA256_sigma0(word)   \
  (SHA256_ROTR( 7,word) ^ SHA256_ROTR(18,word) ^ SHA256_SHR( 3,word))
#define SHA256_sigma1(word)   \
  (SHA256_ROTR(17,word) ^ SHA256_ROTR(19,word) ^ SHA256_SHR(10,word))


namespace akash {
namespace digest {

    /*
     * init
     *
     * Description:
     *   This function will initialize the Context in preparation
     *   for computing a new SHA256 message digest.
     *
     */
    void SHA256::init() {
        context_.length_high = context_.length_low = 0;
        context_.msg_block_index = 0;

        context_.intermediate_hash[0] = 0x6A09E667;
        context_.intermediate_hash[1] = 0xBB67AE85;
        context_.intermediate_hash[2] = 0x3C6EF372;
        context_.intermediate_hash[3] = 0xA54FF53A;
        context_.intermediate_hash[4] = 0x510E527F;
        context_.intermediate_hash[5] = 0x9B05688C;
        context_.intermediate_hash[6] = 0x1F83D9AB;
        context_.intermediate_hash[7] = 0x5BE0CD19;

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
     */
    int SHA256::update(const uint8_t* bytes, unsigned int length) {
        if (!length) return shaSuccess;
        if (!bytes) return shaNull;
        if (context_.corrupted) return context_.corrupted;
        if (context_.computed) return context_.corrupted = shaStateError;

        while (length--) {
            context_.msg_block[context_.msg_block_index++] =
                *bytes;

            if ((SHAAddLength32(context_, 8) == shaSuccess) &&
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
     */
    int SHA256::finalBits(uint8_t bits, unsigned int length) {
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

        SHAAddLength32(context_, length);
        finalize(&context_, uint8_t((bits & masks[length]) | markbit[length]));

        return context_.corrupted;
    }

    /*
     * result
     *
     * Description:
     *   This function will return the 256-bit message digest
     *   into the msg_digest array provided by the caller.
     *   NOTE:
     *    The first octet of hash is stored in the element with index 0,
     *    the last octet of hash in the element with index 31.
     *
     * Parameters:
     *   msg_digest[ ]: [out]
     *     Where the digest is returned.
     *
     * Returns:
     *   sha Error Code.
      */
    int SHA256::result(uint8_t msg_digest[kHashSize]) {
        if (!msg_digest) return shaNull;
        if (context_.corrupted) return context_.corrupted;

        if (!context_.computed)
            finalize(&context_, 0x80);

        for (int i = 0; i < kHashSize; ++i)
            msg_digest[i] = uint8_t(context_.intermediate_hash[i >> 2] >> 8 * (3 - (i & 0x03)));

        return shaSuccess;
    }

    /*
     * processMessageBlock
     *
     * Description:
     *   This helper function will process the next 512 bits of the
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
     */
    void SHA256::processMessageBlock(Context* context) {
        /* Constants defined in FIPS 180-3, section 4.2.2 */
        static const uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
            0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
            0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
            0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
            0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
            0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
            0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
            0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
            0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };
        int        t, t4;                   /* Loop counter */
        uint32_t   W[64];                   /* Word sequence */

        /*
         * Initialize the first 16 words in the array W
         */
        for (t = t4 = 0; t < 16; t++, t4 += 4)
            W[t] = (uint32_t(context->msg_block[t4]) << 24) |
            (uint32_t(context->msg_block[t4 + 1]) << 16) |
            (uint32_t(context->msg_block[t4 + 2]) << 8) |
            (uint32_t(context->msg_block[t4 + 3]));
        for (t = 16; t < 64; t++)
            W[t] = SHA256_sigma1(W[t - 2]) + W[t - 7] +
            SHA256_sigma0(W[t - 15]) + W[t - 16];

        /* Word buffers */
        uint32_t A = context->intermediate_hash[0];
        uint32_t B = context->intermediate_hash[1];
        uint32_t C = context->intermediate_hash[2];
        uint32_t D = context->intermediate_hash[3];
        uint32_t E = context->intermediate_hash[4];
        uint32_t F = context->intermediate_hash[5];
        uint32_t G = context->intermediate_hash[6];
        uint32_t H = context->intermediate_hash[7];

        for (t = 0; t < 64; t++) {
            /* Temporary word value */
            uint32_t temp1 = H + SHA256_SIGMA1(E) + SHA_Ch(E, F, G) + K[t] + W[t];
            uint32_t temp2 = SHA256_SIGMA0(A) + SHA_Maj(A, B, C);
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
     */
    void SHA256::finalize(Context* context, uint8_t pad_byte) {
        padMessage(context, pad_byte);
        /* message may be sensitive, so clear it out */
        for (int i = 0; i < kMsgBlockSize; ++i)
            context->msg_block[i] = 0;
        context->length_high = 0;     /* and clear length */
        context->length_low = 0;
        context->computed = true;
    }

    /*
     * padMessage
     *
     * Description:
     *   According to the standard, the message must be padded to the next
     *   even multiple of 512 bits.  The first padding bit must be a '1'.
     *   The last 64 bits represent the length of the original message.
     *   All bits in between should be 0.  This helper function will pad
     *   the message according to those rules by filling the
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
     */
    void SHA256::padMessage(Context* context, uint8_t pad_byte) {
        /*
         * Check to see if the current message block is too small to hold
         * the initial padding bits and length.  If so, we will pad the
         * block, process it, and then continue padding into a second
         * block.
         */
        if (context->msg_block_index >= (kMsgBlockSize - 8)) {
            context->msg_block[context->msg_block_index++] = pad_byte;
            while (context->msg_block_index < kMsgBlockSize)
                context->msg_block[context->msg_block_index++] = 0;
            processMessageBlock(context);
        } else
            context->msg_block[context->msg_block_index++] = pad_byte;

        while (context->msg_block_index < (kMsgBlockSize - 8))
            context->msg_block[context->msg_block_index++] = 0;

        /*
         * Store the message length as the last 8 octets
         */
        context->msg_block[56] = static_cast<uint8_t>(context->length_high >> 24);
        context->msg_block[57] = static_cast<uint8_t>(context->length_high >> 16);
        context->msg_block[58] = static_cast<uint8_t>(context->length_high >> 8);
        context->msg_block[59] = static_cast<uint8_t>(context->length_high);
        context->msg_block[60] = static_cast<uint8_t>(context->length_low >> 24);
        context->msg_block[61] = static_cast<uint8_t>(context->length_low >> 16);
        context->msg_block[62] = static_cast<uint8_t>(context->length_low >> 8);
        context->msg_block[63] = static_cast<uint8_t>(context->length_low);

        processMessageBlock(context);
    }

}
}