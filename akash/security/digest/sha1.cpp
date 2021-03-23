// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/security/digest/sha.h"

#include "sha_private.h"

/*
 *  Define the SHA1 circular left shift macro
 */
#define SHA1_ROTL(bits,word) \
                (((word) << (bits)) | ((word) >> (32-(bits))))


namespace akash {
namespace digest {

    /**
     *  init
     *
     *  Description:
     *      This function will initialize the Context in preparation
     *      for computing a new SHA1 message digest.
     *
     *  Returns:
     *      sha Error Code.
     *
     */
    void SHA1::init()
    {
        context_.length_high = context_.length_low = 0;
        context_.msg_block_index = 0;

        /* Initial Hash Values: FIPS 180-3 section 5.3.1 */
        context_.intermediate_hash[0] = 0x67452301;
        context_.intermediate_hash[1] = 0xEFCDAB89;
        context_.intermediate_hash[2] = 0x98BADCFE;
        context_.intermediate_hash[3] = 0x10325476;
        context_.intermediate_hash[4] = 0xC3D2E1F0;

        context_.computed = false;
        context_.corrupted = shaSuccess;
    }

    /*
     *  update
     *
     *  Description:
     *      This function accepts an array of octets as the next portion
     *      of the message.
     *
     *  Parameters:
     *      bytes[ ]: [in]
     *          An array of octets representing the next portion of
     *          the message.
     *      length: [in]
     *          The length of the message in bytes.
     *
     *  Returns:
     *      sha Error Code.
     *
     */
    int SHA1::update(const uint8_t* bytes, unsigned length) {
        if (!length) return shaSuccess;
        if (!bytes) return shaNull;
        if (context_.corrupted) return context_.corrupted;
        if (context_.computed) return context_.corrupted = shaStateError;

        while (length--) {
            context_.msg_block[context_.msg_block_index++] = *bytes;

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
    int SHA1::finalBits(uint8_t bits, unsigned int length) {
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
     *   This function will return the 160-bit message digest
     *   into the msg_digest array provided by the caller.
     *   NOTE:
     *    The first octet of hash is stored in the element with index 0,
     *      the last octet of hash in the element with index 19.
     *
     * Parameters:
     *   msg_digest[ ]: [out]
     *     Where the digest is returned.
     *
     * Returns:
     *   sha Error Code.
     *
     */
    int SHA1::result(uint8_t msg_digest[kHashSize]) {
        if (!msg_digest) return shaNull;
        if (context_.corrupted) return context_.corrupted;

        if (!context_.computed)
            finalize(&context_, 0x80);

        for (int i = 0; i < kHashSize; ++i)
            msg_digest[i] = uint8_t(context_.intermediate_hash[i >> 2] >> (8 * (3 - (i & 0x03))));

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
    void SHA1::processMessageBlock(Context* context) {
        /* Constants defined in FIPS 180-3, section 4.2.1 */
        const uint32_t K[4] = {
            0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
        };
        int        t;               /* Loop counter */
        uint32_t   temp;            /* Temporary word value */
        uint32_t   W[80];           /* Word sequence */

        /*
         * Initialize the first 16 words in the array W
         */
        for (t = 0; t < 16; t++) {
            W[t] = static_cast<uint32_t>(context->msg_block[t * 4]) << 24;
            W[t] |= static_cast<uint32_t>(context->msg_block[t * 4 + 1]) << 16;
            W[t] |= static_cast<uint32_t>(context->msg_block[t * 4 + 2]) << 8;
            W[t] |= static_cast<uint32_t>(context->msg_block[t * 4 + 3]);
        }

        for (t = 16; t < 80; t++)
            W[t] = SHA1_ROTL(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);

        // Word buffers
        uint32_t A = context->intermediate_hash[0];
        uint32_t B = context->intermediate_hash[1];
        uint32_t C = context->intermediate_hash[2];
        uint32_t D = context->intermediate_hash[3];
        uint32_t E = context->intermediate_hash[4];

        for (t = 0; t < 20; t++) {
            temp = SHA1_ROTL(5, A) + SHA_Ch(B, C, D) + E + W[t] + K[0];
            E = D;
            D = C;
            C = SHA1_ROTL(30, B);
            B = A;
            A = temp;
        }

        for (t = 20; t < 40; t++) {
            temp = SHA1_ROTL(5, A) + SHA_Parity(B, C, D) + E + W[t] + K[1];
            E = D;
            D = C;
            C = SHA1_ROTL(30, B);
            B = A;
            A = temp;
        }

        for (t = 40; t < 60; t++) {
            temp = SHA1_ROTL(5, A) + SHA_Maj(B, C, D) + E + W[t] + K[2];
            E = D;
            D = C;
            C = SHA1_ROTL(30, B);
            B = A;
            A = temp;
        }

        for (t = 60; t < 80; t++) {
            temp = SHA1_ROTL(5, A) + SHA_Parity(B, C, D) + E + W[t] + K[3];
            E = D;
            D = C;
            C = SHA1_ROTL(30, B);
            B = A;
            A = temp;
        }

        context->intermediate_hash[0] += A;
        context->intermediate_hash[1] += B;
        context->intermediate_hash[2] += C;
        context->intermediate_hash[3] += D;
        context->intermediate_hash[4] += E;
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
    void SHA1::finalize(Context* context, uint8_t pad_byte) {
        padMessage(context, pad_byte);
        /* message may be sensitive, clear it out */
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
     *   the message according to those rules by filling the Message_Block
     *   array accordingly.  When it returns, it can be assumed that the
     *   message digest has been computed.
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
    void SHA1::padMessage(Context* context, uint8_t pad_byte) {
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