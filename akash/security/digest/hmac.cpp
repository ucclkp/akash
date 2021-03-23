// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/security/digest/sha.h"


namespace akash {
namespace digest {

    /*
     *  calculate
     *
     *  Description:
     *      This function will compute an HMAC message digest.
     *
     *  Parameters:
     *      which: [in]
     *          One of SHA1, SHA224, SHA256, SHA384, SHA512
     *      message_array[ ]: [in]
     *          An array of octets representing the message.
     *          Note: in RFC 2104, this parameter is known
     *          as 'text'.
     *      length: [in]
     *          The length of the message in message_array.
     *      key[ ]: [in]
     *          The secret shared key.
     *      key_len: [in]
     *          The length of the secret shared key.
     *      digest[ ]: [out]
     *          Where the digest is to be returned.
     *          NOTE: The length of the digest is determined by
     *              the value of which.
     *
     *  Returns:
     *      sha Error Code.
     *
     */
    int HMAC::calculate(
        SHAVersion which,
        const unsigned char* message_array, int length,
        const unsigned char* key, int key_len,
        uint8_t digest[USHA::kMaxHashSize])
    {
        HMAC hmac;
        return hmac.init(which, key, key_len) ||
            hmac.update(message_array, length) ||
            hmac.result(digest);
    }

    /*
     *  init
     *
     *  Description:
     *      This function will initialize the hmacContext in preparation
     *      for computing a new HMAC message digest.
     *
     *  Parameters:
     *      which: [in]
     *          One of SHA1, SHA224, SHA256, SHA384, SHA512
     *      key[ ]: [in]
     *          The secret shared key.
     *      key_len: [in]
     *          The length of the secret shared key.
     *
     *  Returns:
     *      sha Error Code.
     *
     */
    int HMAC::init(SHAVersion which, const unsigned char* key, int key_len) {
        int i;

        /* inner padding - key XORd with ipad */
        unsigned char k_ipad[USHA::kMaxMsgBlockSize];

        /* temporary buffer when keylen > blocksize */
        unsigned char tempkey[USHA::kMaxHashSize];
        context_.computed = false;
        context_.corrupted = shaSuccess;

        int blocksize = context_.blockSize = USHA::USHABlockSize(which);
        int hashsize = context_.hashSize = USHA::USHAHashSize(which);
        context_.which_sha = which;

        /*
         * If key is longer than the hash blocksize,
         * reset it to key = HASH(key).
         */
        if (key_len > blocksize) {
            USHA usha;
            int err = usha.init(which) ||
                usha.update(key, key_len) ||
                usha.result(tempkey);
            if (err != shaSuccess) return err;

            key = tempkey;
            key_len = hashsize;
        }

        /*
         * The HMAC transform looks like:
         *
         * SHA(K XOR opad, SHA(K XOR ipad, text))
         *
         * where K is an n byte key, 0-padded to a total of blocksize bytes,
         * ipad is the byte 0x36 repeated blocksize times,
         * opad is the byte 0x5c repeated blocksize times,
         * and text is the data being protected.
         */

         /* store key into the pads, XOR'd with ipad and opad values */
        for (i = 0; i < key_len; i++) {
            k_ipad[i] = key[i] ^ 0x36;
            context_.k_opad[i] = key[i] ^ 0x5c;
        }
        /* remaining pad bytes are '\0' XOR'd with ipad and opad values */
        for (; i < blocksize; i++) {
            k_ipad[i] = 0x36;
            context_.k_opad[i] = 0x5c;
        }

        /* perform inner hash */
        /* init context for 1st pass */
        int ret = context_.sha.init(which) ||
            /* and start with inner pad */
            context_.sha.update(k_ipad, blocksize);
        return context_.corrupted = ret;
    }

    /*
     *  update
     *
     *  Description:
     *      This function accepts an array of octets as the next portion
     *      of the message.  It may be called multiple times.
     *
     *  Parameters:
     *      text[ ]: [in]
     *          An array of octets representing the next portion of
     *          the message.
     *      text_len: [in]
     *          The length of the message in text.
     *
     *  Returns:
     *      sha Error Code.
     *
     */
    int HMAC::update(const unsigned char* text, int text_len) {
        if (context_.corrupted) return context_.corrupted;
        if (context_.computed) return context_.corrupted = shaStateError;
        /* then text of datagram */
        return context_.corrupted = context_.sha.update(text, text_len);
    }

    /*
     * finalBits
     *
     * Description:
     *   This function will add in any final bits of the message.
     *
     * Parameters:
     *   message_bits: [in]
     *     The final bits of the message, in the upper portion of the
     *     byte.  (Use 0b###00000 instead of 0b00000### to input the
     *     three bits ###.)
     *   length: [in]
     *     The number of bits in message_bits, between 1 and 7.
     *
     * Returns:
     *   sha Error Code.
     */
    int HMAC::finalBits(uint8_t bits, unsigned int bit_count) {
        if (context_.corrupted) return context_.corrupted;
        if (context_.computed) return context_.corrupted = shaStateError;
        /* then final bits of datagram */
        return context_.corrupted = context_.sha.finalBits(bits, bit_count);
    }

    /*
     * result
     *
     * Description:
     *   This function will return the N-byte message digest into the
     *   Message_Digest array provided by the caller.
     *
     * Parameters:
     *   digest[ ]: [out]
     *     Where the digest is returned.
     *     NOTE 2: The length of the hash is determined by the value of
     *      which_sha that was passed to init().
     *
     * Returns:
     *   sha Error Code.
     *
     */
    int HMAC::result(uint8_t *digest) {
        if (context_.corrupted) return context_.corrupted;
        if (context_.computed) return context_.corrupted = shaStateError;

        /* finish up 1st pass */
        /* (Use digest here as a temporary buffer.) */
        int ret = context_.sha.result(digest) ||

            /* perform outer SHA */
            /* init context for 2nd pass */
            context_.sha.init(context_.which_sha) ||

            /* start with outer pad */
            context_.sha.update(context_.k_opad, context_.blockSize) ||

            /* then results of 1st hash */
            context_.sha.update(digest, context_.hashSize) ||
            /* finish up 2nd pass */
            context_.sha.result(digest);

        context_.computed = true;
        return context_.corrupted = ret;
    }

}
}