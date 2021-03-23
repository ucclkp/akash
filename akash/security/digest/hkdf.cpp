// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/security/digest/sha.h"

#include <memory>


namespace akash {
namespace digest {

    /*
     *  calculate
     *
     *  Description:
     *      This function will generate keying material using HKDF.
     *
     *  Parameters:
     *      which_sha: [in]
     *          One of SHA1, SHA224, SHA256, SHA384, SHA512
     *      salt[ ]: [in]
     *          The optional salt value (a non-secret random value);
     *          if not provided (salt == NULL), it is set internally
     *          to a string of HashLen(which_sha) zeros.
     *      salt_len: [in]
     *          The length of the salt value.  (Ignored if salt == NULL.)
     *      ikm[ ]: [in]
     *          Input keying material.
     *      ikm_len: [in]
     *          The length of the input keying material.
     *      info[ ]: [in]
     *          The optional context and application specific information.
     *          If info == NULL or a zero-length string, it is ignored.
     *      info_len: [in]
     *          The length of the optional context and application specific
     *          information.  (Ignored if info == NULL.)
     *      okm[ ]: [out]
     *          Where the HKDF is to be stored.
     *      okm_len: [in]
     *          The length of the buffer to hold okm.
     *          okm_len must be <= 255 * USHABlockSize(which_sha)
     *
     *  Notes:
     *      Calls hkdfExtract() and hkdfExpand().
     *
     *  Returns:
     *      sha Error Code.
     *
     */
    int HKDF::calculate(
        SHAVersion which,
        const unsigned char *salt, int salt_len,
        const unsigned char *ikm, int ikm_len,
        const unsigned char *info, int info_len,
        uint8_t okm[], int okm_len)
    {
        uint8_t prk[USHA::kMaxHashSize];
        return hkdfExtract(which, salt, salt_len, ikm, ikm_len, prk) ||
            hkdfExpand(which, prk, USHA::USHAHashSize(which), info,
                info_len, okm, okm_len);
    }

    /*
     *  hkdfExtract
     *
     *  Description:
     *      This function will perform HKDF extraction.
     *
     *  Parameters:
     *      which_sha: [in]
     *          One of SHA1, SHA224, SHA256, SHA384, SHA512
     *      salt[ ]: [in]
     *          The optional salt value (a non-secret random value);
     *          if not provided (salt == NULL), it is set internally
     *          to a string of HashLen(which_sha) zeros.
     *      salt_len: [in]
     *          The length of the salt value.  (Ignored if salt == NULL.)
     *      ikm[ ]: [in]
     *          Input keying material.
     *      ikm_len: [in]
     *          The length of the input keying material.
     *      prk[ ]: [out]
     *          Array where the HKDF extraction is to be stored.
     *          Must be larger than USHAHashSize(which_sha);
     *
     *  Returns:
     *      sha Error Code.
     *
     */
    int HKDF::hkdfExtract(
        SHAVersion which,
        const unsigned char *salt, int salt_len,
        const unsigned char *ikm, int ikm_len,
        uint8_t prk[USHA::kMaxHashSize])
    {
        unsigned char nullSalt[USHA::kMaxHashSize];
        if (!salt) {
            salt = nullSalt;
            salt_len = USHA::USHAHashSize(which);
            std::memset(nullSalt, '\0', salt_len);
        } else if (salt_len < 0) {
            return shaBadParam;
        }
        return HMAC::calculate(which, ikm, ikm_len, salt, salt_len, prk);
    }

    /*
     *  hkdfExpand
     *
     *  Description:
     *      This function will perform HKDF expansion.
     *
     *  Parameters:
     *      which_sha: [in]
     *          One of SHA1, SHA224, SHA256, SHA384, SHA512
     *      prk[ ]: [in]
     *          The pseudo-random key to be expanded; either obtained
     *          directly from a cryptographically strong, uniformly
     *          distributed pseudo-random number generator, or as the
     *          output from hkdfExtract().
     *      prk_len: [in]
     *          The length of the pseudo-random key in prk;
     *          should at least be equal to USHAHashSize(whichSHA).
     *      info[ ]: [in]
     *          The optional context and application specific information.
     *          If info == NULL or a zero-length string, it is ignored.
     *      info_len: [in]
     *          The length of the optional context and application specific
     *          information.  (Ignored if info == NULL.)
     *      okm[ ]: [out]
     *          Where the HKDF is to be stored.
     *      okm_len: [in]
     *          The length of the buffer to hold okm.
     *          okm_len must be <= 255 * USHABlockSize(which_sha)
     *
     *  Returns:
     *      sha Error Code.
     *
     */
    int HKDF::hkdfExpand(
        SHAVersion which, const uint8_t prk[], int prk_len,
        const unsigned char *info, int info_len, uint8_t okm[], int okm_len)
    {
        unsigned char T[USHA::kMaxHashSize];

        if (!info) {
            info = reinterpret_cast<const unsigned char *>("");
            info_len = 0;
        } else if (info_len < 0) {
            return shaBadParam;
        }
        if (okm_len <= 0) return shaBadParam;
        if (!okm) return shaBadParam;

        int hash_len = USHA::USHAHashSize(which);
        if (prk_len < hash_len) return shaBadParam;
        int N = okm_len / hash_len;
        if ((okm_len % hash_len) != 0) N++;
        if (N > 255) return shaBadParam;

        int Tlen = 0;
        int where = 0;
        for (int i = 1; i <= N; i++) {
            HMAC hmac;
            unsigned char c = i;
            int ret = hmac.init(which, prk, prk_len) ||
                hmac.update(T, Tlen) ||
                hmac.update(info, info_len) ||
                hmac.update(&c, 1) ||
                hmac.result(T);
            if (ret != shaSuccess) return ret;
            std::memcpy(okm + where, T,
                (i != N) ? hash_len : (okm_len - where));
            where += hash_len;
            Tlen = hash_len;
        }
        return shaSuccess;
    }

    /*
     *  init
     *
     *  Description:
     *      This function will initialize the hkdfContext in preparation
     *      for key derivation using the modular HKDF interface for
     *      arbitrary length inputs.
     *
     *  Parameters:
     *      which_sha: [in]
     *          One of SHA1, SHA224, SHA256, SHA384, SHA512
     *      salt[ ]: [in]
     *          The optional salt value (a non-secret random value);
     *          if not provided (salt == NULL), it is set internally
     *          to a string of HashLen(which_sha) zeros.
     *      salt_len: [in]
     *          The length of the salt value.  (Ignored if salt == NULL.)
     *
     *  Returns:
     *      sha Error Code.
     *
     */
    int HKDF::init(
        SHAVersion which,
        const unsigned char* salt, int salt_len)
    {
        unsigned char nullSalt[USHA::kMaxHashSize];

        context_.which_sha = which;
        context_.hashSize = USHA::USHAHashSize(which);
        context_.computed = false;
        if (!salt) {
            salt = nullSalt;
            salt_len = context_.hashSize;
            std::memset(nullSalt, '\0', salt_len);
        }

        return context_.hmac.init(which, salt, salt_len);
    }

    /*
     *  input
     *
     *  Description:
     *      This function accepts an array of octets as the next portion
     *      of the input keying material.  It may be called multiple times.
     *
     *  Parameters:
     *      ikm[ ]: [in]
     *          An array of octets representing the next portion of
     *          the input keying material.
     *      ikm_len: [in]
     *          The length of ikm.
     *
     *  Returns:
     *      sha Error Code.
     *
     */
    int HKDF::update(const unsigned char* ikm, int ikm_len) {
        if (context_.corrupted) return context_.corrupted;
        if (context_.computed) return context_.corrupted = shaStateError;
        return context_.hmac.update(ikm, ikm_len);
    }

    /*
     * finalBits
     *
     * Description:
     *   This function will add in any final bits of the
     *   input keying material.
     *
     * Parameters:
     *   ikm_bits: [in]
     *     The final bits of the input keying material, in the upper
     *     portion of the byte.  (Use 0b###00000 instead of 0b00000###
     *     to input the three bits ###.)
     *   ikm_bit_count: [in]
     *     The number of bits in message_bits, between 1 and 7.
     *
     * Returns:
     *   sha Error Code.
     */
    int HKDF::finalBits(uint8_t ikm_bits, unsigned int ikm_bit_count) {
        if (context_.corrupted) return context_.corrupted;
        if (context_.computed) return context_.corrupted = shaStateError;
        return context_.hmac.finalBits(ikm_bits, ikm_bit_count);
    }

    /*
     * result
     *
     * Description:
     *   This function will finish the HKDF extraction and perform the
     *   final HKDF expansion.
     *
     * Parameters:
     *   prk[ ]: [out]
     *     An optional location to store the HKDF extraction.
     *     Either NULL, or pointer to a buffer that must be
     *     larger than USHAHashSize(which_sha);
     *   info[ ]: [in]
     *     The optional context and application specific information.
     *     If info == NULL or a zero-length string, it is ignored.
     *   info_len: [in]
     *     The length of the optional context and application specific
     *     information.  (Ignored if info == NULL.)
     *   okm[ ]: [out]
     *     Where the HKDF is to be stored.
     *   okm_len: [in]
     *     The length of the buffer to hold okm.
     *     okm_len must be <= 255 * USHABlockSize(which_sha)
     *
     * Returns:
     *   sha Error Code.
     *
     */
    int HKDF::result(
        uint8_t prk[USHA::kMaxHashSize],
        const unsigned char* info, int info_len,
        uint8_t okm[], int okm_len)
    {
        uint8_t prkbuf[USHA::kMaxHashSize];

        if (context_.corrupted) return context_.corrupted;
        if (context_.computed) return context_.corrupted = shaStateError;
        if (!okm) return context_.corrupted = shaBadParam;
        if (!prk) prk = prkbuf;

        int ret = context_.hmac.result(prk) ||
            hkdfExpand(context_.which_sha, prk, context_.hashSize, info,
                info_len, okm, okm_len);
        context_.computed = true;
        return context_.corrupted = ret;
    }

}
}