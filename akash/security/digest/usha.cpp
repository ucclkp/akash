// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/security/digest/sha.h"


namespace akash {
namespace digest {

    /*
     *  init
     *
     *  Description:
     *      This function will initialize the SHA Context in preparation
     *      for computing a new SHA message digest.
     *
     *  Parameters:
     *      which: [in]
     *          Selects which SHA reset to call
     *
     *  Returns:
     *      sha Error Code.
     *
     */
    int USHA::init(SHAVersion which) {
        context_.which_sha = which;
        switch (which) {
        case SHAVersion::SHA1:   context_.ctx.sha1.init();   break;
        case SHAVersion::SHA224: context_.ctx.sha224.init(); break;
        case SHAVersion::SHA256: context_.ctx.sha256.init(); break;
        case SHAVersion::SHA384: context_.ctx.sha384.init(); break;
        case SHAVersion::SHA512: context_.ctx.sha512.init(); break;
        default:
            return shaBadParam;
        }

        return shaSuccess;
    }

    /*
     *  update
     *
     *  Description:
     *      This function accepts an array of octets as the next portion
     *      of the message.
     *
     *  Parameters:
     *      message_array: [in]
     *          An array of octets representing the next portion of
     *          the message.
     *      length: [in]
     *          The length of the message in message_array.
     *
     *  Returns:
     *      sha Error Code.
     *
     */
    int USHA::update(const uint8_t* bytes, unsigned int length) {
        switch (context_.which_sha) {
        case SHAVersion::SHA1:
            return context_.ctx.sha1.update(bytes, length);
        case SHAVersion::SHA224:
            return context_.ctx.sha224.update(bytes, length);
        case SHAVersion::SHA256:
            return context_.ctx.sha256.update(bytes, length);
        case SHAVersion::SHA384:
            return context_.ctx.sha384.update(bytes, length);
        case SHAVersion::SHA512:
            return context_.ctx.sha512.update(bytes, length);
        default: return shaBadParam;
        }
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
     *     The number of bits in message_bits, between 1 and 7.
     *
     * Returns:
     *   sha Error Code.
     */
    int USHA::finalBits(uint8_t bits, unsigned int length) {
        switch (context_.which_sha) {
        case SHAVersion::SHA1:
            return context_.ctx.sha1.finalBits(bits, length);
        case SHAVersion::SHA224:
            return context_.ctx.sha224.finalBits(bits, length);
        case SHAVersion::SHA256:
            return context_.ctx.sha256.finalBits(bits, length);
        case SHAVersion::SHA384:
            return context_.ctx.sha384.finalBits(bits, length);
        case SHAVersion::SHA512:
            return context_.ctx.sha512.finalBits(bits, length);
        default: return shaBadParam;
        }
    }

    /*
     * result
     *
     * Description:
     *   This function will return the message digest of the appropriate
     *   bit size, as returned by USHAHashSizeBits(whichSHA) for the
     *   'whichSHA' value used in the preceeding call to init,
     *   into the msg_digest array provided by the caller.
     *
     * Parameters:
     *   msg_digest: [out]
     *     Where the digest is returned.
     *
     * Returns:
     *   sha Error Code.
     *
     */
    int USHA::result(uint8_t msg_digest[kMaxHashSize]) {
        switch (context_.which_sha) {
        case SHAVersion::SHA1:
            return context_.ctx.sha1.result(msg_digest);
        case SHAVersion::SHA224:
            return context_.ctx.sha224.result(msg_digest);
        case SHAVersion::SHA256:
            return context_.ctx.sha256.result(msg_digest);
        case SHAVersion::SHA384:
            return context_.ctx.sha384.result(msg_digest);
        case SHAVersion::SHA512:
            return context_.ctx.sha512.result(msg_digest);
        default: return shaBadParam;
        }
    }

    /*
     * USHABlockSize
     *
     * Description:
     *   This function will return the blocksize for the given SHA
     *   algorithm.
     *
     * Parameters:
     *   which:
     *     which SHA algorithm to query
     *
     * Returns:
     *   block size
     *
     */
    int USHA::USHABlockSize(SHAVersion which) {
        switch (which) {
        case SHAVersion::SHA1:   return SHA1::kMsgBlockSize;
        case SHAVersion::SHA224: return SHA224::kMsgBlockSize;
        case SHAVersion::SHA256: return SHA256::kMsgBlockSize;
        case SHAVersion::SHA384: return SHA384::kMsgBlockSize;
        default:
        case SHAVersion::SHA512: return SHA512::kMsgBlockSize;
        }
    }

    /*
     * USHAHashSize
     *
     * Description:
     *   This function will return the hashsize for the given SHA
     *   algorithm.
     *
     * Parameters:
     *   which:
     *     which SHA algorithm to query
     *
     * Returns:
     *   hash size
     *
     */
    int USHA::USHAHashSize(SHAVersion which) {
        switch (which) {
        case SHAVersion::SHA1:   return SHA1::kHashSize;
        case SHAVersion::SHA224: return SHA224::kHashSize;
        case SHAVersion::SHA256: return SHA256::kHashSize;
        case SHAVersion::SHA384: return SHA384::kHashSize;
        default:
        case SHAVersion::SHA512: return SHA512::kHashSize;
        }
    }

    /*
     * USHAHashSizeBits
     *
     * Description:
     *   This function will return the hashsize for the given SHA
     *   algorithm, expressed in bits.
     *
     * Parameters:
     *   which:
     *     which SHA algorithm to query
     *
     * Returns:
     *   hash size in bits
     *
     */
    int USHA::USHAHashSizeBits(SHAVersion which) {
        switch (which) {
        case SHAVersion::SHA1:   return SHA1::kHashSizeBits;
        case SHAVersion::SHA224: return SHA224::kHashSizeBits;
        case SHAVersion::SHA256: return SHA256::kHashSizeBits;
        case SHAVersion::SHA384: return SHA384::kHashSizeBits;
        default:
        case SHAVersion::SHA512: return SHA512::kHashSizeBits;
        }
    }

    /*
     * USHAHashName
     *
     * Description:
     *   This function will return the name of the given SHA algorithm
     *   as a string.
     *
     * Parameters:
     *   which:
     *     which SHA algorithm to query
     *
     * Returns:
     *   character string with the name in it
     *
     */
    const char* USHA::USHAHashName(SHAVersion which) {
        switch (which) {
        case SHAVersion::SHA1:   return "SHA1";
        case SHAVersion::SHA224: return "SHA224";
        case SHAVersion::SHA256: return "SHA256";
        case SHAVersion::SHA384: return "SHA384";
        default:
        case SHAVersion::SHA512: return "SHA512";
        }
    }

}
}