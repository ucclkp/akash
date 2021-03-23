// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef SHA_PRIVATE_H_
#define SHA_PRIVATE_H_

#include <cstdint>


/*
 * These definitions are defined in FIPS 180-3, section 4.1.
 * Ch() and Maj() are defined identically in sections 4.1.1,
 * 4.1.2, and 4.1.3.
 *
 * The definitions used in FIPS 180-3 are as follows:
 */
#ifndef USE_MODIFIED_MACROS
#define SHA_Ch(x,y,z)        (((x) & (y)) ^ ((~(x)) & (z)))
#define SHA_Maj(x,y,z)       (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#else /* USE_MODIFIED_MACROS */
 /*
  * The following definitions are equivalent and potentially faster.
  */
#define SHA_Ch(x, y, z)      (((x) & ((y) ^ (z))) ^ (z))
#define SHA_Maj(x, y, z)     (((x) & ((y) | (z))) | ((y) & (z)))

#endif /* USE_MODIFIED_MACROS */

#define SHA_Parity(x, y, z)  ((x) ^ (y) ^ (z))

/*
 * Add "length" to the length.
 * Set Corrupted when overflow has occurred.
 */
static uint32_t addTemp32;
#define SHAAddLength32(context, length)                     \
    (addTemp32 = (context).length_low,                      \
     (context).corrupted =                                  \
        (((context).length_low += (length)) < addTemp32) && \
        (++(context).length_high == 0) ? shaInputTooLong    \
                                        : (context).corrupted)

static uint64_t addTemp64;
#define SHAAddLength64(context, length)                     \
    (addTemp64 = (context).length_low,                      \
     (context).corrupted =                                  \
        (((context).length_low += (length)) < addTemp64) && \
        (++(context).length_high == 0) ? shaInputTooLong    \
                                        : (context).corrupted)


#endif  // SHA_PRIVATE_H_