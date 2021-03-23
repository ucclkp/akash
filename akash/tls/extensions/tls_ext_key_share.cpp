// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/tls/extensions/tls_ext_key_share.h"

#include "utils/stream_utils.h"

#include "akash/security/crypto/ecdp.h"
#include "akash/tls/extensions/tls_ext.h"


namespace akash {
namespace tls {
namespace ext {

    // KeyShare
    bool KeyShare::write(std::ostream& s, Data* out) {
        WRITE_STREAM_BE(enum_cast(ExtensionType::KeyShare), 2);
        BEGIN_WRB16(0);

        BEGIN_WRB16(1);
        {
            auto k = utl::BigInteger::fromRandom(32 * 8);
            k.setBit(255, 0);
            k.setBit(254, 1);
            k.setBit(2, 0);
            k.setBit(1, 0);
            k.setBit(0, 0);
            assert(k.getByteCount() == 32);

            uint32_t A;
            uint8_t cofactor, Up;
            utl::BigInteger p, order, Vp, result;
            crypto::ECDP::curve25519(&p, &A, &order, &cofactor, &Up, &Vp);
            crypto::ECDP::X25519(p, k, utl::BigInteger::fromU32(Up), &result);

            out->x25519_K = k;
            out->x25519_P = p;

            auto r = result.getBytesLE();
            assert(r.size() == 32);

            WRITE_STREAM_BE(enum_cast(NamedGroup::X25519), 2);
            WRITE_STREAM_BE(UIntToUInt16(r.length()), 2);
            WRITE_STREAM_STR(r);
        }

        uint8_t h;
        utl::BigInteger a, b, S, p, Gx, Gy, n;
        {
            crypto::ECDP::secp384r1(&p, &a, &b, &S, &Gx, &Gy, &n, &h);
            auto d = utl::BigInteger::fromRandom(utl::BigInteger::ONE, n - 1);
            crypto::ECDP::mulPoint(p, a, d, &Gx, &Gy);
            crypto::ECDP::verifyPoint(p, a, b, Gx, Gy);

            ECDHEParams p_secp384;
            p_secp384.X = Gx.getBytesBE();
            p_secp384.Y = Gy.getBytesBE();

            auto r = p_secp384.toBytes();
            WRITE_STREAM_BE(enum_cast(NamedGroup::SECP384R1), 2);
            WRITE_STREAM_BE(UIntToUInt16(r.length()), 2);
            WRITE_STREAM_STR(r);
        }

        {
            crypto::ECDP::secp256r1(&p, &a, &b, &S, &Gx, &Gy, &n, &h);
            auto d = utl::BigInteger::fromRandom(utl::BigInteger::ONE, n - 1);
            crypto::ECDP::mulPoint(p, a, d, &Gx, &Gy);
            crypto::ECDP::verifyPoint(p, a, b, Gx, Gy);

            ECDHEParams p_secp256;
            p_secp256.X = Gx.getBytesBE();
            p_secp256.Y = Gy.getBytesBE();

            auto r = p_secp256.toBytes();
            WRITE_STREAM_BE(enum_cast(NamedGroup::SECP256R1), 2);
            WRITE_STREAM_BE(UIntToUInt16(r.length()), 2);
            WRITE_STREAM_STR(r);
        }
        END_WRB16(1);

        END_WRB16(0);
        return true;
    }

    bool KeyShare::parseSH(std::istream& s, KeyShareEntry* entry) {
        uint16_t grp;
        READ_STREAM_BE(grp, 2);
        entry->group = NamedGroup(grp);
        return true;
    }


    // KeyShareEntry
    bool KeyShareEntry::parseX25519(std::istream& s, std::string* U) {
        uint16_t length;
        READ_STREAM_BE(length, 2);

        U->resize(length);
        READ_STREAM(*U->begin(), length);
        return true;
    }

}
}
}
