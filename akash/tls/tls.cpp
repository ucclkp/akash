// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/tls/tls.h"

#include <random>

#include "utils/log.h"
#include "utils/stream_utils.h"

#include "akash/security/crypto/ecdp.h"
#include "akash/security/digest/sha.h"

#include "akash/tls/tls_key_schedule.h"
#include "akash/tls/handshakes/tls_hs.h"
#include "akash/tls/handshakes/tls_hs_client_hello.h"
#include "akash/tls/handshakes/tls_hs_server_hello.h"
#include "akash/tls/handshakes/tls_hs_encrypted_exts.h"
#include "akash/tls/handshakes/tls_hs_certificate.h"
#include "akash/tls/handshakes/tls_hs_finished.h"


namespace akash {
namespace tls {

    TLS::TLS() {}

    TLS::~TLS() {}

    bool TLS::parseFragment(const TLSRecordLayer::TLSPlaintext& text) {
        std::istringstream s(std::string(text.fragment.begin(), text.fragment.end()), std::ios::binary);

        for (; !finished_;) {
            PEEK_STREAM(char buf);
            if (buf == EOF) {
                break;
            }

            switch (text.type) {
            case ContentType::Alert:
            {
                uint8_t level, desc;
                READ_STREAM(level, 1);
                READ_STREAM(desc, 1);

                auto alert_level = AlertLevel(level);
                auto alert_desc = AlertDescription(desc);
                finished_ = true;
                break;
            }

            case ContentType::Handshake:
            {
                if (!parseHandshake(s, text.fragment)) {
                    return false;
                }
                break;
            }

            case ContentType::ChangeCipherSpec:
                // Do nothing
                break;

            case ContentType::ApplicationData:
            {
                break;
            }

            default:
                break;
            }
        }

        return true;
    }

    bool TLS::writeHandshake(HandshakeType type, std::ostream& s) {
        PUT_STREAM(enum_cast(type));
        uint32_t len = 0;
        WRITE_STREAM(len, 3);
        auto start_p = s.tellp();

        switch (type) {
        case HandshakeType::ClientHello:
        {
            HSClientHello client_hello;
            if (!client_hello.write(host_, s)) {
                return false;
            }

            x25519_K_ = client_hello.x25519_K_;
            x25519_P_ = client_hello.x25519_P_;
            break;
        }
        default:
            break;
        }

        auto end_p = s.tellp();
        len = IntToUInt24(end_p - start_p);
        SEEKP_STREAM(start_p - std::streamoff(3));
        WRITE_STREAM_MLBE(len, 3);
        SEEKP_STREAM(end_p);
        return true;
    }

    bool TLS::parseHandshake(std::istream& s, const std::string& fragment) {
        HSHandshake::Data data;
        if (!HSHandshake::parse(s, &data)) {
            return false;
        }

        auto end_p = s.tellg() + std::streamoff(data.length);

        switch (data.type) {
        case HandshakeType::ServerHello:
        {
            server_hello_data_ = fragment;

            HSServerHello server_hello;
            server_hello.x25519_P_ = x25519_P_;
            server_hello.x25519_K_ = x25519_K_;
            if (!server_hello.parse(s)) {
                return false;
            }

            share_K_ = server_hello.share_K_;
            generateServerWriteKey();
            break;
        }

        case HandshakeType::EncryptedExtensions:
        {
            encrypted_exts_data_ = fragment;

            HSEncryptedExtensions encrypted_exts;
            if (!encrypted_exts.parse(s)) {
                return false;
            }
            break;
        }

        case HandshakeType::Certificate:
        {
            certificate_data_ = fragment;

            HSCertificate cert;
            if (!cert.parse(s)) {
                return false;
            }
            break;
        }

        case HandshakeType::CertificateRequest:
            assert(false);
            break;

        case HandshakeType::CertificateVerify:
            certificate_verify_data_ = fragment;
            SKIP_BYTES(data.length);
            break;

        case HandshakeType::Finished:
        {
            finished_ = true;
            HSFinished finished;
            std::string context = client_hello_data_
                + server_hello_data_
                + encrypted_exts_data_
                + certificate_data_
                + certificate_verify_data_;

            if (!finished.parse(s, context, server_handshake_traffic_secret_)) {
                assert(false);
                return false;
            }
            break;
        }

        default:
            SKIP_BYTES(data.length);
            assert(false);
            break;
        }

        if (s.tellg() != end_p) {
            return false;
        }

        return true;
    }

    bool TLS::generateServerWriteKey() {
        // Section 7.1
        // 生成 server_handshake_traffic_secret
        uint8_t salt[32];
        uint8_t psk[32];
        std::memset(salt, 0, 32);
        std::memset(psk, 0, 32);

        uint8_t early_secret[64];
        digest::HKDF::hkdfExtract(
            digest::SHAVersion::SHA256,
            salt, 32, psk, 32, early_secret);

        std::string out;
        KeySchedule::deriveSecret(early_secret, 32, "derived", {}, &out);

        std::string_view ecdhe(share_K_);

        uint8_t handshake_secret[64];
        digest::HKDF::hkdfExtract(
            digest::SHAVersion::SHA256,
            reinterpret_cast<const uint8_t*>(out.data()), out.size(),
            reinterpret_cast<const uint8_t*>(ecdhe.data()), ecdhe.size(), handshake_secret);

        std::string sht_secret;
        std::string message = client_hello_data_ + server_hello_data_;
        KeySchedule::deriveSecret(handshake_secret, 32, "s hs traffic", message, &sht_secret);
        server_handshake_traffic_secret_ = sht_secret;

        // Section 7.3
        // 生成 server_write_iv
        std::string sw_iv;
        // iv 的长度根据 RFC 5116
        // https://tools.ietf.org/html/rfc5116
        KeySchedule::HKDFExpandLabel(
            reinterpret_cast<const uint8_t*>(sht_secret.data()), sht_secret.length(),
            "iv", "", 12, &sw_iv);

        // 生成 server_write_key
        std::string sw_key;
        KeySchedule::HKDFExpandLabel(
            reinterpret_cast<const uint8_t*>(sht_secret.data()), sht_secret.length(),
            "key", "", 16, &sw_key);

        record_layer_.setServerWriteKey(sw_key, sw_iv);

        return true;
    }

    void TLS::testHandshake() {
        host_ = "";
        finished_ = false;

        std::ostringstream ch_ss;
        writeHandshake(HandshakeType::ClientHello, ch_ss);

        std::string client_hello(ch_ss.str());
        client_hello_data_ = client_hello;

        TLSRecordLayer::TLSPlaintext text;
        text.type = ContentType::Handshake;
        text.version.major = 3;
        text.version.minor = 1;
        text.length = uint16_t(client_hello.length());
        text.fragment = client_hello;

        if (!record_layer_.connect(host_)) {
            ubassert(false);
            return;
        }

        if (!record_layer_.sendFragment(text)) {
            ubassert(false);
            return;
        }

        TLSRecordLayer::TLSPlaintext out;
        for (;;) {
            if (!record_layer_.recvFragment(&out)) {
                ubassert(false);
                break;
            }
            if (out.type != ContentType::ChangeCipherSpec) {
                if (!parseFragment(out) || finished_) {
                    break;
                }
            }
        }

        record_layer_.disconnect();
    }

}
}