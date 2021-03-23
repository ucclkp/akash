// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/tls/tls_record_layer.h"

#include "utils/log.h"
#include "utils/stream_utils.h"

#include "akash/security/big_integer/byte_string.h"
#include "akash/security/crypto/aead.h"
#include "akash/socket/socket.h"


namespace akash {
namespace tls {

    TLSRecordLayer::TLSRecordLayer() {
        socket_client_.reset(SocketClient::create());
    }

    TLSRecordLayer::~TLSRecordLayer() {
    }

    bool TLSRecordLayer::connect(const std::string& host) {
        if (!socket_client_->connectByHost(host, 443)) {
            return false;
        }

        //worker_ = std::thread(&TLSRecordLayer::OnBackgroundWorker, this);
        return true;
    }

    void TLSRecordLayer::disconnect() {
        //worker_.join();
        socket_client_->close();
    }

    bool TLSRecordLayer::sendFragment(const TLSPlaintext& text) {
        std::ostringstream s(std::ios::binary);

        PUT_STREAM(enum_cast(text.type));
        PUT_STREAM(text.version.major);
        PUT_STREAM(text.version.minor);

        // length, 16bit
        WRITE_STREAM_BE(UIntToUInt16(text.fragment.size()), 2);
        WRITE_STREAM_STR(text.fragment);

        ++sequence_num_w_;

        return socket_client_->send(s.str());
    }

    bool TLSRecordLayer::recvFragment(TLSPlaintext* text) {
        std::string rec_header;
        if (!socket_client_->recv(5, &rec_header)) {
            DCHECK(false);
            return false;
        }
        if (rec_header.length() < 5) {
            DCHECK(false);
            return false;
        }

        {
            std::istringstream s(rec_header, std::ios::binary);
            READ_STREAM(text->type, 1);
            READ_STREAM(text->version.major, 1);
            READ_STREAM(text->version.minor, 1);
            READ_STREAM_BE(text->length, 2);
        }

        std::string out;
        if (!socket_client_->recv(text->length, &out)) {
            DCHECK(false);
            return false;
        }
        if (out.length() < text->length) {
            DCHECK(false);
            return false;
        }

        if (text->type == ContentType::ChangeCipherSpec) {
            return true;
        }

        std::string result;
        if (is_encrypt_enabled_ && text->type == ContentType::ApplicationData) {
            std::string_view C(out);
            auto tag = C.substr(C.size() - 16);
            C = C.substr(0, C.size() - 16);
            std::string_view A(rec_header);

            // Section 5.3
            std::string padded_seq_num(sw_iv_.size() - 8, 0);
            auto val = utl::fromToBE(sequence_num_r_);
            padded_seq_num.append(reinterpret_cast<const char*>(&val), 8);

            std::string nonce(sw_iv_.size(), 0);
            utl::ByteString::exor(
                reinterpret_cast<const uint8_t*>(padded_seq_num.data()), padded_seq_num.size(),
                reinterpret_cast<const uint8_t*>(sw_iv_.data()), sw_iv_.size(),
                reinterpret_cast<uint8_t*>(&*nonce.begin()));

            result.resize(C.length());
            if (!crypto::GCM::GCM_AD(
                reinterpret_cast<const uint8_t*>(sw_key_.data()), sw_key_.length(),
                reinterpret_cast<const uint8_t*>(nonce.data()), nonce.length(),
                reinterpret_cast<const uint8_t*>(C.data()), C.length(),
                reinterpret_cast<const uint8_t*>(A.data()), A.length(),
                reinterpret_cast<const uint8_t*>(tag.data()), 16,
                reinterpret_cast<uint8_t*>(&*result.begin())))
            {
                DCHECK(false);
                return false;
            }
            ++sequence_num_r_;

            char ch = 0;
            auto idx = result.find_last_not_of(ch);
            if (idx == std::string::npos) {
                DCHECK(false);
                return false;
            }

            text->type = ContentType(result[idx]);
            result = result.substr(0, idx);
        } else {
            result = std::move(out);
        }

        text->fragment = std::move(result);
        return true;
    }

    void TLSRecordLayer::setServerWriteKey(const std::string& key, const std::string& iv) {
        sw_iv_ = iv;
        sw_key_ = key;
        is_encrypt_enabled_ = true;
    }

    void TLSRecordLayer::OnBackgroundWorker() {
    }

}
}