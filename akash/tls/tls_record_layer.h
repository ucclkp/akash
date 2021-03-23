// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_TLS_TLS_RECORD_LAYER_H_
#define AKASH_TLS_TLS_RECORD_LAYER_H_

#include <thread>

#include "akash/tls/tls_common.h"


namespace akash {

    class SocketClient;

namespace tls {

    class TLSRecordLayer {
    public:
        struct TLSPlaintext {
            ContentType type;
            ProtocolVersion version;
            uint16_t length;
            std::string fragment;
        };

        struct TLSCompressed {
            ContentType type;
            ProtocolVersion version;
            uint16_t length;
            std::string fragment;
        };

        struct TLSInnerPlaintext {
            std::string content;
            ContentType type;
            std::string zeros;
        };

        struct TLSCiphertext {
            ContentType opaque_type;
            ProtocolVersion legacy_record_version;
            uint16_t length;
            std::string encrypted_record;
        };

        TLSRecordLayer();
        ~TLSRecordLayer();

        bool connect(const std::string& host);
        void disconnect();

        bool sendFragment(const TLSPlaintext& text);
        bool recvFragment(TLSPlaintext* text);

        void setServerWriteKey(const std::string& key, const std::string& iv);

    private:
        void OnBackgroundWorker();

        std::thread worker_;
        std::unique_ptr<SocketClient> socket_client_;

        bool is_encrypt_enabled_ = false;
        uint64_t sequence_num_w_ = 0;
        uint64_t sequence_num_r_ = 0;
        std::string sw_key_;
        std::string sw_iv_;
    };

}
}

#endif  // AKASH_TLS_TLS_RECORD_LAYER_H_