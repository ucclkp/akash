// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include <iostream>

#include "utils/log.h"

#include "akash/socket/socket.h"
#include "akash/http/http_client.h"
#include "akash/tls/tls.h"

#include "akash-test/security/cert_unit_test.h"
#include "akash-test/security/crypto_unit_test.h"
#include "akash-test/security/digest_unit_test.h"


int main(int argc, wchar_t* argv[]) {
    utl::Log::Params log_params;
    log_params.file_name = u"akash-debug.log";
    log_params.short_file_name = false;
    log_params.target = utl::Log::OutputTarget::DEBUGGER | utl::Log::OutputTarget::FILE;
    utl::InitLogging(log_params);

    LOG(Log::INFO) << "akash-test start.";

    //akash::test::TEST_ECDP_X25519();
    //akash::test::TEST_ECDP_X448();
    //akash::test::TEST_AES();
    //akash::test::TEST_AEAD_AES_GCM();
    //akash::test::TEST_RSA();
    //akash::test::TEST_CERT();
    //akash::test::TEST_MD5();
    //akash::test::TEST_SHA();

    akash::tls::TLS tls_client;
    tls_client.testHandshake();

    if (akash::isSocketInitialized()) {
        akash::unInitializeSocket();
    }

    LOG(Log::INFO) << "akash-test exit.\n";

    utl::UninitLogging();

    return 0;
}