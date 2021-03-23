// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash-test/security/cert_unit_test.h"

#include "akash/security/cert/cert_path_validator.h"


namespace akash {
namespace test {

    void TEST_CERT() {
        cert::CertPathValidator validator;
        validator.validate();
    }

}
}
