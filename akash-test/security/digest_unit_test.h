// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_TEST_SECURITY_DIGEST_UNIT_TEST_H_
#define AKASH_TEST_SECURITY_DIGEST_UNIT_TEST_H_


namespace akash {
namespace test {

    /**
     * 该测试代码来自 RFC6234
     * https://tools.ietf.org/html/rfc6234
     */

    int TEST_SHA();
    int TEST_MD5();

}
}

#endif  // AKASH_TEST_SECURITY_DIGEST_UNIT_TEST_H_
