// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_HTTP_HTTP_CLIENT_H_
#define AKASH_HTTP_HTTP_CLIENT_H_

#include <string>


namespace akash {

    // 根据 RFC 7230 实现的 HTTP 客户端
    class HttpClient {
    public:
        HttpClient();

        bool connect(const std::string& url);

    private:
        struct URLInfo {
            std::string scheme;
            std::string host;
            std::string path;
            unsigned short port = 0;
        };

        bool getURLInfo(const std::string& url, URLInfo* info) const;
    };

}

#endif  // AKASH_HTTP_HTTP_CLIENT_H_