// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/http/http_client.h"

#include "utils/convert.h"
#include "utils/log.h"

#include "akash/socket/socket.h"


namespace akash {

    HttpClient::HttpClient() {}

    bool HttpClient::connect(const std::string& url) {
        URLInfo info;
        if (!getURLInfo(url, &info)) {
            return false;
        }

        std::unique_ptr<SocketClient> client(SocketClient::create());
        if (!client->connectByHost(info.host, info.port)) {
            return false;
        }

        std::string ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36";

        std::string buf;
        buf.append("GET / HTTP/1.1").append("\r\n");
        buf.append("Host: ").append(info.host).append("\r\n");
        buf.append("User-Agent: ").append(ua).append("\r\n");
        buf.append("\r\n");

        if (!client->send(buf)) {
            return false;
        }

        client->shutdown();

        std::string response;
        if (!client->recv(&response)) {
            return false;
        }

        client->close();
        return true;
    }

    bool HttpClient::getURLInfo(const std::string& url, URLInfo* info) const {
        std::string scheme;
        std::string url_tmp;
        auto index = url.find("://");
        if (index == std::string::npos) {
            url_tmp = url;
        } else {
            scheme = url.substr(0, index);
            url_tmp = url.substr(index + 3);
        }

        std::string path;
        index = url_tmp.find("/");
        if (index != std::string::npos) {
            path = url_tmp.substr(index);
            url_tmp = url_tmp.substr(0, index);
        } else {
            path = "/";
        }

        std::string host;
        unsigned short port;
        index = url_tmp.find_last_of(":");
        if (index != std::string::npos) {
            if (!scheme.empty()) {
                return false;
            }
            host = url_tmp.substr(0, index);
            auto port_str = url_tmp.substr(index + 1);
            if (!utl::stringToNumber(port_str, &port)) {
                return false;
            }
        } else {
            host = url_tmp;
            if (scheme.empty() || scheme == "http") {
                port = 80;
            } else if (scheme == "https") {
                port = 443;
            } else {
                return false;
            }
        }

        index = host.find(".");
        if (index == std::string::npos || index == 0 || index + 1 == host.length()) {
            return false;
        }
        index = host.find_last_of(".");
        if (index == std::string::npos || index == 0 || index + 1 == host.length()) {
            return false;
        }

        info->scheme = std::move(scheme);
        info->host = std::move(host);
        info->path = std::move(path);
        info->port = port;

        return true;
    }

}