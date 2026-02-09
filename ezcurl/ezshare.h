#pragma once
#include "ezcurl.h"

class ezshare : public ezcurl {
    using base = ezcurl;
public:
    ezshare();
    ~ezshare();
    ezcurl_response get(const std::string& url, const nlohmann::json& params = {}) override;
    ezcurl_response post(const std::string& url, const nlohmann::json& params = {}) override;
    std::string get_cookie_value(const std::string& key);
    void store_cookie(const std::string& netscape_cookie); //inefficient to loop through stored cookies repeatedly
private:
    CURLSH* share_;
};