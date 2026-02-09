#pragma once
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <map>
#include <string>


struct ezcurl_response {
    CURLcode res;
    long http_code;
    std::string body;
};

class ezcurl {
public:
    ezcurl();
    ~ezcurl();
    virtual ezcurl_response get(const std::string& url, const nlohmann::json& params = {});
    virtual ezcurl_response post(const std::string& url, const nlohmann::json& params = {});
    void set_headers(const std::vector<std::string>& headers);
    void set_cookie(const std::string& cookie);
    std::string string_unescape(const std::string& s); //assumes no %00 encoding
    std::string get_url_key_value(const std::string& url, const std::string& key);
protected:
    CURL* curl_;
private:
    curl_slist* headers_ = nullptr;
    std::string params_escape(const nlohmann::json& params);
    std::string string_escape(const std::string& s);
};