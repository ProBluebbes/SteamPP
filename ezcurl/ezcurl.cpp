#include "ezcurl.h"
#include <format>
#include <iostream>
#include <sstream>

namespace
{
    size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata)
    {
        size_t total_size = size * nmemb;
        std::string *response = static_cast<std::string *>(userdata);
        response->append(static_cast<char *>(ptr), total_size);
        return total_size;
    }

    size_t noop(void *ptr, size_t size, size_t nmemb, void *userdata)
    {
        size_t total_size = size * nmemb;
        return total_size;
    }
}

ezcurl::ezcurl() {
    curl_ = curl_easy_init();
}

ezcurl::~ezcurl() {
    curl_easy_cleanup(curl_);
}

ezcurl_response ezcurl::get(const std::string& url, const nlohmann::json& params) {
    ezcurl_response response;
    curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl_, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl_, CURLOPT_PROXY, "http://127.0.0.1:8080");
    curl_easy_setopt(curl_, CURLOPT_PROXY_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 0L);

    if (!params.empty()) {
        std::string escaped_params = params_escape(params);
        std::string new_url = std::format("{}?{}", url, escaped_params);

        curl_easy_setopt(curl_, CURLOPT_URL, new_url.c_str());
    }

    CURLcode res = curl_easy_perform(curl_);
    response.res = res;

    if (headers_) {
        curl_slist_free_all(headers_);
        headers_ = nullptr;
    }

    if (res != CURLE_OK) {
        std::cerr << "Failed to perform get: " << url << std::endl;
        curl_easy_reset(curl_);
        return response;
    }

    long response_code;
    curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &response_code);
    response.http_code = response_code;

    curl_easy_reset(curl_);
    return response;
}

ezcurl_response ezcurl::post(const std::string& url, const nlohmann::json& params) {
    ezcurl_response response;
    curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl_, CURLOPT_POST, 1L);
    curl_easy_setopt(curl_, CURLOPT_POSTFIELDSIZE, 0L);
    curl_easy_setopt(curl_, CURLOPT_PROXY, "http://127.0.0.1:8080");
    curl_easy_setopt(curl_, CURLOPT_PROXY_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 0L);

    if (!params.empty()) {
        std::string escaped_params = params_escape(params);

        curl_easy_setopt(curl_, CURLOPT_POSTFIELDSIZE, (long)escaped_params.length());
        curl_easy_setopt(curl_, CURLOPT_COPYPOSTFIELDS, escaped_params.c_str()); //ok since fields are short
    }

    CURLcode res = curl_easy_perform(curl_);
    response.res = res;

    if (headers_) {
        curl_slist_free_all(headers_);
        headers_ = nullptr;
    }

    if (res != CURLE_OK) {
        std::cerr << "Failed to perform post: " << url << std::endl;
        curl_easy_reset(curl_);
        return response;
    }

    long response_code;
    curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &response_code);
    response.http_code = response_code;

    curl_easy_reset(curl_);
    return response;
}

void ezcurl::set_headers(const std::vector<std::string>& headers) {
    headers_ = nullptr;

    for (auto header : headers) {
        headers_ = curl_slist_append(headers_, header.c_str());
    }

    curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers_);
}

void ezcurl::set_cookie(const std::string& cookie) {
    curl_easy_setopt(curl_, CURLOPT_COOKIE, cookie.c_str());
}

std::string ezcurl::string_unescape(const std::string& s) {
    char *output = curl_easy_unescape(curl_, s.c_str(), (int)s.length(), NULL);
    if (output)
    {
        std::string res(output);
        curl_free(output);
        return res;
    }
    return "";
}

std::string ezcurl::get_url_key_value(const std::string& url, const std::string& key)
{
    std::string raw_params = url.substr(url.find("?") + 1);
    std::stringstream ss(raw_params);
    std::string segment;

    while (std::getline(ss, segment, '&')) {
        const size_t pos = segment.find('=');
        if (segment.substr(0, pos - 1) == key) {
            return segment.substr(pos + 1);
        }
    }
    return "";
}

std::string ezcurl::params_escape(const nlohmann::json& params)
{
    std::string escaped_params = "";
    bool first = true;

    for (const auto& [key, value] : params.items())
    {
        if (first) 
            first = false;
        else
            escaped_params += '&';

        if (value.is_string())
            escaped_params += std::format("{}={}", string_escape(key), string_escape(value));
        else
            escaped_params += std::format("{}={}", string_escape(key), (uint64_t)value); //assuming number
    }

    return escaped_params;
}

std::string ezcurl::string_escape(const std::string& s)
{
    char *output = curl_easy_escape(curl_, s.c_str(), (int)s.length());
    if (output)
    {
        std::string res(output);
        curl_free(output);
        return res;
    }
    return "";
}