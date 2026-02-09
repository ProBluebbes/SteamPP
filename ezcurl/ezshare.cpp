#include "ezshare.h"
#include <sstream>
#include <iostream>

namespace {
    enum class NETSCAPE_DATA {
        Domain,
        IncludeSubdomains,
        Path,
        HttpsOnly,
        Expiration,
        CookieName,
        CookieValue
    };
    
    std::string get_netscape_data(const std::string &line, NETSCAPE_DATA query)
    {
        std::stringstream ss(line);
        std::string segment;
        std::vector<std::string> tokens;

        // Split by tab
        while (std::getline(ss, segment, '\t'))
        {
            tokens.push_back(segment);
        }

        std::string delim = "#HttpOnly_";
        size_t find = line.find(delim);

        if (find != std::string::npos) {
            tokens[0] = tokens[0].substr(find + delim.length());
        }

        if (tokens.size() >= 7) //netscape cookies must be 7 fields
        {
            return tokens[(size_t)query];
        }
        return "";
    }
}

ezshare::ezshare() {
    share_ = curl_share_init();
}

ezshare::~ezshare() {
    curl_share_cleanup(share_);
}

ezcurl_response ezshare::get(const std::string& url, const nlohmann::json& params) {
    curl_easy_setopt(curl_, CURLOPT_SHARE, share_); //not including "this" keyword makes it unsafe for templates
    return base::get(url, params); 
}

ezcurl_response ezshare::post(const std::string& url, const nlohmann::json& params) {
    curl_easy_setopt(curl_, CURLOPT_SHARE, share_);
    return base::post(url, params);
}

std::string ezshare::get_cookie_value(const std::string& key)
{
    curl_easy_setopt(curl_, CURLOPT_SHARE, share_); //may need to set url too

    curl_slist *cookies = nullptr;
    std::string value = "";

    CURLcode res = curl_easy_getinfo(curl_, CURLINFO_COOKIELIST, &cookies);
    if (res == CURLE_OK && cookies)
    {
        curl_slist *nc = cookies;
        while (nc)
        {
            std::string cookie_name = get_netscape_data(nc->data, NETSCAPE_DATA::CookieName);
            if (cookie_name == key)
            {
                value = get_netscape_data(nc->data, NETSCAPE_DATA::CookieValue);
                break;
            }
            nc = nc->next;
        }
    }
    if (cookies)
        curl_slist_free_all(cookies);

    if (value.empty())
    {
        std::cerr << "failed to get " << key << " cookie\n";
    }
    return value;
}

void ezshare::store_cookie(const std::string& netscape_cookie) {
    curl_easy_setopt(curl_, CURLOPT_SHARE, share_);

    curl_slist *cookies = nullptr;
    bool found = false;

    CURLcode res = curl_easy_getinfo(curl_, CURLINFO_COOKIELIST, &cookies);
    if (res == CURLE_OK)
    {
        if (!cookies) {
            curl_easy_setopt(curl_, CURLOPT_COOKIELIST, netscape_cookie.c_str());
            return;
        }

        std::string ns_domain = get_netscape_data(netscape_cookie, NETSCAPE_DATA::Domain);
        std::string ns_cookie_name = get_netscape_data(netscape_cookie, NETSCAPE_DATA::CookieName);

        curl_slist *nc = cookies;
        while (nc)
        {
            std::string domain = get_netscape_data(nc->data, NETSCAPE_DATA::Domain);
            std::string cookie_name = get_netscape_data(nc->data, NETSCAPE_DATA::CookieName);
            if (cookie_name == ns_cookie_name && domain == ns_domain)
            {
                found = true;
                break;
            }
            nc = nc->next;
        }
    }

    if (!found)
        curl_easy_setopt(curl_, CURLOPT_COOKIELIST, netscape_cookie.c_str());

    curl_slist_free_all(cookies);
}