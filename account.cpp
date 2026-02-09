#include "account.h"
#include "urls.h"
#include "guard.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <format>
#include <nlohmann/json.hpp>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

/*
    for debugging purposes
    curl_easy_setopt(curl_, CURLOPT_PROXY, "http://127.0.0.1:8080");
    curl_easy_setopt(curl_, CURLOPT_PROXY_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 0L);
        
*/

namespace {
    enum class TRADE_OFFER_STATE {
        Invalid = 1,
        Active = 2,
        Accepted = 3,
        Countered = 4,
        Expired = 5,
        Canceled = 6,
        Declined = 7,
        InvalidItems = 8,
        ConfirmationNeed = 9,
        CanceledBySecondaryFactor = 10,
        StateInEscrow = 11
    };

    uint64_t accountid_to_steamid(uint64_t accountid) {
        //magic number for conversion to steamid64
        return 76561197960265728 + accountid;
    }
}

namespace steampp
{
    struct RSA_PARAMS
    {
        std::string key;
        std::string exp;
        std::string timestamp;
    };

    struct AUTH_SESSION_DATA 
    {
        std::string client_id;
        std::string steamid;
        std::string request_id; 
    };

    struct CONFIRMATION
    {
        std::string id;
        std::string nonce;
        std::string creator_id;
    };

    // PUBLIC
    account::account(const std::string &username, const std::string &password, const std::string &shared_secret)
        : username_(username), password_(password), shared_secret_(shared_secret) {};

    bool account::login()
    {
        RSA_PARAMS rsa_params = fetch_rsa_params();
        std::string encrypted_password = encrypt_password(rsa_params);
        AUTH_SESSION_DATA auth_data = begin_auth_session(encrypted_password, rsa_params.timestamp);
        update_steam_guard(auth_data);
        poll_session(auth_data);
        std::string finalize_data = finalize_login();
        perform_redirects(finalize_data);
        set_sessionid_cookies();
        set_access_token();
        steamid_ = auth_data.steamid;
        device_id_ = generate_device_id(steamid_);
        return true;
    }


    void account::accept_trade(const std::string& offer_id) 
    {
        std::string trade = get_trade_offer(offer_id);
        
        nlohmann::json doc = nlohmann::json::parse(trade);
        TRADE_OFFER_STATE state = (TRADE_OFFER_STATE)doc["response"]["offer"]["trade_offer_state"];

        if (state != TRADE_OFFER_STATE::Active) {
            std::cerr << "Trade not active\n";
            return;
        }

        std::string url = std::format("{}/tradeoffer/{}/accept", COMMUNITY_URL, offer_id);

        requests_.set_headers({
            std::format("Referer: {}/tradeoffer/{}", COMMUNITY_URL, offer_id)
        });

        ezcurl_response response = requests_.post(url, {
            {"sessionid", sessionid_},
            {"tradeofferid", offer_id},
            {"serverid", "1"},
            {"partner", accountid_to_steamid(doc["response"]["offer"]["accountid_other"])},
            {"captcha", ""}
        });

        if (response.res != CURLE_OK) {
            std::cerr << "Accept trade request failed\n";
            return;
        }

        doc = nlohmann::json::parse(response.body);
        if (doc.value("needs_mobile_confirmation", false)) {
            confirm_trade(offer_id);
        }
    }

    // PRIVATE
    ezcurl_response account::api_call(const std::string &service, const std::string &endpoint,
                                  const nlohmann::json& params, bool post, const std::string &version)
    {
        ezcurl_response response;
        std::string url = std::format("{}/{}/{}/{}", API_URL, service, endpoint, version);

        if (post) 
            response = requests_.post(url, params);
        else
            response = requests_.get(url, params);

        if (response.res != CURLE_OK)
            std::cerr << std::format("Performing API CALL {} failed with res {}\n", url, (int)response.res); // will need proper handling

        return response;
    }

    RSA_PARAMS account::fetch_rsa_params() // verify bad fragile code
    {
        RSA_PARAMS rsa_params;

        // steampy has a post to steamcommunity at start? not sure if necessary; setting remember login here
        ezcurl_response response;
        requests_.set_cookie("steamRememberLogin=true");
        response = requests_.post(std::string(COMMUNITY_URL));

        if (response.res != CURLE_OK)
        {
            std::cerr << "Rsa params initial post failed\n"; // will need proper handling esp since rsa uninitialized
            return rsa_params;
        }

        // actual fetch
        std::map<std::string, std::string> params = {{"account_name", username_}};
        response = api_call("IAuthenticationService", "GetPasswordRSAPublicKey", params, false); // retry code not present nor is status checks

        if (!response.body.empty())
        { // empty parse will throw parse_error immediately, consider refactoring
            try
            {
                nlohmann::json doc = nlohmann::json::parse(response.body);

                if (!doc.contains("response"))
                {
                    std::cerr << "RSA PARAMS 1 Invalid response\n";
                    return rsa_params;
                }

                const auto &response = doc["response"];

                rsa_params.key = response.at("publickey_mod");
                rsa_params.exp = response.at("publickey_exp");
                rsa_params.timestamp = response.at("timestamp");
            }
            catch (const nlohmann::json::exception &e)
            {
                std::cerr << "JSON Error: " << e.what() << '\n';
                return rsa_params;
            }
        }
        else
        {
            std::cerr << "RSA body empty\n";
        }

        return rsa_params;
    }

    std::string account::encrypt_password(const RSA_PARAMS& rsa_params)
    {
        CryptoPP::RSA::PublicKey pubKey;
        pubKey.Initialize(
            CryptoPP::Integer((std::string("0x") + rsa_params.key).c_str()),
            CryptoPP::Integer((std::string("0x") + rsa_params.exp).c_str()));

        std::string output;
        CryptoPP::AutoSeededRandomPool rng;

        CryptoPP::RSAES_PKCS1v15_Encryptor encryptor(pubKey);

        CryptoPP::StringSource ss(password_, true,
                                  new CryptoPP::PK_EncryptorFilter(rng, encryptor,
                                                                   new CryptoPP::Base64Encoder(
                                                                       new CryptoPP::StringSink(output),
                                                                       false 
                                                                       )));

        return output;
    }

    AUTH_SESSION_DATA account::begin_auth_session(const std::string& encrypted_password, const std::string& timestamp) 
    {
        std::map<std::string, std::string> params = {
            {"persistence", "1"},
            {"encrypted_password", encrypted_password},
            {"account_name", username_},
            {"encryption_timestamp", timestamp}
        };

        ezcurl_response response = api_call("IAuthenticationService", "BeginAuthSessionViaCredentials", params, true);

        nlohmann::json doc;
        AUTH_SESSION_DATA auth_session;

        if (!response.body.empty())
        { // empty parse will throw parse_error immediately, consider refactoring
            try
            {
                doc = nlohmann::json::parse(response.body);

                if (!doc.contains("response"))
                {
                    std::cerr << "Invalid login body\n";
                    return auth_session;
                }

                if (doc.value("captcha_needed", false))
                {
                    std::cerr << "Login requires captcha\n";
                    return auth_session;
                }

                const auto &response = doc["response"];
                auth_session.client_id = response.at("client_id");
                auth_session.steamid = response.at("steamid");
                auth_session.request_id = response.at("request_id");
            }
            catch (const nlohmann::json::exception &e)
            {
                std::cerr << "JSON Error: " << e.what() << '\n';
                return auth_session;
            };
        }
        else
        {
            std::cerr << "RSA body empty\n";
            return auth_session;
        }
        return auth_session;
    }

    void account::update_steam_guard(const AUTH_SESSION_DATA& auth_data) 
    {
        std::string code = generate_otc(shared_secret_);
        std::map<std::string, std::string> params = {
            {"client_id", auth_data.client_id},
            {"steamid", auth_data.steamid},
            {"code_type", "3"},
            {"code", code}
        };

        api_call("IAuthenticationService", "UpdateAuthSessionWithSteamGuardCode", params, true); // no error handling
    }

    void account::poll_session(const AUTH_SESSION_DATA& auth_data) 
    {
        std::map<std::string, std::string> params;
        params["client_id"] = auth_data.client_id;
        params["request_id"] = auth_data.request_id;
        ezcurl_response response = api_call("IAuthenticationService", "PollAuthSessionStatus", params, true);

        try
        {
            nlohmann::json doc = nlohmann::json::parse(response.body);

            if (!doc.contains("response"))
            {
                std::cerr << "Invalid poll body\n";
            }

            refresh_token_ = doc["response"]["refresh_token"];
        }
        catch (const nlohmann::json::exception &e)
        {
            std::cerr << "JSON Error: " << e.what() << '\n';
        };
    }

    std::string account::finalize_login()
    {
        std::string url = std::format("{}/jwt/finalizelogin", LOGIN_URL);
        sessionid_ = requests_.get_cookie_value("sessionid");

        requests_.set_headers({
            std::format("Referer: {}/", COMMUNITY_URL),
            std::format("Origin: {}", COMMUNITY_URL)
        });

        ezcurl_response response = requests_.post(url, {
            {"nonce", refresh_token_},
            {"sessionid", sessionid_},
            {"redir", std::format("{}/login/home/?goto=", COMMUNITY_URL)}
        });

        if (response.res != CURLE_OK)
        {
            // Using std::format for error logging as well
            std::cerr << std::format("failed to finalize login: {}\n", curl_easy_strerror(response.res));
        }

        return response.body;
    }

    void account::perform_redirects(const std::string& redirect_data)
    {
        nlohmann::json doc = nlohmann::json::parse(redirect_data);
        const auto &transfers = doc.at("transfer_info");
        for (const auto pass_data : transfers)
        {
            std::string url = pass_data["url"];

            nlohmann::json params = pass_data["params"];
            params["steamID"] = doc["steamID"];

            ezcurl_response response = requests_.post(url, params);
            if (response.res != CURLE_OK)
            {
                std::cerr << "Transport redirect failed\n";
            }
        }
    }

    void account::set_sessionid_cookies()
    {
        //skip "https://"
         std::vector<std::string> domains = {
            std::string(COMMUNITY_URL.substr(8)),
            std::string(STORE_URL.substr(8))
        };

        std::vector<std::string> cookies = {
            "steamLoginSecure",
            "sessionid",
            "steamRefresh_steam",
            "steamCountry"
        };

        for (auto& cookie : cookies) {
            std::string value = requests_.get_cookie_value(cookie);
            for (const auto& domain : domains) {
                requests_.store_cookie(std::format("{}\tTRUE\t/\tTRUE\t0\t{}\t{}", domain, cookie, value));
            }
        }
    }

    void account::set_access_token()
    {
        std::string steamLoginSecure = requests_.get_cookie_value("steamLoginSecure");
        std::string decoded = requests_.string_unescape(steamLoginSecure);

        std::string delimiter = "||";

        auto pos = decoded.find(delimiter);

        if (pos != std::string::npos) {
            access_token_ = decoded.substr(pos + delimiter.length());
        } else {
            std::cerr << "Access token delim not found\n";
        }
    }

    std::string account::get_trade_offer(const std::string& offer_id) 
    {
        std::map<std::string, std::string> params = {
            {"tradeofferid", offer_id},
            {"language", "english"},
            {"access_token", access_token_}
        };

        ezcurl_response response = api_call("IEconService", "GetTradeOffer", params);
        if (response.res != CURLE_OK) {
            std::cerr << "Failed to get trade offer\n"; 
        }
        return response.body;
    }

    void account::confirm_trade(const std::string& offer_id)
    {
        std::vector<CONFIRMATION> confirmations = get_confirmations();
        
        if (confirmations.empty()) {
            std::cerr << "Cannot confirm trade " << offer_id << " because confirmations empty\n";
            return;
        }

        for (auto const& confirmation : confirmations) {
            if (confirmation.creator_id == offer_id) {
                send_confirmation(confirmation);
                break;
            }
        }
    }

    std::vector<CONFIRMATION> account::get_confirmations()
    {
        std::vector<CONFIRMATION> confirmations;
        std::string url = std::format("{}/getlist", CONF_URL);
        uint64_t timestamp = std::time(nullptr);
        
        requests_.set_headers({
            "X-Requested-With: com.valvesoftware.android.steam.community"
        });

        ezcurl_response response = requests_.get(url, {
            {"p", device_id_},
            {"a", steamid_},
            {"k", generate_confirmation_key(identity_secret_, std::string(TAG_CONF), timestamp)},
            {"t", timestamp},
            {"m", "android"},
            {"tag", std::string(TAG_CONF)}
        });

        if (response.body.find("Steam Guard Mobile Authenticator is providing incorrect Steam Guard codes.") != std::string::npos) {
            std::cerr << "Invalid steam guard file\n";
            return confirmations;
        }
        
        nlohmann::json doc = nlohmann::json::parse(response.body);
        for (const auto& conf : doc["conf"]) {
            confirmations.emplace_back(conf["id"], conf["nonce"], conf["creator_id"]);
        }
        return confirmations;
    }

    void account::send_confirmation(const CONFIRMATION& confirmation)
    {
        std::string url = std::format("{}/ajaxop", CONF_URL);
        uint64_t timestamp = std::time(nullptr);
        
        requests_.set_headers({
            "X-Requested-With: XMLHttpRequest"
        });

        ezcurl_response response = requests_.get(url, {
            {"p", device_id_},
            {"a", steamid_},
            {"k", generate_confirmation_key(identity_secret_, std::string(TAG_ALLOW), timestamp)},
            {"t", timestamp},
            {"m", "android"},
            {"tag", std::string(TAG_ALLOW)},
            {"op", std::string(TAG_ALLOW)},
            {"cid", confirmation.id},
            {"ck", confirmation.nonce}
        });

        if (response.res != CURLE_OK) {
            std::cerr << "CURL RES FAILED TO CONFIRM\n";
            return;
        }

        nlohmann::json doc = nlohmann::json::parse(response.body);
        if (!doc.value("success", false)) {
            std::cerr << "CURL CONFIRM DIDNT GET SUCCESS RESPONSE\n";
        }
    }
}