#pragma once
#include "ezcurl/ezshare.h"
#include "item.h"
#include <string>
#include <map>

namespace steampp {
    struct RSA_PARAMS;
    struct AUTH_SESSION_DATA;
    struct CONFIRMATION;

    class account {
    public:
        account(const std::string& username, const std::string& password, const std::string& shared_secret);
        bool login();
        void accept_trade(const std::string& offer_id);
        //make return tradeid
        std::string identity_secret_;
    private:
        ezshare requests_;
        std::string username_;
        std::string password_;
        std::string shared_secret_;
        //std::string identity_secret_; //adapt for db file
        std::string steamid_;
        std::string sessionid_;
        std::string device_id_;
        std::string refresh_token_;
        std::string access_token_;
                
        ezcurl_response api_call(const std::string& service, const std::string& endpoint, 
                        const nlohmann::json& params = {}, bool post=false, const std::string& version="v1");
        RSA_PARAMS fetch_rsa_params();
        std::string encrypt_password(const RSA_PARAMS& rsa_params);
        AUTH_SESSION_DATA begin_auth_session(const std::string& encrypted_password, const std::string& timestamp);
        void update_steam_guard(const AUTH_SESSION_DATA& auth_data);
        void poll_session(const AUTH_SESSION_DATA& auth_data);
        std::string finalize_login();
        void perform_redirects(const std::string& redirect_data);
        void set_sessionid_cookies();
        void set_access_token();
        std::string get_trade_offer(const std::string& offer_id);
        void confirm_trade(const std::string& offer_id);
        std::vector<CONFIRMATION> get_confirmations();
        void send_confirmation(const CONFIRMATION& confirmation);
    };
}