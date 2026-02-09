#pragma once
#include <string>

namespace steampp {
    inline constexpr std::string_view TAG_CONF = "conf";
    inline constexpr std::string_view TAG_DETAILS = "details";
    inline constexpr std::string_view TAG_ALLOW = "allow";
    inline constexpr std::string_view TAG_CANCEL = "cancel";

    std::string generate_otc(const std::string& shared_secret);
    std::string generate_confirmation_key(const std::string& identity_secret, const std::string& tag, uint64_t timestamp = 0);
    std::string generate_device_id(const std::string& steamid);
}