#pragma once
#include <string>
#include <nlohmann/json.hpp>

namespace steampp {
    struct ITEM {
        std::string market_hash_name;
        std::string assetid;
        std::string image;
        double price;
        std::string appid;
        std::string contextid;
        uint64_t amount;

        ITEM(const std::string& market_hash_name_, const std::string& assetid_, const std::string& image_, double price_)
            : market_hash_name(market_hash_name_), assetid(assetid_), image(image_), price(price_) {}

        bool operator==(const ITEM& other) const {
            return assetid == other.assetid;
        }
        
        nlohmann::json to_offer_dict() {
            return {
                {"appid", appid},
                {"contextid", contextid},
                {"amount", amount},
                {"assetid", assetid}
            };
        }
    };
}
