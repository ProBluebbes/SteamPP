#include <iostream>
#include <string>
#include <ctime>
#include <sstream>
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

namespace steampp
{
    std::string generate_otc(const std::string &shared_secret)
    {
        std::string secret_bytes;
        CryptoPP::StringSource(shared_secret, true,
                               new CryptoPP::Base64Decoder(new CryptoPP::StringSink(secret_bytes)));

        uint64_t time_slice = std::time(nullptr) / 30;
        unsigned char time_buffer[8];
        for (int i = 7; i >= 0; i--)
        {
            time_buffer[i] = time_slice & 0xFF;
            time_slice >>= 8;
        }

        CryptoPP::HMAC<CryptoPP::SHA1> hmac((CryptoPP::byte *)secret_bytes.data(), secret_bytes.size());
        CryptoPP::byte digest[CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE];
        hmac.CalculateDigest(digest, time_buffer, sizeof(time_buffer));

        int start = digest[19] & 0x0F;
        uint32_t full_code = (((digest[start] & 0x7F) << 24) |
                              (digest[start + 1] << 16) |
                              (digest[start + 2] << 8) |
                              digest[start + 3]);

        const char chars[] = "23456789BCDFGHJKMNPQRTVWXY";
        std::string code = "";

        for (int i = 0; i < 5; ++i)
        {
            code += chars[full_code % 26];
            full_code /= 26;
        }

        return code;
    }

    std::string generate_confirmation_key(const std::string &identity_secret, const std::string &tag, uint64_t timestamp)
    {
        if (timestamp == 0)
        {
            timestamp = (uint64_t)std::time(nullptr);
        }

        std::string decoded_secret;
        try
        {
            CryptoPP::StringSource ss(identity_secret, true,
                                      new CryptoPP::Base64Decoder(
                                          new CryptoPP::StringSink(decoded_secret)));
        }
        catch (const CryptoPP::Exception &e)
        {
            return "";
        }

        std::string buffer;
        buffer.resize(8);

        buffer[0] = (timestamp >> 56) & 0xFF;
        buffer[1] = (timestamp >> 48) & 0xFF;
        buffer[2] = (timestamp >> 40) & 0xFF;
        buffer[3] = (timestamp >> 32) & 0xFF;
        buffer[4] = (timestamp >> 24) & 0xFF;
        buffer[5] = (timestamp >> 16) & 0xFF;
        buffer[6] = (timestamp >> 8) & 0xFF;
        buffer[7] = (timestamp) & 0xFF;

        buffer += tag;

        std::string result;

        try
        {
            CryptoPP::HMAC<CryptoPP::SHA1> hmac;
            hmac.SetKey((const CryptoPP::byte *)decoded_secret.data(), decoded_secret.size());

            CryptoPP::StringSource ss(buffer, true,
                                      new CryptoPP::HashFilter(hmac,
                                                               new CryptoPP::Base64Encoder(
                                                                   new CryptoPP::StringSink(result),
                                                                   false
                                                                   )));
        }
        catch (const CryptoPP::Exception &e)
        {
            return "";
        }

        return result;
    }

    std::string generate_device_id(const std::string& steamid)
    {
        std::string hex_digest;

        try
        {
            CryptoPP::SHA1 sha1;
            CryptoPP::StringSource ss(steamid, true,
                                      new CryptoPP::HashFilter(sha1,
                                                               new CryptoPP::HexEncoder(
                                                                   new CryptoPP::StringSink(hex_digest),
                                                                   false)));
        }
        catch (const CryptoPP::Exception &e)
        {
            return "";
        }

        std::stringstream ss;
        ss << "android:"
           << hex_digest.substr(0, 8) << "-"
           << hex_digest.substr(8, 4) << "-"
           << hex_digest.substr(12, 4) << "-"
           << hex_digest.substr(16, 4) << "-"
           << hex_digest.substr(20, 12);

        return ss.str();
    }
}