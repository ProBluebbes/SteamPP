# SteamPP
A modern C++ steam trading library based on bukson/steampy. This project is still under development. It will have all the necessary features required for steam market transactions and trades upon completion. It currently has logins, 2fa, and accepting trades implemented. Other features will be added later.

### Dependencies
SteamPP depends on nlohmann/json, libcurl, and cryptopp (for authentication).

### Usage & API
Sample
```cpp
steampp::account acc(username, password, shared_secret);

acc.login();
acc.accept_trade(tradeid);
```
Will be updated as the library gets developed.
