#pragma once
#include "interstellar.hpp"

// Interstellar: Sodium
// Sodium with extra Salt
namespace INTERSTELLAR_NAMESPACE::Sodium {
	extern std::string random(int min, int max, bool alpha);

	namespace Hex {
		extern std::string to_hex(const unsigned char* data, size_t length);
		extern std::string to_hex(const std::string& input);
		extern std::string from_hex(const std::string& hex);
	}

	namespace Base64 {
		extern std::string encode(std::string inputString);
		extern std::string decode(std::string inputString, const std::string& ignore);
	}

	namespace Signature {
		extern void key(std::string& pk, std::string& sk);
		extern std::string encode(std::string message, std::string sk);
		extern std::string decode(std::string signature, std::string pk);
	}

	namespace Hash {
		extern std::string enc256(std::string message);
		extern std::string enc512(std::string message);
	}

	namespace HMAC {
		extern std::string key256();
		extern std::string enc256(std::string message, std::string key);
		extern std::string key512();
		extern std::string enc512(std::string message, std::string key);
		extern std::string key512256();
		extern std::string enc512256(std::string message, std::string key);
	}

	namespace AEAD {
		namespace CHACHAPOLY {
			extern std::string nonce();
			extern std::string key();
			extern std::string key(std::string base);
			extern std::string key(std::string base, std::string salt);
			extern std::string encrypt(std::string message, std::string key, std::string nonce);
			extern std::string decrypt(std::string ciphertext, std::string key, std::string nonce);
			extern std::string encode(std::string message, std::string key);
			extern std::string decode(std::string message, std::string key);
		}

		namespace GCM {
			extern std::string nonce();
			extern std::string key();
			extern std::string key(std::string base);
			extern std::string key(std::string base, std::string salt);
			extern std::string encrypt(std::string message, std::string key, std::string nonce);
			extern std::string decrypt(std::string ciphertext, std::string key, std::string nonce);
			extern std::string encode(std::string message, std::string key);
			extern std::string decode(std::string message, std::string key);
		}

		namespace AEGIS {
			extern std::string nonce();
			extern std::string key();
			extern std::string key(std::string base);
			extern std::string key(std::string base, std::string salt);
			extern std::string encrypt(std::string message, std::string key, std::string nonce);
			extern std::string decrypt(std::string ciphertext, std::string key, std::string nonce);
			extern std::string encode(std::string message, std::string key);
			extern std::string decode(std::string message, std::string key);
		}
	}

    extern void push(API::lua_State* L, UMODULE hndle);
    extern void api();
}