#include "interstellar_sodium.hpp"
#include <sodium.h>
#pragma comment (lib, "libsodium.Lib")
#include <stdexcept>
#include <sstream>
#include <iomanip>

namespace INTERSTELLAR_NAMESPACE::Sodium {
	using namespace API;

	namespace Hex {
		std::string to_hex(const unsigned char* data, size_t length) {
			std::stringstream ss;
			ss << std::hex << std::setfill('0');
			for (size_t i = 0; i < length; ++i) {
				ss << std::setw(2) << static_cast<int>(data[i]);
			}
			return ss.str();
		}

		std::string to_hex(const std::string& input) {
			std::stringstream ss;
			ss << std::hex << std::setfill('0');
			for (unsigned char c : input) {
				ss << std::setw(2) << static_cast<int>(c);
			}
			return ss.str();
		}

		std::string from_hex(const std::string& hex) {
			if (hex.size() % 2 != 0) {
				return "";
			}

			std::string binary;
			binary.reserve(hex.size() / 2);

			for (size_t i = 0; i < hex.size(); i += 2) {
				char byte = static_cast<char>(
					(std::stoi(hex.substr(i, 1), nullptr, 16) << 4) |
					std::stoi(hex.substr(i + 1, 1), nullptr, 16));
				binary.push_back(byte);
			}

			return binary;
		}

		int encodel(lua_State* L) {
			std::string input = luaL::checkcstring(L, 1);
			std::string result = to_hex(input);
			lua::pushlstring(L, result.c_str(), result.size());
			return 1;
		}

		int decodel(lua_State* L) {
			std::string input = luaL::checkcstring(L, 1);
			std::string result = from_hex(input);
			lua::pushlstring(L, result.c_str(), result.size());
			return 1;
		}
	}

	using namespace Hex;

	std::string random(int min, int max, bool alpha) {
		static unsigned int seed = 1;
		seed = (seed + 1) % 0x7FFFFFF;
		srand(seed);

		unsigned int len = min + (rand() % (max - min + 1));
		std::string result;

		if (alpha) {
			static const std::string alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
			result.reserve(len);
			for (unsigned int i = 0; i < len; i++) {
				result += alphanum[rand() % alphanum.size()];
			}
		}
		else {
			if (len == 0) return "";
			unsigned char* buffer = new unsigned char[len];
			randombytes_buf(buffer, len);
			result.assign(reinterpret_cast<char*>(buffer), len);
			delete[] buffer;
		}

		return result;
	}

	int randoml(lua_State* L) {
		int min = (int)luaL::checknumber(L, 1);
		int max = (int)luaL::checknumber(L, 2);
		bool alpha = false;

		if (lua::isboolean(L, 3)) {
			alpha = lua::toboolean(L, 3);
		}

		std::string result = random(min, max, alpha);

		if (!alpha) {
			result = to_hex(result);
		}

		lua::pushlstring(L, result.c_str(), result.size());

		return 1;
	}

	namespace Base64 {
		std::string encode(std::string inputString) {
			const size_t bin_len = inputString.size();
			unsigned long long b64_len = sodium_base64_encoded_len(bin_len, sodium_base64_VARIANT_ORIGINAL);
			std::string b64(b64_len - 1, 0);

			char* encoded = sodium_bin2base64(b64.data(), b64_len,
				(unsigned char*)inputString.data(), bin_len,
				sodium_base64_VARIANT_ORIGINAL);

			if (encoded == NULL) {
				throw std::runtime_error("sodium.base64.encode: Error encoding base64");
			}

			return b64;
		}

		std::string decode(std::string inputString, const std::string& ignore) {
			// Estimation of actual size of string
			std::size_t bin_maxlen = inputString.size();
			std::string bin(bin_maxlen, 0);
			std::size_t bin_len;

			if (sodium_base642bin((unsigned char*)bin.data(), bin_maxlen,
				inputString.data(), inputString.size(), ignore.data(), &bin_len,
				NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {
				throw std::runtime_error("sodium.base64.decode: Error decoding base64");
			}

			if (bin_len != bin_maxlen) {
				bin.resize(bin_len);
			}

			return bin;
		}

		int encodel(lua_State* L) {
			size_t size = 0;
			const char* _input = luaL::checklstring(L, 1, &size);
			std::string input = std::string(_input, size);

			std::string output;

			try {
				output = encode(input);
			}
			catch (std::exception& e) {
				return luaL::error(L, "%s", e.what());
			}

			lua::pushlstring(L, output.c_str(), output.size());

			return 1;
		}

		int decodel(lua_State* L) {
			size_t size = 0;
			const char* _input = luaL::checklstring(L, 1, &size);
			std::string input = std::string(_input, size);

			std::string output;

			try {
				output = decode(input, "");
			}
			catch (std::exception& e) {
				return luaL::error(L, "%s", e.what());
			}

			lua::pushlstring(L, output.c_str(), output.size());

			return 1;
		}

		int xencodel(lua_State* L) {
			size_t size = 0;
			const char* _input = luaL::checklstring(L, 1, &size);
			std::string input = std::string(_input, size);

			if (input.size() == 0) {
				return luaL::error(L, "sodium.base64.encode: invalid input size (must be valid hexstring)");
			}

			input = from_hex(input);

			if (input.size() == 0) {
				return luaL::error(L, "sodium.base64.encode: invalid input size (must be valid hexstring)");
			}

			std::string output;

			try {
				output = encode(input);
			}
			catch (std::exception& e) {
				return luaL::error(L, "%s", e.what());
			}

			lua::pushlstring(L, output.c_str(), output.size());

			return 1;
		}

		int xdecodel(lua_State* L) {
			size_t size = 0;
			const char* _input = luaL::checklstring(L, 1, &size);
			std::string input = std::string(_input, size);
			std::string output;

			try {
				output = decode(input, "");
			}
			catch (std::exception& e) {
				return luaL::error(L, "%s", e.what());
			}

			output = to_hex(output);

			lua::pushlstring(L, output.c_str(), output.size());

			return 1;
		}
	}

	namespace Signature {
		void key(std::string& pk, std::string& sk) {
			unsigned char* _pk = new unsigned char[crypto_sign_PUBLICKEYBYTES];
			unsigned char* _sk = new unsigned char[crypto_sign_SECRETKEYBYTES];

			if (int err = crypto_sign_keypair(_pk, _sk) != 0) {
				throw std::runtime_error(std::string("sodium.signature.key: Couldn't generate - ") + std::to_string(err));
			}

			pk = std::string((char*)_pk, crypto_sign_PUBLICKEYBYTES);
			sk = std::string((char*)_sk, crypto_sign_SECRETKEYBYTES);
		}

		int keypairl(lua_State* L) {
			std::string pk;
			std::string sk;

			try {
				key(pk, sk);
			}
			catch (std::exception& e) {
				return luaL::error(L, "%s", e.what());
			}

			pk = to_hex(pk);
			sk = to_hex(sk);

			lua::pushlstring(L, pk.c_str(), pk.size());
			lua::pushlstring(L, sk.c_str(), sk.size());

			return 2;
		}

		std::string encode(std::string message, std::string sk) {
			if (sk.size() != crypto_sign_SECRETKEYBYTES) {
				throw std::runtime_error("sodium.signature.encode: Invalid secret key size (" + std::to_string(sk.size()) + " != " + std::to_string(crypto_sign_SECRETKEYBYTES) + ")");
			}

			unsigned char* signature = new unsigned char[message.size() + crypto_sign_BYTES];
			unsigned long long signature_length;

			if (int ret = crypto_sign(
				signature, &signature_length,
				(unsigned char*)message.data(), message.size(),
				(unsigned char*)sk.data()) != 0) {
				throw std::runtime_error(std::string("sodium.signature.encode: Couldn't encrypt - ") + std::to_string(ret));
			}

			return std::string((char*)signature, signature_length);
		}

		int encodel(lua_State* L) {
			size_t size = 0;
			const char* _input = luaL::checklstring(L, 1, &size);
			std::string input = std::string(_input, size);

			if (input.size() == 0) {
				return luaL::error(L, "sodium.signature.encode: invalid input size");
			}

			size = 0;
			const char* _sk = luaL::checklstring(L, 2, &size);
			std::string sk = std::string(_sk, size);

			if (sk.size() == 0) {
				return luaL::error(L, "sodium.signature.encode: invalid sk size (must be valid hexstring)");
			}

			sk = from_hex(sk);

			if (sk.size() == 0) {
				return luaL::error(L, "sodium.signature.encode: invalid sk size (must be valid hexstring)");
			}

			std::string output;

			try {
				output = encode(input, sk);
			}
			catch (std::exception& e) {
				return luaL::error(L, "%s", e.what());
			}

			output = to_hex(output);

			lua::pushlstring(L, output.c_str(), output.size());

			return 1;
		}

		std::string decode(std::string signature, std::string pk) {
			if (pk.size() != crypto_sign_PUBLICKEYBYTES) {
				throw std::runtime_error("sodium.signature.decode: Invalid public key size (" + std::to_string(pk.size()) + " != " + std::to_string(crypto_sign_PUBLICKEYBYTES) + ")");
			}

			if (signature.size() <= crypto_sign_BYTES) {
				throw std::runtime_error("sodium.signature.decode: Invalid signature size (" + std::to_string(signature.size()) + " <= " + std::to_string(crypto_sign_PUBLICKEYBYTES) + ")");
			}

			unsigned char* message = new unsigned char[signature.size()];
			unsigned long long message_length;

			if (int ret = crypto_sign_open(
				message, &message_length,
				(unsigned char*)signature.data(), signature.size(),
				(unsigned char*)pk.data()) != 0) {
				throw std::runtime_error(std::string("sodium.signature.decode: Couldn't encrypt - ") + std::to_string(ret));
			}

			return std::string((char*)message, message_length);
		}

		int decodel(lua_State* L) {
			size_t size = 0;
			const char* _input = luaL::checklstring(L, 1, &size);
			std::string input = std::string(_input, size);

			if (input.size() == 0) {
				return luaL::error(L, "sodium.signature.decode: invalid input size (must be valid hexstring)");
			}

			input = from_hex(input);

			if (input.size() == 0) {
				return luaL::error(L, "sodium.signature.decode: invalid input size (must be valid hexstring)");
			}

			size = 0;
			const char* _pk = luaL::checklstring(L, 2, &size);
			std::string pk = std::string(_pk, size);

			if (pk.size() == 0) {
				return luaL::error(L, "sodium.signature.decode: invalid pk size (must be valid hexstring)");
			}

			pk = from_hex(pk);

			if (pk.size() == 0) {
				return luaL::error(L, "sodium.signature.decode: invalid pk size (must be valid hexstring)");
			}

			std::string output;

			try {
				output = decode(input, pk);
			}
			catch (std::exception& e) {
				return luaL::error(L, "%s", e.what());
			}

			lua::pushlstring(L, output.c_str(), output.size());

			return 1;
		}
	}

	namespace Hash {
		std::string enc256(std::string message) {
			unsigned char* hashed = new unsigned char[crypto_hash_sha256_BYTES];

			if (crypto_hash_sha256(hashed, (unsigned char*)message.data(), message.size()) != 0) {
				throw std::runtime_error("sodium.hash.enc256: Couldn't hash");
			}

			std::stringstream ss;
			ss << std::hex << std::setfill('0');
			for (size_t i = 0; i < crypto_hash_sha256_BYTES; ++i) {
				ss << std::setw(2) << static_cast<unsigned>(hashed[i]);
			}

			return ss.str();
		}

		int enc256l(lua_State* L) {
			size_t size = 0;
			const char* _input = luaL::checklstring(L, 1, &size);
			std::string input = std::string(_input, size);

			if (input.size() == 0) {
				return luaL::error(L, "sodium.hash.enc256: invalid input size");
			}

			std::string output = enc256(input);

			lua::pushlstring(L, output.c_str(), output.size());

			return 1;
		}

		std::string enc512(std::string message) {
			unsigned char* hashed = new unsigned char[crypto_hash_sha512_BYTES];

			if (crypto_hash_sha512(hashed, (unsigned char*)message.data(), message.size()) != 0) {
				throw std::runtime_error("sodium.hash.enc512: Couldn't hash");
			}

			std::stringstream ss;
			ss << std::hex << std::setfill('0');
			for (size_t i = 0; i < crypto_hash_sha512_BYTES; ++i) {
				ss << std::setw(2) << static_cast<unsigned>(hashed[i]);
			}

			return ss.str();
		}

		int enc512l(lua_State* L) {
			size_t size = 0;
			const char* _input = luaL::checklstring(L, 1, &size);
			std::string input = std::string(_input, size);

			if (input.size() == 0) {
				return luaL::error(L, "sodium.hash.enc512: invalid input size");
			}

			std::string output = enc512(input);

			lua::pushlstring(L, output.c_str(), output.size());

			return 1;
		}
	}

	namespace HMAC {
		std::string key256() {
			unsigned char* _key = new unsigned char[crypto_auth_hmacsha256_KEYBYTES];
			crypto_auth_hmacsha256_keygen(_key);
			return std::string((char*)_key, crypto_auth_hmacsha256_KEYBYTES);
		}

		int key256l(lua_State* L) {
			std::string _key;

			try {
				_key = key256();
			}
			catch (std::exception& e) {
				return luaL::error(L, "%s", e.what());
			}

			_key = to_hex(_key);

			lua::pushlstring(L, _key.c_str(), _key.size());
			return 1;
		}

		std::string enc256(std::string message, std::string key) {
			if (key.size() != crypto_auth_hmacsha256_KEYBYTES) {
				throw std::runtime_error("sodium.hmac.enc256: Invalid key size (" + std::to_string(key.size()) + " != " + std::to_string(crypto_auth_hmacsha256_KEYBYTES) + ")");
			}

			unsigned char* result = new unsigned char[crypto_auth_hmacsha256_BYTES];

			if (int ret = crypto_auth_hmacsha256(
				(unsigned char*)result,
				(unsigned char*)message.data(),
				message.size(),
				(unsigned char*)key.data()) != 0) {
				throw std::runtime_error(std::string("sodium.hmac.enc256: Couldn't hash - ") + std::to_string(ret));
			}

			return std::string((char*)result, crypto_auth_hmacsha256_BYTES);
		}

		int enc256l(lua_State* L) {
			size_t size = 0;
			const char* _input = luaL::checklstring(L, 1, &size);
			std::string input = std::string(_input, size);

			if (input.size() == 0) {
				return luaL::error(L, "sodium.hmac.enc256: invalid input size");
			}

			size = 0;
			const char* _key = luaL::checklstring(L, 2, &size);
			std::string key = std::string(_key, size);

			if (key.size() == 0) {
				return luaL::error(L, "sodium.hmac.enc256: invalid key size (must be valid hexstring)");
			}

			key = from_hex(key);

			if (key.size() == 0) {
				return luaL::error(L, "sodium.hmac.enc256: invalid key size (must be valid hexstring)");
			}

			std::string output;

			try {
				output = enc256(input, key);
			}
			catch (std::exception& e) {
				return luaL::error(L, "%s", e.what());
			}

			output = to_hex(output);

			lua::pushlstring(L, output.c_str(), output.size());

			return 1;
		}

		std::string key512() {
			unsigned char* _key = new unsigned char[crypto_auth_hmacsha512_KEYBYTES];
			crypto_auth_hmacsha512_keygen(_key);
			return std::string((char*)_key, crypto_auth_hmacsha512_KEYBYTES);
		}

		int key512l(lua_State* L) {
			std::string _key;

			try {
				_key = key512();
			}
			catch (std::exception& e) {
				return luaL::error(L, "%s", e.what());
			}

			_key = to_hex(_key);

			lua::pushlstring(L, _key.c_str(), _key.size());
			return 1;
		}

		std::string enc512(std::string message, std::string key) {
			if (key.size() != crypto_auth_hmacsha512_KEYBYTES) {
				throw std::runtime_error("sodium.hmac.enc512: Invalid key size (" + std::to_string(key.size()) + " != " + std::to_string(crypto_auth_hmacsha512_KEYBYTES) + ")");
			}

			unsigned char* result = new unsigned char[crypto_auth_hmacsha512_BYTES];

			if (int ret = crypto_auth_hmacsha512(
				(unsigned char*)result,
				(unsigned char*)message.data(),
				message.size(),
				(unsigned char*)key.data()) != 0) {
				throw std::runtime_error(std::string("sodium.hmac.enc512: Couldn't hash - ") + std::to_string(ret));
			}

			return std::string((char*)result, crypto_auth_hmacsha512_BYTES);
		}

		int enc512l(lua_State* L) {
			size_t size = 0;
			const char* _input = luaL::checklstring(L, 1, &size);
			std::string input = std::string(_input, size);

			if (input.size() == 0) {
				return luaL::error(L, "sodium.hmac.enc512: invalid input size");
			}

			size = 0;
			const char* _key = luaL::checklstring(L, 2, &size);
			std::string key = std::string(_key, size);

			if (key.size() == 0) {
				return luaL::error(L, "sodium.hmac.enc512: invalid key size (must be valid hexstring)");
			}

			key = from_hex(key);

			if (key.size() == 0) {
				return luaL::error(L, "sodium.hmac.enc512: invalid key size (must be valid hexstring)");
			}

			std::string output;

			try {
				output = enc512(input, key);
			}
			catch (std::exception& e) {
				return luaL::error(L, "%s", e.what());
			}

			output = to_hex(output);

			lua::pushlstring(L, output.c_str(), output.size());

			return 1;
		}

		std::string key512256() {
			unsigned char* _key = new unsigned char[crypto_auth_hmacsha512256_KEYBYTES];
			crypto_auth_hmacsha256_keygen(_key);
			return std::string((char*)_key, crypto_auth_hmacsha512256_KEYBYTES);
		}

		int key512256l(lua_State* L) {
			std::string _key;

			try {
				_key = key512256();
			}
			catch (std::exception& e) {
				return luaL::error(L, "%s", e.what());
			}

			_key = to_hex(_key);

			lua::pushlstring(L, _key.c_str(), _key.size());
			return 1;
		}

		std::string enc512256(std::string message, std::string key) {
			if (key.size() != crypto_auth_hmacsha512256_KEYBYTES) {
				throw std::runtime_error("sodium.hmac.enc512256: Invalid key size (" + std::to_string(key.size()) + " != " + std::to_string(crypto_auth_hmacsha512256_KEYBYTES) + ")");
			}

			unsigned char* result = new unsigned char[crypto_auth_hmacsha512256_BYTES];

			if (int ret = crypto_auth_hmacsha512256(
				(unsigned char*)result,
				(unsigned char*)message.data(),
				message.size(),
				(unsigned char*)key.data()) != 0) {
				throw std::runtime_error(std::string("sodium.hmac.enc512256: Couldn't hash - ") + std::to_string(ret));
			}

			return std::string((char*)result, crypto_auth_hmacsha512256_BYTES);
		}

		int enc512256l(lua_State* L) {
			size_t size = 0;
			const char* _input = luaL::checklstring(L, 1, &size);
			std::string input = std::string(_input, size);

			if (input.size() == 0) {
				return luaL::error(L, "sodium.hmac.enc512256: invalid input size");
			}

			size = 0;
			const char* _key = luaL::checklstring(L, 2, &size);
			std::string key = std::string(_key, size);

			if (key.size() == 0) {
				return luaL::error(L, "sodium.hmac.enc512256: invalid key size (must be valid hexstring)");
			}

			key = from_hex(key);

			if (key.size() == 0) {
				return luaL::error(L, "sodium.hmac.enc512256: invalid key size (must be valid hexstring)");
			}

			std::string output;

			try {
				output = enc512256(input, key);
			}
			catch (std::exception& e) {
				return luaL::error(L, "%s", e.what());
			}

			output = to_hex(output);

			lua::pushlstring(L, output.c_str(), output.size());

			return 1;
		}
	}

	namespace AEAD {
		namespace CHACHAPOLY {
			std::string nonce() {
				unsigned char* _key = new unsigned char[crypto_aead_chacha20poly1305_NPUBBYTES];
				randombytes_buf(_key, crypto_aead_chacha20poly1305_NPUBBYTES);
				std::string key = std::string((char*)_key, crypto_aead_chacha20poly1305_NPUBBYTES);
				delete[] _key;
				return key;
			}

			int noncel(lua_State* L) {
				std::string output;

				try {
					output = nonce();
				}
				catch (std::exception& e) {
					return luaL::error(L, "%s", e.what());
				}

				output = to_hex(output);

				lua::pushlstring(L, output.c_str(), output.size());
				return 1;
			}

			std::string key() {
				unsigned char* _key = new unsigned char[crypto_aead_chacha20poly1305_KEYBYTES];
				randombytes_buf(_key, crypto_aead_chacha20poly1305_KEYBYTES);
				std::string key = std::string((char*)_key, crypto_aead_chacha20poly1305_KEYBYTES);
				delete[] _key;
				return key;
			}

			std::string key(std::string base) {
				unsigned char* _key = new unsigned char[crypto_aead_chacha20poly1305_KEYBYTES];
				unsigned char* prk = new unsigned char[crypto_auth_hmacsha256_BYTES];

				crypto_auth_hmacsha256_state state;
				if (int ret = crypto_auth_hmacsha256_init(&state, (unsigned char*)base.data(), base.size()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.chachapoly.key: Couldn't hmac init - ") + std::to_string(ret));
				}

				if (int ret = crypto_auth_hmacsha256_update(&state, (unsigned char*)base.data(), base.size()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.chachapoly.key: Couldn't hmac update - ") + std::to_string(ret));
				}

				if (int ret = crypto_auth_hmacsha256_final(&state, prk) != 0) {
					throw std::runtime_error(std::string("sodium.aead.chachapoly.key: Couldn't hmac final - ") + std::to_string(ret));
				}

				if (int ret = crypto_generichash_blake2b_salt_personal(
					_key, crypto_aead_chacha20poly1305_KEYBYTES, NULL, NULL,
					prk, crypto_auth_hmacsha256_BYTES, NULL, NULL) != 0) {
					throw std::runtime_error(std::string("sodium.aead.chachapoly.key: Couldn't salt - ") + std::to_string(ret));
				}

				return std::string((char*)_key, crypto_aead_chacha20poly1305_KEYBYTES);
			}

			std::string key(std::string base, std::string salt) {
				unsigned char* _key = new unsigned char[crypto_aead_chacha20poly1305_KEYBYTES];
				unsigned char* prk = new unsigned char[crypto_auth_hmacsha256_BYTES];

				crypto_auth_hmacsha256_state state;
				if (int ret = crypto_auth_hmacsha256_init(&state, (unsigned char*)base.data(), base.size()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.chachapoly.key: Couldn't hmac init - ") + std::to_string(ret));
				}

				if (int ret = crypto_auth_hmacsha256_update(&state, (unsigned char*)salt.data(), salt.size()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.chachapoly.key: Couldn't hmac update - ") + std::to_string(ret));
				}

				if (int ret = crypto_auth_hmacsha256_final(&state, prk) != 0) {
					throw std::runtime_error(std::string("sodium.aead.chachapoly.key: Couldn't hmac final - ") + std::to_string(ret));
				}

				if (int ret = crypto_generichash_blake2b_salt_personal(
					_key, crypto_aead_chacha20poly1305_KEYBYTES, NULL, NULL,
					prk, crypto_auth_hmacsha256_BYTES, NULL, NULL) != 0) {
					throw std::runtime_error(std::string("sodium.aead.chachapoly.key: Couldn't salt - ") + std::to_string(ret));
				}

				return std::string((char*)_key, crypto_aead_chacha20poly1305_KEYBYTES);
			}

			int keyl(lua_State* L) {
				std::string output;

				if (lua::isstring(L, 2)) {
					size_t size = 0;
					const char* _input = luaL::checklstring(L, 1, &size);
					std::string input = std::string(_input, size);

					size = 0;
					const char* _salt = luaL::checklstring(L, 2, &size);
					std::string salt = std::string(_salt, size);

					std::string output;

					try {
						output = key(input, salt);
					}
					catch (std::exception& e) {
						return luaL::error(L, "%s", e.what());
					}

					output = to_hex(output);
				}
				else if (lua::isstring(L, 1)) {
					size_t size = 0;
					const char* _input = luaL::checklstring(L, 1, &size);
					std::string input = std::string(_input, size);

					std::string output;

					try {
						output = key(input);
					}
					catch (std::exception& e) {
						return luaL::error(L, "%s", e.what());
					}

					output = to_hex(output);
				}
				else {
					std::string output;

					try {
						output = key();
					}
					catch (std::exception& e) {
						return luaL::error(L, "%s", e.what());
					}

					output = to_hex(output);
				}

				lua::pushlstring(L, output.c_str(), output.size());

				return 1;
			}

			std::string encrypt(std::string message, std::string key, std::string nonce) {
				if (key.size() != crypto_aead_chacha20poly1305_KEYBYTES) {
					throw std::runtime_error("sodium.aead.chachapoly.encrypt: Invalid key size (" + std::to_string(key.size()) + " != " + std::to_string(crypto_aead_chacha20poly1305_KEYBYTES) + ")");
				}

				if (nonce.size() != crypto_aead_chacha20poly1305_NPUBBYTES) {
					throw std::runtime_error("sodium.aead.chachapoly.encrypt: Invalid nonce size (" + std::to_string(nonce.size()) + " != " + std::to_string(crypto_aead_chacha20poly1305_NPUBBYTES) + ")");
				}

				unsigned char* ciphertext = new unsigned char[message.size() + crypto_aead_chacha20poly1305_ABYTES];
				unsigned long long ciphertext_length;

				if (int ret = crypto_aead_chacha20poly1305_encrypt(
					ciphertext, &ciphertext_length,
					(const unsigned char*)message.data(), message.size(),
					NULL, 0, NULL,
					(const unsigned char*)nonce.data(),
					(const unsigned char*)key.data()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.chachapoly.encrypt: Couldn't encrypt - ") + std::to_string(ret));
				}

				return std::string((char*)ciphertext, ciphertext_length);
			}

			int encryptl(lua_State* L) {
				size_t size = 0;
				const char* _input = luaL::checklstring(L, 1, &size);
				std::string input = std::string(_input, size);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.encrypt: invalid input size");
				}

				size = 0;
				const char* _key = luaL::checklstring(L, 1, &size);
				std::string key = std::string(_key, size);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.encrypt: invalid key size (must be valid hexstring)");
				}

				key = from_hex(key);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.encrypt: invalid key size (must be valid hexstring)");
				}

				size = 0;
				const char* _nonce = luaL::checklstring(L, 1, &size);
				std::string nonce = std::string(_nonce, size);

				if (nonce.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.encrypt: invalid nonce size (must be valid hexstring)");
				}

				nonce = from_hex(nonce);

				if (nonce.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.encrypt: invalid nonce size (must be valid hexstring)");
				}

				std::string output;

				try {
					output = encrypt(input, key, nonce);
				}
				catch (std::exception& e) {
					return luaL::error(L, "%s", e.what());
				}

				output = to_hex(output);

				lua::pushlstring(L, output.c_str(), output.size());

				return 1;
			}

			std::string decrypt(std::string ciphertext, std::string key, std::string nonce) {
				if (key.size() != crypto_aead_chacha20poly1305_KEYBYTES) {
					throw std::runtime_error("sodium.aead.chachapoly.decrypt: Invalid key size (" + std::to_string(key.size()) + " != " + std::to_string(crypto_aead_chacha20poly1305_KEYBYTES));
				}

				if (nonce.size() != crypto_aead_chacha20poly1305_NPUBBYTES) {
					throw std::runtime_error("sodium.aead.chachapoly.decrypt: Invalid nonce size (" + std::to_string(nonce.size()) + " != " + std::to_string(crypto_aead_chacha20poly1305_NPUBBYTES) + ")");
				}

				if (ciphertext.size() <= crypto_aead_chacha20poly1305_ABYTES) {
					throw std::runtime_error("sodium.aead.chachapoly.decrypt: Invalid ciphertext size (" + std::to_string(ciphertext.size()) + " <= " + std::to_string(crypto_aead_chacha20poly1305_ABYTES) + ")");
				}

				unsigned char* plaintext = new unsigned char[ciphertext.size()];
				unsigned long long plaintext_length;

				if (int ret = crypto_aead_chacha20poly1305_decrypt(
					plaintext, &plaintext_length,
					NULL,
					(const unsigned char*)ciphertext.data(), ciphertext.size(),
					NULL, 0,
					(const unsigned char*)nonce.data(),
					(const unsigned char*)key.data()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.chachapoly.decrypt: Couldn't decrypt - ") + std::to_string(ret));
				}

				return std::string((char*)plaintext, plaintext_length);
			}

			int decryptl(lua_State* L) {
				size_t size = 0;
				const char* _input = luaL::checklstring(L, 1, &size);
				std::string input = std::string(_input, size);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.decrypt: invalid input size (must be valid hexstring)");
				}

				input = from_hex(input);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.decrypt: invalid input size (must be valid hexstring)");
				}

				size = 0;
				const char* _key = luaL::checklstring(L, 1, &size);
				std::string key = std::string(_key, size);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.decrypt: invalid key size (must be valid hexstring)");
				}

				key = from_hex(key);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.decrypt: invalid key size (must be valid hexstring)");
				}

				size = 0;
				const char* _nonce = luaL::checklstring(L, 1, &size);
				std::string nonce = std::string(_nonce, size);

				if (nonce.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.decrypt: invalid nonce size (must be valid hexstring)");
				}

				nonce = from_hex(nonce);

				if (nonce.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.decrypt: invalid nonce size (must be valid hexstring)");
				}

				std::string output;

				try {
					output = decrypt(input, key, nonce);
				}
				catch (std::exception& e) {
					return luaL::error(L, "%s", e.what());
				}

				lua::pushlstring(L, output.c_str(), output.size());

				return 1;
			}

			std::string encode(std::string message, std::string key) {
				if (key.size() != crypto_aead_chacha20poly1305_KEYBYTES) {
					throw std::runtime_error("sodium.aead.chachapoly.encode: Invalid key size (" + std::to_string(key.size()) + " != " + std::to_string(crypto_aead_chacha20poly1305_KEYBYTES) + ")");
				}

				std::string nonce_ = nonce();
				std::string encrypted = encrypt(message, key, nonce_);
				std::string finalized = encrypted + nonce_;

				return finalized;
			}

			int encodel(lua_State* L) {
				size_t size = 0;
				const char* _input = luaL::checklstring(L, 1, &size);
				std::string input = std::string(_input, size);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.encode: invalid input size");
				}

				size = 0;
				const char* _key = luaL::checklstring(L, 1, &size);
				std::string key = std::string(_key, size);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.encode: invalid key size (must be valid hexstring)");
				}

				key = from_hex(key);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.encode: invalid key size (must be valid hexstring)");
				}

				std::string output;

				try {
					output = encode(input, key);
				}
				catch (std::exception& e) {
					return luaL::error(L, "%s", e.what());
				}

				output = to_hex(output);

				lua::pushlstring(L, output.c_str(), output.size());

				return 1;
			}

			std::string decode(std::string message, std::string key) {
				if (key.size() != crypto_aead_chacha20poly1305_KEYBYTES) {
					throw std::runtime_error("sodium.aead.chachapoly.decode: Invalid key size (" + std::to_string(key.size()) + " != " + std::to_string(crypto_aead_chacha20poly1305_KEYBYTES) + ")");
				}

				std::string nonce_ = message.substr(message.size() - crypto_aead_chacha20poly1305_NPUBBYTES);
				std::string encrypted = message.substr(0, message.size() - crypto_aead_chacha20poly1305_NPUBBYTES);
				std::string decrypted = decrypt(encrypted, key, nonce_);

				return decrypted;
			}

			int decodel(lua_State* L) {
				size_t size = 0;
				const char* _input = luaL::checklstring(L, 1, &size);
				std::string input = std::string(_input, size);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.decode: invalid input size (must be valid hexstring)");
				}

				input = from_hex(input);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.decode: invalid input size (must be valid hexstring)");
				}

				size = 0;
				const char* _key = luaL::checklstring(L, 1, &size);
				std::string key = std::string(_key, size);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.decode: invalid key size (must be valid hexstring)");
				}

				key = from_hex(key);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.chachapoly.decode: invalid key size (must be valid hexstring)");
				}

				std::string output;

				try {
					output = decode(input, key);
				}
				catch (std::exception& e) {
					return luaL::error(L, "%s", e.what());
				}

				lua::pushlstring(L, output.c_str(), output.size());

				return 1;
			}
		}

		namespace GCM {
			std::string nonce() {
				unsigned char* _key = new unsigned char[crypto_aead_aes256gcm_NPUBBYTES];
				randombytes_buf(_key, crypto_aead_aes256gcm_NPUBBYTES);
				std::string key = std::string((char*)_key, crypto_aead_aes256gcm_NPUBBYTES);
				delete[] _key;
				return key;
			}

			int noncel(lua_State* L) {
				std::string output;

				try {
					output = nonce();
				}
				catch (std::exception& e) {
					return luaL::error(L, "%s", e.what());
				}

				output = to_hex(output);

				lua::pushlstring(L, output.c_str(), output.size());
				return 1;
			}

			std::string key() {
				unsigned char* _key = new unsigned char[crypto_aead_aes256gcm_KEYBYTES];
				randombytes_buf(_key, crypto_aead_aes256gcm_KEYBYTES);
				std::string key = std::string((char*)_key, crypto_aead_aes256gcm_KEYBYTES);
				delete[] _key;
				return key;
			}

			std::string key(std::string base) {
				unsigned char* _key = new unsigned char[crypto_aead_aes256gcm_KEYBYTES];
				unsigned char* prk = new unsigned char[crypto_auth_hmacsha256_BYTES];

				crypto_auth_hmacsha256_state state;
				if (int ret = crypto_auth_hmacsha256_init(&state, (unsigned char*)base.data(), base.size()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.gcm.key: Couldn't hmac init - ") + std::to_string(ret));
				}

				if (int ret = crypto_auth_hmacsha256_update(&state, (unsigned char*)base.data(), base.size()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.gcm.key: Couldn't hmac update - ") + std::to_string(ret));
				}

				if (int ret = crypto_auth_hmacsha256_final(&state, prk) != 0) {
					throw std::runtime_error(std::string("sodium.aead.gcm.key: Couldn't hmac final - ") + std::to_string(ret));
				}

				if (int ret = crypto_generichash_blake2b_salt_personal(
					_key, crypto_aead_aes256gcm_KEYBYTES, NULL, NULL,
					prk, crypto_auth_hmacsha256_BYTES, NULL, NULL) != 0) {
					throw std::runtime_error(std::string("sodium.aead.gcm.key: Couldn't salt - ") + std::to_string(ret));
				}

				return std::string((char*)_key, crypto_aead_aes256gcm_KEYBYTES);
			}

			std::string key(std::string base, std::string salt) {
				unsigned char* _key = new unsigned char[crypto_aead_aes256gcm_KEYBYTES];
				unsigned char* prk = new unsigned char[crypto_auth_hmacsha256_BYTES];

				crypto_auth_hmacsha256_state state;
				if (int ret = crypto_auth_hmacsha256_init(&state, (unsigned char*)base.data(), base.size()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.gcm.key: Couldn't hmac init - ") + std::to_string(ret));
				}

				if (int ret = crypto_auth_hmacsha256_update(&state, (unsigned char*)salt.data(), salt.size()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.gcm.key: Couldn't hmac update - ") + std::to_string(ret));
				}

				if (int ret = crypto_auth_hmacsha256_final(&state, prk) != 0) {
					throw std::runtime_error(std::string("sodium.aead.gcm.key: Couldn't hmac final - ") + std::to_string(ret));
				}

				if (int ret = crypto_generichash_blake2b_salt_personal(
					_key, crypto_aead_aes256gcm_KEYBYTES, NULL, NULL,
					prk, crypto_auth_hmacsha256_BYTES, NULL, NULL) != 0) {
					throw std::runtime_error(std::string("sodium.aead.gcm.key: Couldn't salt - ") + std::to_string(ret));
				}

				return std::string((char*)_key, crypto_aead_aes256gcm_KEYBYTES);
			}

			int keyl(lua_State* L) {
				std::string output;

				if (lua::isstring(L, 2)) {
					size_t size = 0;
					const char* _input = luaL::checklstring(L, 1, &size);
					std::string input = std::string(_input, size);

					size = 0;
					const char* _salt = luaL::checklstring(L, 2, &size);
					std::string salt = std::string(_salt, size);

					std::string output;

					try {
						output = key(input, salt);
					}
					catch (std::exception& e) {
						return luaL::error(L, "%s", e.what());
					}

					output = to_hex(output);
				}
				else if (lua::isstring(L, 1)) {
					size_t size = 0;
					const char* _input = luaL::checklstring(L, 1, &size);
					std::string input = std::string(_input, size);

					std::string output;

					try {
						output = key(input);
					}
					catch (std::exception& e) {
						return luaL::error(L, "%s", e.what());
					}

					output = to_hex(output);
				}
				else {
					std::string output;

					try {
						output = key();
					}
					catch (std::exception& e) {
						return luaL::error(L, "%s", e.what());
					}

					output = to_hex(output);
				}

				lua::pushlstring(L, output.c_str(), output.size());

				return 1;
			}

			std::string encrypt(std::string message, std::string key, std::string nonce) {
				if (key.size() != crypto_aead_aes256gcm_KEYBYTES) {
					throw std::runtime_error("sodium.aead.gcm.encrypt: Invalid key size (" + std::to_string(key.size()) + " != " + std::to_string(crypto_aead_aes256gcm_KEYBYTES) + ")");
				}

				if (nonce.size() != crypto_aead_aes256gcm_NPUBBYTES) {
					throw std::runtime_error("sodium.aead.gcm.encrypt: Invalid nonce size (" + std::to_string(nonce.size()) + " != " + std::to_string(crypto_aead_aes256gcm_NPUBBYTES) + ")");
				}

				unsigned char* ciphertext = new unsigned char[message.size() + crypto_aead_aes256gcm_ABYTES];
				unsigned long long ciphertext_length;

				if (int ret = crypto_aead_aes256gcm_encrypt(
					ciphertext, &ciphertext_length,
					(const unsigned char*)message.data(), message.size(),
					NULL, 0, NULL,
					(const unsigned char*)nonce.data(),
					(const unsigned char*)key.data()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.gcm.encrypt: Couldn't encrypt - ") + std::to_string(ret));
				}

				return std::string((char*)ciphertext, ciphertext_length);
			}

			int encryptl(lua_State* L) {
				size_t size = 0;
				const char* _input = luaL::checklstring(L, 1, &size);
				std::string input = std::string(_input, size);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.encrypt: invalid input size");
				}

				size = 0;
				const char* _key = luaL::checklstring(L, 1, &size);
				std::string key = std::string(_key, size);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.encrypt: invalid key size (must be valid hexstring)");
				}

				key = from_hex(key);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.encrypt: invalid key size (must be valid hexstring)");
				}

				size = 0;
				const char* _nonce = luaL::checklstring(L, 1, &size);
				std::string nonce = std::string(_nonce, size);

				if (nonce.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.encrypt: invalid nonce size (must be valid hexstring)");
				}

				nonce = from_hex(nonce);

				if (nonce.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.encrypt: invalid nonce size (must be valid hexstring)");
				}

				std::string output;

				try {
					output = encrypt(input, key, nonce);
				}
				catch (std::exception& e) {
					return luaL::error(L, "%s", e.what());
				}

				output = to_hex(output);

				lua::pushlstring(L, output.c_str(), output.size());

				return 1;
			}

			std::string decrypt(std::string ciphertext, std::string key, std::string nonce) {
				if (key.size() != crypto_aead_aes256gcm_KEYBYTES) {
					throw std::runtime_error("sodium.aes.gcm.decrypt: Invalid key size (" + std::to_string(key.size()) + " != " + std::to_string(crypto_aead_aes256gcm_KEYBYTES) + ")");
				}

				if (nonce.size() != crypto_aead_aes256gcm_NPUBBYTES) {
					throw std::runtime_error("sodium.aead.gcm.decrypt: Invalid nonce size (" + std::to_string(nonce.size()) + " != " + std::to_string(crypto_aead_aes256gcm_NPUBBYTES) + ")");
				}

				if (ciphertext.size() <= crypto_aead_aes256gcm_ABYTES) {
					throw std::runtime_error("sodium.aead.gcm.decrypt: Invalid ciphertext size (" + std::to_string(ciphertext.size()) + " <= " + std::to_string(crypto_aead_aes256gcm_ABYTES) + ")");
				}

				unsigned char* plaintext = new unsigned char[ciphertext.size()];
				unsigned long long plaintext_length;

				if (int ret = crypto_aead_aes256gcm_decrypt(
					plaintext, &plaintext_length,
					NULL,
					(const unsigned char*)ciphertext.data(), ciphertext.size(),
					NULL, 0,
					(const unsigned char*)nonce.data(),
					(const unsigned char*)key.data()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.gcm.decrypt: Couldn't decrypt - ") + std::to_string(ret));
				}

				return std::string((char*)plaintext, plaintext_length);
			}

			int decryptl(lua_State* L) {
				size_t size = 0;
				const char* _input = luaL::checklstring(L, 1, &size);
				std::string input = std::string(_input, size);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.decrypt: invalid input size (must be valid hexstring)");
				}

				input = from_hex(input);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.decrypt: invalid input size (must be valid hexstring)");
				}

				size = 0;
				const char* _key = luaL::checklstring(L, 1, &size);
				std::string key = std::string(_key, size);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.decrypt: invalid key size (must be valid hexstring)");
				}

				key = from_hex(key);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.decrypt: invalid key size (must be valid hexstring)");
				}

				size = 0;
				const char* _nonce = luaL::checklstring(L, 1, &size);
				std::string nonce = std::string(_nonce, size);

				if (nonce.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.decrypt: invalid nonce size (must be valid hexstring)");
				}

				nonce = from_hex(nonce);

				if (nonce.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.decrypt: invalid nonce size (must be valid hexstring)");
				}

				std::string output;

				try {
					output = decrypt(input, key, nonce);
				}
				catch (std::exception& e) {
					return luaL::error(L, "%s", e.what());
				}

				lua::pushlstring(L, output.c_str(), output.size());

				return 1;
			}

			std::string encode(std::string message, std::string key) {
				if (key.size() != crypto_aead_aes256gcm_KEYBYTES) {
					throw std::runtime_error("sodium.aead.gcm.encode: Invalid key size (" + std::to_string(key.size()) + " != " + std::to_string(crypto_aead_aes256gcm_KEYBYTES) + ")");
				}

				std::string nonce_ = nonce();
				std::string encrypted = encrypt(message, key, nonce_);
				std::string finalized = encrypted + nonce_;

				return finalized;
			}

			int encodel(lua_State* L) {
				size_t size = 0;
				const char* _input = luaL::checklstring(L, 1, &size);
				std::string input = std::string(_input, size);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.encode: invalid input size");
				}

				size = 0;
				const char* _key = luaL::checklstring(L, 1, &size);
				std::string key = std::string(_key, size);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.encode: invalid key size (must be valid hexstring)");
				}

				key = from_hex(key);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.encode: invalid key size (must be valid hexstring)");
				}

				std::string output;

				try {
					output = encode(input, key);
				}
				catch (std::exception& e) {
					return luaL::error(L, "%s", e.what());
				}

				output = to_hex(output);

				lua::pushlstring(L, output.c_str(), output.size());

				return 1;
			}

			std::string decode(std::string message, std::string key) {
				if (key.size() != crypto_aead_aes256gcm_KEYBYTES) {
					throw std::runtime_error("sodium.aes.gcm.decode: Invalid key size (" + std::to_string(key.size()) + " != " + std::to_string(crypto_aead_aes256gcm_KEYBYTES) + ")");
				}

				std::string nonce_ = message.substr(message.size() - crypto_aead_aes256gcm_NPUBBYTES);
				std::string encrypted = message.substr(0, message.size() - crypto_aead_aes256gcm_NPUBBYTES);
				std::string decrypted = decrypt(encrypted, key, nonce_);

				return decrypted;
			}

			int decodel(lua_State* L) {
				size_t size = 0;
				const char* _input = luaL::checklstring(L, 1, &size);
				std::string input = std::string(_input, size);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.decode: invalid input size (must be valid hexstring)");
				}

				input = from_hex(input);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.decode: invalid input size (must be valid hexstring)");
				}

				size = 0;
				const char* _key = luaL::checklstring(L, 1, &size);
				std::string key = std::string(_key, size);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.decode: invalid key size (must be valid hexstring)");
				}

				key = from_hex(key);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.gcm.decode: invalid key size (must be valid hexstring)");
				}

				std::string output;

				try {
					output = decode(input, key);
				}
				catch (std::exception& e) {
					return luaL::error(L, "%s", e.what());
				}

				lua::pushlstring(L, output.c_str(), output.size());

				return 1;
			}
		}

		namespace AEGIS {
			std::string nonce() {
				unsigned char* _key = new unsigned char[crypto_aead_aegis256_NPUBBYTES];
				randombytes_buf(_key, crypto_aead_aegis256_NPUBBYTES);
				std::string key = std::string((char*)_key, crypto_aead_aegis256_NPUBBYTES);
				delete[] _key;
				return key;
			}

			int noncel(lua_State* L) {
				std::string output;

				try {
					output = nonce();
				}
				catch (std::exception& e) {
					return luaL::error(L, "%s", e.what());
				}

				output = to_hex(output);

				lua::pushlstring(L, output.c_str(), output.size());
				return 1;
			}

			std::string key() {
				unsigned char* _key = new unsigned char[crypto_aead_aegis256_KEYBYTES];
				randombytes_buf(_key, crypto_aead_aegis256_KEYBYTES);
				std::string key = std::string((char*)_key, crypto_aead_aegis256_KEYBYTES);
				delete[] _key;
				return key;
			}

			std::string key(std::string base) {
				unsigned char* _key = new unsigned char[crypto_aead_aegis256_KEYBYTES];
				unsigned char* prk = new unsigned char[crypto_auth_hmacsha256_BYTES];

				crypto_auth_hmacsha256_state state;
				if (int ret = crypto_auth_hmacsha256_init(&state, (unsigned char*)base.data(), base.size()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.aegis.key: Couldn't hmac init - ") + std::to_string(ret));
				}

				if (int ret = crypto_auth_hmacsha256_update(&state, (unsigned char*)base.data(), base.size()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.aegis.key: Couldn't hmac update - ") + std::to_string(ret));
				}

				if (int ret = crypto_auth_hmacsha256_final(&state, prk) != 0) {
					throw std::runtime_error(std::string("sodium.aead.aegis.key: Couldn't hmac final - ") + std::to_string(ret));
				}

				if (int ret = crypto_generichash_blake2b_salt_personal(
					_key, crypto_aead_aegis256_KEYBYTES, NULL, NULL,
					prk, crypto_auth_hmacsha256_BYTES, NULL, NULL) != 0) {
					throw std::runtime_error(std::string("sodium.aead.aegis.key: Couldn't salt - ") + std::to_string(ret));
				}

				return std::string((char*)_key, crypto_aead_aegis256_KEYBYTES);
			}

			std::string key(std::string base, std::string salt) {
				unsigned char* _key = new unsigned char[crypto_aead_aegis256_KEYBYTES];
				unsigned char* prk = new unsigned char[crypto_auth_hmacsha256_BYTES];

				crypto_auth_hmacsha256_state state;
				if (int ret = crypto_auth_hmacsha256_init(&state, (unsigned char*)base.data(), base.size()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.aegis.key: Couldn't hmac init - ") + std::to_string(ret));
				}

				if (int ret = crypto_auth_hmacsha256_update(&state, (unsigned char*)salt.data(), salt.size()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.aegis.key: Couldn't hmac update - ") + std::to_string(ret));
				}

				if (int ret = crypto_auth_hmacsha256_final(&state, prk) != 0) {
					throw std::runtime_error(std::string("sodium.aead.aegis.key: Couldn't hmac final - ") + std::to_string(ret));
				}

				if (int ret = crypto_generichash_blake2b_salt_personal(
					_key, crypto_aead_aegis256_KEYBYTES, NULL, NULL,
					prk, crypto_auth_hmacsha256_BYTES, NULL, NULL) != 0) {
					throw std::runtime_error(std::string("sodium.aead.aegis.key: Couldn't salt - ") + std::to_string(ret));
				}

				return std::string((char*)_key, crypto_aead_aegis256_KEYBYTES);
			}

			int keyl(lua_State* L) {
				std::string output;

				if (lua::isstring(L, 2)) {
					size_t size = 0;
					const char* _input = luaL::checklstring(L, 1, &size);
					std::string input = std::string(_input, size);

					size = 0;
					const char* _salt = luaL::checklstring(L, 2, &size);
					std::string salt = std::string(_salt, size);

					std::string output;

					try {
						output = key(input, salt);
					}
					catch (std::exception& e) {
						return luaL::error(L, "%s", e.what());
					}

					output = to_hex(output);
				}
				else if (lua::isstring(L, 1)) {
					size_t size = 0;
					const char* _input = luaL::checklstring(L, 1, &size);
					std::string input = std::string(_input, size);

					std::string output;

					try {
						output = key(input);
					}
					catch (std::exception& e) {
						return luaL::error(L, "%s", e.what());
					}

					output = to_hex(output);
				}
				else {
					std::string output;

					try {
						output = key();
					}
					catch (std::exception& e) {
						return luaL::error(L, "%s", e.what());
					}

					output = to_hex(output);
				}

				lua::pushlstring(L, output.c_str(), output.size());

				return 1;
			}

			std::string encrypt(std::string message, std::string key, std::string nonce) {
				if (key.size() != crypto_aead_aegis256_KEYBYTES) {
					throw std::runtime_error("sodium.aead.aegis.encrypt: Invalid key size (" + std::to_string(key.size()) + " != " + std::to_string(crypto_aead_aegis256_KEYBYTES) + ")");
				}

				if (nonce.size() != crypto_aead_aegis256_NPUBBYTES) {
					throw std::runtime_error("sodium.aead.aegis.encrypt: Invalid nonce size (" + std::to_string(nonce.size()) + " != " + std::to_string(crypto_aead_aegis256_NPUBBYTES) + ")");
				}

				unsigned char* ciphertext = new unsigned char[message.size() + crypto_aead_aegis256_ABYTES];
				unsigned long long ciphertext_length;

				if (int ret = crypto_aead_aegis256_encrypt(
					ciphertext, &ciphertext_length,
					(const unsigned char*)message.data(), message.size(),
					NULL, 0, NULL,
					(const unsigned char*)nonce.data(),
					(const unsigned char*)key.data()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.aegis.encrypt: Couldn't encrypt - ") + std::to_string(ret));
				}

				return std::string((char*)ciphertext, ciphertext_length);
			}

			int encryptl(lua_State* L) {
				size_t size = 0;
				const char* _input = luaL::checklstring(L, 1, &size);
				std::string input = std::string(_input, size);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.encrypt: invalid input size");
				}

				size = 0;
				const char* _key = luaL::checklstring(L, 1, &size);
				std::string key = std::string(_key, size);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.encrypt: invalid key size (must be valid hexstring)");
				}

				key = from_hex(key);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.encrypt: invalid key size (must be valid hexstring)");
				}

				size = 0;
				const char* _nonce = luaL::checklstring(L, 1, &size);
				std::string nonce = std::string(_nonce, size);

				if (nonce.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.encrypt: invalid nonce size (must be valid hexstring)");
				}

				nonce = from_hex(nonce);

				if (nonce.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.encrypt: invalid nonce size (must be valid hexstring)");
				}

				std::string output;

				try {
					output = encrypt(input, key, nonce);
				}
				catch (std::exception& e) {
					return luaL::error(L, "%s", e.what());
				}

				output = to_hex(output);

				lua::pushlstring(L, output.c_str(), output.size());

				return 1;
			}

			std::string decrypt(std::string ciphertext, std::string key, std::string nonce) {
				if (key.size() != crypto_aead_aegis256_KEYBYTES) {
					throw std::runtime_error("sodium.aes.aegis.decrypt: Invalid key size (" + std::to_string(key.size()) + " != " + std::to_string(crypto_aead_aegis256_KEYBYTES) + ")");
				}

				if (nonce.size() != crypto_aead_aegis256_NPUBBYTES) {
					throw std::runtime_error("sodium.aead.aegis.decrypt: Invalid nonce size (" + std::to_string(nonce.size()) + " != " + std::to_string(crypto_aead_aegis256_NPUBBYTES) + ")");
				}

				if (ciphertext.size() <= crypto_aead_aegis256_ABYTES) {
					throw std::runtime_error("sodium.aead.aegis.decrypt: Invalid ciphertext size (" + std::to_string(ciphertext.size()) + " <= " + std::to_string(crypto_aead_aegis256_ABYTES) + ")");
				}

				unsigned char* plaintext = new unsigned char[ciphertext.size()];
				unsigned long long plaintext_length;

				if (int ret = crypto_aead_aegis256_decrypt(
					plaintext, &plaintext_length,
					NULL,
					(const unsigned char*)ciphertext.data(), ciphertext.size(),
					NULL, 0,
					(const unsigned char*)nonce.data(),
					(const unsigned char*)key.data()) != 0) {
					throw std::runtime_error(std::string("sodium.aead.aegis.decrypt: Couldn't decrypt - ") + std::to_string(ret));
				}

				return std::string((char*)plaintext, plaintext_length);
			}

			int decryptl(lua_State* L) {
				size_t size = 0;
				const char* _input = luaL::checklstring(L, 1, &size);
				std::string input = std::string(_input, size);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.decrypt: invalid input size (must be valid hexstring)");
				}

				input = from_hex(input);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.decrypt: invalid input size (must be valid hexstring)");
				}

				size = 0;
				const char* _key = luaL::checklstring(L, 1, &size);
				std::string key = std::string(_key, size);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.decrypt: invalid key size (must be valid hexstring)");
				}

				key = from_hex(key);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.decrypt: invalid key size (must be valid hexstring)");
				}

				size = 0;
				const char* _nonce = luaL::checklstring(L, 1, &size);
				std::string nonce = std::string(_nonce, size);

				if (nonce.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.decrypt: invalid nonce size (must be valid hexstring)");
				}

				nonce = from_hex(nonce);

				if (nonce.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.decrypt: invalid nonce size (must be valid hexstring)");
				}

				std::string output;

				try {
					output = decrypt(input, key, nonce);
				}
				catch (std::exception& e) {
					return luaL::error(L, "%s", e.what());
				}

				lua::pushlstring(L, output.c_str(), output.size());

				return 1;
			}

			std::string encode(std::string message, std::string key) {
				if (key.size() != crypto_aead_aegis256_KEYBYTES) {
					throw std::runtime_error("sodium.aead.aegis.encode: Invalid key size (" + std::to_string(key.size()) + " != " + std::to_string(crypto_aead_aegis256_KEYBYTES) + ")");
				}

				std::string nonce_ = nonce();
				std::string encrypted = encrypt(message, key, nonce_);
				std::string finalized = encrypted + nonce_;

				return finalized;
			}

			int encodel(lua_State* L) {
				size_t size = 0;
				const char* _input = luaL::checklstring(L, 1, &size);
				std::string input = std::string(_input, size);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.encode: invalid input size");
				}

				size = 0;
				const char* _key = luaL::checklstring(L, 1, &size);
				std::string key = std::string(_key, size);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.encode: invalid key size (must be valid hexstring)");
				}

				key = from_hex(key);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.encode: invalid key size (must be valid hexstring)");
				}

				std::string output;

				try {
					output = encode(input, key);
				}
				catch (std::exception& e) {
					return luaL::error(L, "%s", e.what());
				}

				output = to_hex(output);

				lua::pushlstring(L, output.c_str(), output.size());

				return 1;
			}

			std::string decode(std::string message, std::string key) {
				if (key.size() != crypto_aead_aegis256_KEYBYTES) {
					throw std::runtime_error("sodium.aes.aegis.decode: Invalid key size (" + std::to_string(key.size()) + " != " + std::to_string(crypto_aead_aegis256_KEYBYTES) + ")");
				}

				std::string nonce_ = message.substr(message.size() - crypto_aead_aegis256_NPUBBYTES);
				std::string encrypted = message.substr(0, message.size() - crypto_aead_aegis256_NPUBBYTES);
				std::string decrypted = decrypt(encrypted, key, nonce_);

				return decrypted;
			}

			int decodel(lua_State* L) {
				size_t size = 0;
				const char* _input = luaL::checklstring(L, 1, &size);
				std::string input = std::string(_input, size);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.decode: invalid input size (must be valid hexstring)");
				}

				input = from_hex(input);

				if (input.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.decode: invalid input size (must be valid hexstring)");
				}

				size = 0;
				const char* _key = luaL::checklstring(L, 1, &size);
				std::string key = std::string(_key, size);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.decode: invalid key size (must be valid hexstring)");
				}

				key = from_hex(key);

				if (key.size() == 0) {
					return luaL::error(L, "sodium.aead.aegis.decode: invalid key size (must be valid hexstring)");
				}

				std::string output;

				try {
					output = decode(input, key);
				}
				catch (std::exception& e) {
					return luaL::error(L, "%s", e.what());
				}

				lua::pushlstring(L, output.c_str(), output.size());

				return 1;
			}
		}
	}

    void push(API::lua_State* L, UMODULE hndle) {
		sodium_init();

		lua::newtable(L);

		lua::pushstring(L, SODIUM_VERSION_STRING);
		lua::setfield(L, -2, "version");

		lua::pushcfunction(L, randoml);
		lua::setfield(L, -2, "random");
		
		lua::newtable(L);
			lua::pushcfunction(L, Hex::encodel);
			lua::setfield(L, -2, "encode");
			lua::pushcfunction(L, Hex::decodel);
			lua::setfield(L, -2, "decode");
		lua::setfield(L, -2, "hex");

		lua::newtable(L);
			lua::pushcfunction(L, Base64::encodel);
			lua::setfield(L, -2, "encode");
			lua::pushcfunction(L, Base64::decodel);
			lua::setfield(L, -2, "decode");
			lua::pushcfunction(L, Base64::xencodel);
			lua::setfield(L, -2, "xencode");
			lua::pushcfunction(L, Base64::xdecodel);
			lua::setfield(L, -2, "xdecode");
		lua::setfield(L, -2, "base64");

		lua::newtable(L);
			lua::pushcfunction(L, Signature::keypairl);
			lua::setfield(L, -2, "key");
			lua::pushcfunction(L, Signature::encodel);
			lua::setfield(L, -2, "encode");
			lua::pushcfunction(L, Signature::decodel);
			lua::setfield(L, -2, "decode");
		lua::setfield(L, -2, "signature");

		lua::newtable(L);
			lua::pushcfunction(L, Hash::enc256l);
			lua::setfield(L, -2, "enc256");
			lua::pushcfunction(L, Hash::enc512l);
			lua::setfield(L, -2, "enc512");
		lua::setfield(L, -2, "hash");

		lua::newtable(L);
			lua::pushcfunction(L, HMAC::key256l);
			lua::setfield(L, -2, "key256");
			lua::pushcfunction(L, HMAC::enc256l);
			lua::setfield(L, -2, "enc256");
			lua::pushcfunction(L, HMAC::key512l);
			lua::setfield(L, -2, "key512");
			lua::pushcfunction(L, HMAC::enc512l);
			lua::setfield(L, -2, "enc512");
			lua::pushcfunction(L, HMAC::key512256l);
			lua::setfield(L, -2, "key512256");
			lua::pushcfunction(L, HMAC::enc512256l);
			lua::setfield(L, -2, "enc512256");
		lua::setfield(L, -2, "hmac");

		lua::newtable(L);
		{
			using namespace AEAD;

			lua::newtable(L);
				lua::pushcfunction(L, CHACHAPOLY::keyl);
				lua::setfield(L, -2, "key");
				lua::pushcfunction(L, CHACHAPOLY::encodel);
				lua::setfield(L, -2, "encode");
				lua::pushcfunction(L, CHACHAPOLY::decodel);
				lua::setfield(L, -2, "decode");
				lua::pushcfunction(L, CHACHAPOLY::encryptl);
				lua::setfield(L, -2, "encrypt");
				lua::pushcfunction(L, CHACHAPOLY::decryptl);
				lua::setfield(L, -2, "decrypt");
			lua::setfield(L, -2, "chachapoly");

			lua::newtable(L);
				lua::pushcfunction(L, GCM::keyl);
				lua::setfield(L, -2, "key");
				lua::pushcfunction(L, GCM::encodel);
				lua::setfield(L, -2, "encode");
				lua::pushcfunction(L, GCM::decodel);
				lua::setfield(L, -2, "decode");
				lua::pushcfunction(L, GCM::encryptl);
				lua::setfield(L, -2, "encrypt");
				lua::pushcfunction(L, GCM::decryptl);
				lua::setfield(L, -2, "decrypt");
			lua::setfield(L, -2, "gcm");

			lua::newtable(L);
				lua::pushcfunction(L, AEGIS::keyl);
				lua::setfield(L, -2, "key");
				lua::pushcfunction(L, AEGIS::encodel);
				lua::setfield(L, -2, "encode");
				lua::pushcfunction(L, AEGIS::decodel);
				lua::setfield(L, -2, "decode");
				lua::pushcfunction(L, AEGIS::encryptl);
				lua::setfield(L, -2, "encrypt");
				lua::pushcfunction(L, AEGIS::decryptl);
				lua::setfield(L, -2, "decrypt");
			lua::setfield(L, -2, "aegis");
		}
		lua::setfield(L, -2, "aead");
    }

    void api() {
		Reflection::add("sodium", push);
    }
}