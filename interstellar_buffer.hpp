#pragma once
#include "interstellar.hpp"
#include <vector>
#include <string>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <sstream>
#include <iomanip>

// Interstellar: Buffer
// For handling large amounts of data
namespace INTERSTELLAR_NAMESPACE::Buffer {
    class Buffer {
    public:
        Buffer() = default;

        Buffer(const Buffer& other)
            : data(other.data) {
        }

        Buffer(const Buffer* other)
            : data(other->data) {
        }

        Buffer(long long input) {
            data.clear();
            
            while (input != 0) {
                data.push_back(static_cast<std::byte>(input & 0xFF));
                input >>= 8;
            }

            if (data.empty()) {
                data.push_back(std::byte{ 0 });
            }
        }

        Buffer(const std::vector<std::byte>& input)
            : data(input) {

        }

        Buffer(const std::vector<bool>& bits) {
            size_t count = bits.size();
            for (size_t i = 0; i < count; i += 8) {
                std::byte b{ 0 };
                for (int j = 0; j < 8 && (i + j) < count; ++j) {
                    if (bits[i + j]) {
                        b |= static_cast<std::byte>(1 << j);
                    }
                }
                data.push_back(b);
            }
        }

        Buffer(const std::string& input) {
            data.clear();
            for (char c : input) {
                data.push_back(std::byte(c));
            }
        }

        long long index(long long n) const {
            size_t s = data.size();
            if (n >= static_cast<long long>(s)) return s - 1;
            if (n < 0) {
                n += s;
                if (n < 0) return 0;
            }
            return n;
        }

        // Basics

        size_t size() {
            return data.size();
        }

        std::vector<std::byte>::iterator iterator(long long n) {
            return data.begin() + index(n);
        }

        std::byte peek(long long n) const {
            return data.at(index(n));
        }

        void insert(long long n, std::byte d) {
            data.insert(iterator(n), d);
        }

        void insert(long long n, uint8_t d) {
            this->insert(n, std::byte(d));
        }

        void push(std::byte d) {
            data.insert(data.begin(), d);
        }

        void push(uint8_t d) {
            this->push(std::byte(d));
        }

        void push_back(std::byte d) {
            data.insert(data.end(), d);
        }

        void push_back(uint8_t d) {
            this->push_back(std::byte(d));
        }

        std::byte remove(long long n) {
            n = index(n);
            std::byte d = data[n];
            data.erase(data.begin() + n);
            return d;
        }

        std::byte shift() {
            if (data.empty()) return std::byte(0);
            std::byte d = data.front();
            data.erase(data.begin());
            return d;
        }

        std::byte pop() {
            if (data.empty()) return std::byte(0);
            std::byte d = data.back();
            data.pop_back();
            return d;
        }

        Buffer* substitute(long long begin, long long end = -1) {
            size_t s = data.size();
            begin = index(begin);
            end = (end == -1) ? s : index(end);
            if (end > s) end = s;

            if (begin > end) std::swap(begin, end);
            std::vector<std::byte> subbed(data.begin() + begin, data.begin() + end);
            return new Buffer(subbed);
        }

        // Arithmetic

        Buffer* arithmetic_add(const Buffer* other) { // CLA 8-bit infinite
            const auto& a = this->data;
            const auto& b = other->data;
            size_t max_size = ((a.size()) > (b.size())) ? (a.size()) : (b.size());

            std::vector<std::byte> result;
            result.reserve(max_size + 1);

            uint16_t carry = 0;

            for (size_t i = 0; i < max_size; ++i) {
                uint16_t ai = i < a.size() ? static_cast<uint8_t>(a[i]) : 0;
                uint16_t bi = i < b.size() ? static_cast<uint8_t>(b[i]) : 0;

                uint16_t sum = ai + bi + carry;
                result.push_back(std::byte(sum & 0xFF));
                carry = sum >> 8;
            }

            if (carry) {
                result.push_back(std::byte(carry));
            }

            return new Buffer(result);
        }
        Buffer* arithmetic_add(const long long other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->arithmetic_add(temp);
            delete temp;
            return res;
        }
        Buffer* arithmetic_add(const std::vector<std::byte> other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->arithmetic_add(temp);
            delete temp;
            return res;
        }
        Buffer* arithmetic_add(const std::string other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->arithmetic_add(temp);
            delete temp;
            return res;
        }


        Buffer* arithmetic_sub(const Buffer* other) { // CLA 8-bit (borrow) infinite
            const auto& a = this->data;
            const auto& b = other->data;
            size_t max_size = ((a.size()) > (b.size())) ? (a.size()) : (b.size());

            std::vector<std::byte> result;
            result.reserve(max_size);

            int16_t borrow = 0;

            for (size_t i = 0; i < max_size; ++i) {
                int16_t ai = i < a.size() ? static_cast<uint8_t>(a[i]) : 0;
                int16_t bi = i < b.size() ? static_cast<uint8_t>(b[i]) : 0;

                int16_t diff = ai - bi - borrow;
                if (diff < 0) {
                    diff += 256;
                    borrow = 1;
                }
                else {
                    borrow = 0;
                }

                result.push_back(std::byte(diff & 0xFF));
            }

            // trim leading zeros here, might need to remove this...
            while (result.size() > 1 && result.back() == std::byte(0)) {
                result.pop_back();
            }

            return new Buffer(result);
        }
        Buffer* arithmetic_sub(const long long other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->arithmetic_sub(temp);
            delete temp;
            return res;
        }
        Buffer* arithmetic_sub(const std::vector<std::byte> other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->arithmetic_sub(temp);
            delete temp;
            return res;
        }
        Buffer* arithmetic_sub(const std::string other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->arithmetic_sub(temp);
            delete temp;
            return res;
        }

        Buffer* arithmetic_mul(const Buffer* other) {
            size_t a_size = data.size();
            size_t b_size = other->data.size();
            std::vector<uint16_t> temp(a_size + b_size, 0);

            for (size_t i = 0; i < a_size; ++i) {
                uint16_t ai = static_cast<uint8_t>(data[i]);
                for (size_t j = 0; j < b_size; ++j) {
                    uint16_t bi = static_cast<uint8_t>(other->data[j]);
                    temp[i + j] += ai * bi;
                }
            }

            std::vector<std::byte> result;
            uint16_t carry = 0;
            for (size_t i = 0; i < temp.size(); ++i) {
                temp[i] += carry;
                result.push_back(std::byte(temp[i] & 0xFF));
                carry = temp[i] >> 8;
            }

            // trim leading zeros here, might need to remove this...
            while (result.size() > 1 && result.back() == std::byte(0)) {
                result.pop_back();
            }

            return new Buffer(result);
        }
        Buffer* arithmetic_mul(const long long other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->arithmetic_mul(temp);
            delete temp;
            return res;
        }
        Buffer* arithmetic_mul(const std::vector<std::byte> other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->arithmetic_mul(temp);
            delete temp;
            return res;
        }
        Buffer* arithmetic_mul(const std::string other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->arithmetic_mul(temp);
            delete temp;
            return res;
        }

        Buffer* arithmetic_div(const Buffer* other) {
            if (other->data.empty() || std::all_of(other->data.begin(), other->data.end(), [](std::byte b) { return b == std::byte(0); })) {
                return new Buffer(); // attempt to divide by zero, yea no.
            }

            std::vector<uint8_t> dividend(data.size());
            std::transform(data.begin(), data.end(), dividend.begin(),
                [](std::byte b) { return static_cast<uint8_t>(b); });

            std::vector<uint8_t> divisor(other->data.size());
            std::transform(other->data.begin(), other->data.end(), divisor.begin(),
                [](std::byte b) { return static_cast<uint8_t>(b); });

            std::vector<uint8_t> quotient;
            std::vector<uint8_t> remainder;

            for (uint8_t byte : dividend) {
                remainder.insert(remainder.begin(), byte);

                // remove leading zeroes in remainder
                while (!remainder.empty() && remainder.back() == 0) remainder.pop_back();

                uint8_t q = 0;
                while (remainder.size() >= divisor.size() &&
                    std::lexicographical_compare(divisor.begin(), divisor.end(), remainder.begin(), remainder.end()) == false) {
                    // subtract divisor from remainder
                    int borrow = 0;
                    for (size_t i = 0; i < divisor.size(); ++i) {
                        size_t ri = remainder.size() - divisor.size() + i;
                        int diff = remainder[ri] - divisor[i] - borrow;
                        if (diff < 0) {
                            diff += 256;
                            borrow = 1;
                        }
                        else {
                            borrow = 0;
                        }
                        remainder[ri] = diff;
                    }

                    // remove any leading zeroes
                    while (!remainder.empty() && remainder.back() == 0) remainder.pop_back();

                    ++q;
                }

                quotient.insert(quotient.begin(), q);
            }

            // remove leading zeroes
            while (quotient.size() > 1 && quotient.back() == 0) {
                quotient.pop_back();
            }

            std::vector<std::byte> q_bytes(quotient.size());
            std::transform(quotient.begin(), quotient.end(), q_bytes.begin(),
                [](uint8_t b) { return std::byte(b); });

            return new Buffer(q_bytes);
        }
        Buffer* arithmetic_div(const long long other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->arithmetic_div(temp);
            delete temp;
            return res;
        }
        Buffer* arithmetic_div(const std::vector<std::byte> other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->arithmetic_div(temp);
            delete temp;
            return res;
        }
        Buffer* arithmetic_div(const std::string other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->arithmetic_div(temp);
            delete temp;
            return res;
        }

        Buffer* arithmetic_pow(int amount) {
            if (amount < 0) return new Buffer(); // can't handle negative exponents really... don't have a fp unit yet.
            Buffer* result = new Buffer(1);
            for (int i = 0; i < amount; ++i) {
                Buffer* tmp = result->arithmetic_mul(this);
                delete result;
                result = tmp;
            }
            return result;
        }

        // Bitwise
        Buffer* bitwise_not() {
            std::vector<std::byte> result;
            for (std::byte b : data) {
                result.push_back(~b);
            }
            return new Buffer(result);
        }

        Buffer* bitwise_or(const Buffer* other) {
            std::vector<std::byte> result;
            size_t max_size = ((data.size()) > (other->data.size())) ? (data.size()) : (other->data.size());
            for (size_t i = 0; i < max_size; ++i) {
                std::byte a = (i < data.size()) ? data[i] : std::byte(0);
                std::byte b = (i < other->data.size()) ? other->data[i] : std::byte(0);
                result.push_back(a | b);
            }
            return new Buffer(result);
        }
        Buffer* bitwise_or(const long long other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->bitwise_or(temp);
            delete temp;
            return res;
        }
        Buffer* bitwise_or(const std::vector<std::byte> other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->bitwise_or(temp);
            delete temp;
            return res;
        }
        Buffer* bitwise_or(const std::string other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->bitwise_or(temp);
            delete temp;
            return res;
        }

        Buffer* bitwise_and(const Buffer* other) {
            std::vector<std::byte> result;
            size_t max_size = ((data.size()) > (other->data.size())) ? (data.size()) : (other->data.size());
            for (size_t i = 0; i < max_size; ++i) {
                std::byte a = (i < data.size()) ? data[i] : std::byte(0);
                std::byte b = (i < other->data.size()) ? other->data[i] : std::byte(0);
                result.push_back(a & b);
            }
            return new Buffer(result);
        }
        Buffer* bitwise_and(const long long other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->bitwise_and(temp);
            delete temp;
            return res;
        }
        Buffer* bitwise_and(const std::vector<std::byte> other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->bitwise_and(temp);
            delete temp;
            return res;
        }
        Buffer* bitwise_and(const std::string other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->bitwise_and(temp);
            delete temp;
            return res;
        }

        Buffer* bitwise_xor(const Buffer* other) {
            std::vector<std::byte> result;
            size_t max_size = ((data.size()) > (other->data.size())) ? (data.size()) : (other->data.size());
            for (size_t i = 0; i < max_size; ++i) {
                std::byte a = (i < data.size()) ? data[i] : std::byte(0);
                std::byte b = (i < other->data.size()) ? other->data[i] : std::byte(0);
                result.push_back(a ^ b);
            }
            return new Buffer(result);
        }
        Buffer* bitwise_xor(const long long other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->bitwise_xor(temp);
            delete temp;
            return res;
        }
        Buffer* bitwise_xor(const std::vector<std::byte> other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->bitwise_xor(temp);
            delete temp;
            return res;
        }
        Buffer* bitwise_xor(const std::string other) {
            Buffer* temp = new Buffer(other);
            Buffer* res = this->bitwise_xor(temp);
            delete temp;
            return res;
        }

        Buffer* bitwise_lshift(unsigned int amount) {
            if (amount < 0) return bitwise_rshift(-amount);
            size_t total_bits = data.size() * 8;
            if (amount >= static_cast<int>(total_bits)) {
                return new Buffer(std::vector<std::byte>(data.size(), std::byte(0)));
            }
            std::vector<std::byte> result(data.size(), std::byte(0));
            for (size_t i = 0; i < total_bits - amount; ++i) {
                size_t from_index = i + amount;
                size_t from_byte = from_index / 8;
                size_t from_bit = from_index % 8;
                size_t to_byte = i / 8;
                size_t to_bit = i % 8;
                if (static_cast<unsigned char>(data[from_byte]) & (1 << from_bit)) {
                    result[to_byte] |= std::byte(1 << to_bit);
                }
            }
            return new Buffer(result);
        }

        Buffer* bitwise_rshift(unsigned int amount) {
            if (amount < 0) return bitwise_lshift(-amount);
            size_t total_bits = data.size() * 8;
            if (amount >= static_cast<int>(total_bits)) {
                return new Buffer(std::vector<std::byte>(data.size(), std::byte(0)));
            }
            std::vector<std::byte> result(data.size(), std::byte(0));
            for (size_t i = amount; i < total_bits; ++i) {
                size_t from_index = i - amount;
                size_t from_byte = from_index / 8;
                size_t from_bit = from_index % 8;
                size_t to_byte = i / 8;
                size_t to_bit = i % 8;
                if (static_cast<unsigned char>(data[from_byte]) & (1 << from_bit)) {
                    result[to_byte] |= std::byte(1 << to_bit);
                }
            }
            return new Buffer(result);
        }

        Buffer* bitwise_rol(unsigned int amount) {
            size_t total_bits = data.size() * 8;
            amount = amount % total_bits;
            if (amount == 0) return new Buffer(data);
            std::vector<std::byte> result(data.size(), std::byte(0));
            for (size_t i = 0; i < total_bits; ++i) {
                size_t from_index = (i + amount) % total_bits;
                size_t from_byte = from_index / 8;
                size_t from_bit = from_index % 8;
                size_t to_byte = i / 8;
                size_t to_bit = i % 8;
                if (static_cast<unsigned char>(data[from_byte]) & (1 << from_bit)) {
                    result[to_byte] |= std::byte(1 << to_bit);
                }
            }
            return new Buffer(result);
        }

        Buffer* bitwise_ror(unsigned int amount) {
            size_t total_bits = data.size() * 8;
            amount = amount % total_bits;
            if (amount == 0) return new Buffer(data);
            std::vector<std::byte> result(data.size(), std::byte(0));
            for (size_t i = 0; i < total_bits; ++i) {
                size_t from_index = (i + total_bits - amount) % total_bits;
                size_t from_byte = from_index / 8;
                size_t from_bit = from_index % 8;
                size_t to_byte = i / 8;
                size_t to_bit = i % 8;
                if (static_cast<unsigned char>(data[from_byte]) & (1 << from_bit)) {
                    result[to_byte] |= std::byte(1 << to_bit);
                }
            }
            return new Buffer(result);
        }

        // Consumers

        Buffer* read_bytes(size_t n) {
            size_t s = data.size();
            Buffer* b = this->substitute(0, n);
            if (n > s) n = s;
            data.erase(data.begin(), data.begin() + n);
            return b;
        }

        uint8_t read_uint8() { return uint8_t(shift()); }
        int8_t  read_int8() { return int8_t(read_uint8()); }

        uint16_t read_uint16() {
            uint8_t l = read_uint8();
            uint8_t h = read_uint8();
            return (uint16_t(h) << 8) | l;
        }

        int16_t read_int16() {
            return int16_t(read_uint16());
        }

        uint32_t read_uint32() {
            uint16_t l = read_uint16();
            uint16_t h = read_uint16();
            return (uint32_t(h) << 16) | l;
        }

        int32_t read_int32() {
            return int32_t(read_uint32());
        }

        uint64_t read_uint64() {
            uint32_t l = read_uint32();
            uint32_t h = read_uint32();
            return (uint64_t(h) << 32) | l;
        }

        int64_t read_int64() {
            return int64_t(read_uint64());
        }

        uint64_t read_uleb128() {
            uint64_t result = 0;
            uint64_t factor = 1;

            while (true) {
                uint8_t byte = this->read_uint8();

                if (byte & 0x80) {
                    result += (byte & 0x7F) * factor;
                    factor *= 128;
                }
                else {
                    result += byte * factor;
                    break;
                }
            }

            return result;
        }

        void write_uint8(uint8_t v) { push_back(std::byte(v)); }
        void write_int8(int8_t v) { write_uint8(uint8_t(v)); }

        void write_uint16(uint16_t v) {
            write_uint8(v & 0xFF);
            write_uint8((v >> 8) & 0xFF);
        }

        void write_int16(int16_t v) {
            write_uint16(uint16_t(v));
        }

        void write_uint32(uint32_t v) {
            write_uint16(v & 0xFFFF);
            write_uint16((v >> 16) & 0xFFFF);
        }

        void write_int32(int32_t v) {
            write_uint32(uint32_t(v));
        }

        void write_uint64(uint64_t v) {
            write_uint32(v & 0xFFFFFFFF);
            write_uint32((v >> 32) & 0xFFFFFFFF);
        }

        void write_int64(int64_t v) {
            write_uint64(uint64_t(v));
        }

        void write_uleb128(uint64_t n) {
            if (n >= (1ULL << 32)) n = 0xFFFFFFFF;

            while (n >= 0x80) {
                this->write_uint8(static_cast<uint8_t>((n & 0x7F) | 0x80));
                n /= 128;
            }

            this->write_uint8(static_cast<uint8_t>(n));
        }

        std::vector<std::byte> to_vector() const {
            return data;
        }

        std::string to_string() const {
            std::string o(data.size(), '\0');
            for (size_t i = 0; i < data.size(); ++i) {
                o[i] = static_cast<char>(data[i]);
            }
            return o;
        }

        std::string to_hex() const {
            std::stringstream ss;
            for (auto it = data.begin(); it != data.end(); ++it) {
                uint8_t byte = static_cast<uint8_t>(*it);
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
            }
            if (ss.str().empty()) return "00";
            return ss.str();
        }

        long long to_integer() const {
            long long result = 0;
            size_t len = ((sizeof(long long)) < (data.size())) ? (sizeof(long long)) : (data.size());
            for (size_t i = 0; i < len; ++i) {
                result |= static_cast<long long>(std::to_integer<unsigned char>(data[i])) << (8 * i);
            }
            return result;
        }

        std::vector<bool> to_binary() const {
            std::vector<bool> o;

            for (auto& byte : data) {
                for (int i = 0; i < 8; ++i) {
                    bool bit = static_cast<bool>((byte >> i) & std::byte{ 1 });
                    o.push_back(bit);
                }
            }

            return o;
        }

        Buffer& operator=(const Buffer& other) {
            if (this != &other) {
                data = other.data;
            }
            return *this;
        }

        Buffer& operator+(const Buffer& other) {
            Buffer* clone = new Buffer(this);
            clone->arithmetic_add(&other);
            return *clone;
        }

        Buffer& operator-(const Buffer& other) {
            Buffer* clone = new Buffer(this);
            clone->arithmetic_sub(&other);
            return *clone;
        }

        Buffer& operator*(const Buffer& other) {
            Buffer* clone = new Buffer(this);
            clone->arithmetic_mul(&other);
            return *clone;
        }

        Buffer& operator/(const Buffer& other) {
            Buffer* clone = new Buffer(this);
            clone->arithmetic_div(&other);
            return *clone;
        }

        Buffer& operator^(const Buffer& other) {
            Buffer* clone = new Buffer(this);
            clone->arithmetic_pow(other.to_integer());
            return *clone;
        }
    private:
        std::vector<std::byte> data;
    };

    extern void push_buffer(API::lua_State* L, Buffer* data);
    extern void push_buffer(API::lua_State* L, long long data);
    extern void push_buffer(API::lua_State* L, std::vector<std::byte> data);
    extern void push_buffer(API::lua_State* L, std::vector<bool> data);
    extern void push_buffer(API::lua_State* L, std::string data);

    extern void push(API::lua_State* L, UMODULE hndle);
    extern void api();
}