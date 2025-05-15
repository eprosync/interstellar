#include "interstellar_buffer.hpp"

// TODO: some of these parts are very repetitive, gotta use #define macros at some point

namespace INTERSTELLAR_NAMESPACE::Buffer {
    using namespace API;

    int buffer_new(lua_State* L)
    {
        if (lua::isnumber(L, 1)) {
            push_buffer(L, lua::tonumber(L, 1));
            return 1;
        } else if (lua::isstring(L, 1)) {
            push_buffer(L, lua::tocstring(L, 1));
            return 1;
        }
        else if (Class::is(L, 1, "buffer")) {
            push_buffer(L, (Buffer*)Class::to(L, 1));
            return 1;
        }

        luaL::argerror(L, 1, "expected string, number or buffer");

        return 0;
    }

    // Basics

    int buffer_size(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        lua::pushnumber(L, data->size());
        return 1;
    }

    int buffer_peek(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        lua::pushnumber(L, static_cast<uint8_t>(data->peek(luaL::checknumber(L, 2))));
        return 1;
    }

    int buffer_insert(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        uint64_t idx = luaL::checknumber(L, 2);

        for (int i = 3; i <= lua::gettop(L); i++) {
            uint8_t v = luaL::checknumber(L, i);
            data->insert(idx, v);
        }

        return 0;
    }

    int buffer_push(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");

        for (int i = lua::gettop(L); i >= 2; i--) {
            uint8_t v = luaL::checknumber(L, i);
            data->push(v);
        }

        return 0;
    }

    int buffer_push_back(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");

        size_t size = lua::gettop(L);
        for (int i = 2; i <= size; i++) {
            uint8_t v = luaL::checknumber(L, i);
            data->push_back(v);
        }

        return 0;
    }

    int buffer_remove(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        lua::pushnumber(L, static_cast<uint8_t>(data->remove(luaL::checknumber(L, 2))));
        return 1;
    }

    int buffer_shift(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        lua::pushnumber(L, static_cast<uint8_t>(data->shift()));
        return 1;
    }

    int buffer_pop(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        lua::pushnumber(L, static_cast<uint8_t>(data->pop()));
        return 1;
    }

    int buffer_substitute(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        long long begin = luaL::checknumber(L, 2);
        long long end = -1;
        if (lua::isnumber(L, 3)) {
            end = lua::tonumber(L, 3);
        }

        Buffer* new_data = data->substitute(luaL::checknumber(L, 2), end);
        push_buffer(L, new_data);
        return 1;
    }

    // Arithmetic

    int buffer_arithmetic_add(lua_State* L)
    {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");

        if (lua::isnumber(L, 2)) {
            push_buffer(L, data->arithmetic_add(lua::tonumber(L, 2)));
            return 1;
        }
        else if (lua::isstring(L, 2)) {
            push_buffer(L, data->arithmetic_add(lua::tocstring(L, 2)));
            return 1;
        }
        else if (Class::is(L, 2, "buffer")) {
            push_buffer(L, data->arithmetic_add((Buffer*)Class::to(L, 2)));
            return 1;
        }

        luaL::argerror(L, 2, "expected string, number or buffer");

        return 0;
    }

    int buffer_arithmetic_sub(lua_State* L)
    {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");

        if (lua::isnumber(L, 2)) {
            push_buffer(L, data->arithmetic_sub(lua::tonumber(L, 2)));
            return 1;
        }
        else if (lua::isstring(L, 2)) {
            push_buffer(L, data->arithmetic_sub(lua::tocstring(L, 2)));
            return 1;
        }
        else if (Class::is(L, 2, "buffer")) {
            push_buffer(L, data->arithmetic_sub((Buffer*)Class::to(L, 2)));
            return 1;
        }

        luaL::argerror(L, 2, "expected string, number or buffer");

        return 0;
    }

    int buffer_arithmetic_mul(lua_State* L)
    {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");

        if (lua::isnumber(L, 2)) {
            push_buffer(L, data->arithmetic_mul(lua::tonumber(L, 2)));
            return 1;
        }
        else if (lua::isstring(L, 2)) {
            push_buffer(L, data->arithmetic_mul(lua::tocstring(L, 2)));
            return 1;
        }
        else if (Class::is(L, 2, "buffer")) {
            push_buffer(L, data->arithmetic_mul((Buffer*)Class::to(L, 2)));
            return 1;
        }

        luaL::argerror(L, 2, "expected string, number or buffer");

        return 0;
    }

    int buffer_arithmetic_div(lua_State* L)
    {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");

        if (lua::isnumber(L, 2)) {
            push_buffer(L, data->arithmetic_div(lua::tonumber(L, 2)));
            return 1;
        }
        else if (lua::isstring(L, 2)) {
            push_buffer(L, data->arithmetic_div(lua::tocstring(L, 2)));
            return 1;
        }
        else if (Class::is(L, 2, "buffer")) {
            push_buffer(L, data->arithmetic_div((Buffer*)Class::to(L, 2)));
            return 1;
        }

        luaL::argerror(L, 2, "expected string, number or buffer");

        return 0;
    }

    int buffer_arithmetic_pow(lua_State* L)
    {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");

        if (lua::isnumber(L, 2)) {
            push_buffer(L, data->arithmetic_pow(lua::tonumber(L, 2)));
        }
        else if (lua::isstring(L, 2)) {
            Buffer* temp = new Buffer(lua::tocstring(L, 2));
            push_buffer(L, data->arithmetic_pow(temp->to_integer()));
            delete temp;
            return 1;
        }
        else if (Class::is(L, 2, "buffer")) {
            Buffer* temp = (Buffer*)Class::to(L, 2);
            push_buffer(L, data->arithmetic_pow(temp->to_integer()));
            return 1;
        }

        luaL::argerror(L, 2, "expected string, number or buffer");

        return 0;
    }

    // Bitwise

    int buffer_bitwise_not(lua_State* L)
    {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        push_buffer(L, data->bitwise_not());
        return 1;
    }

    int buffer_bitwise_or(lua_State* L)
    {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");

        if (lua::isnumber(L, 2)) {
            push_buffer(L, data->bitwise_or(lua::tonumber(L, 2)));
            return 1;
        }
        else if (lua::isstring(L, 2)) {
            push_buffer(L, data->bitwise_or(lua::tocstring(L, 2)));
            return 1;
        }
        else if (Class::is(L, 2, "buffer")) {
            push_buffer(L, data->bitwise_or((Buffer*)Class::to(L, 2)));
            return 1;
        }

        luaL::argerror(L, 2, "expected string, number or buffer");

        return 0;
    }

    int buffer_bitwise_and(lua_State* L)
    {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");

        if (lua::isnumber(L, 2)) {
            push_buffer(L, data->bitwise_and(lua::tonumber(L, 2)));
            return 1;
        }
        else if (lua::isstring(L, 2)) {
            push_buffer(L, data->bitwise_and(lua::tocstring(L, 2)));
            return 1;
        }
        else if (Class::is(L, 2, "buffer")) {
            push_buffer(L, data->bitwise_and((Buffer*)Class::to(L, 2)));
            return 1;
        }

        luaL::argerror(L, 2, "expected string, number or buffer");

        return 0;
    }

    int buffer_bitwise_xor(lua_State* L)
    {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");

        if (lua::isnumber(L, 2)) {
            push_buffer(L, data->bitwise_xor(lua::tonumber(L, 2)));
            return 1;
        }
        else if (lua::isstring(L, 2)) {
            push_buffer(L, data->bitwise_xor(lua::tocstring(L, 2)));
            return 1;
        }
        else if (Class::is(L, 2, "buffer")) {
            push_buffer(L, data->bitwise_xor((Buffer*)Class::to(L, 2)));
            return 1;
        }

        luaL::argerror(L, 2, "expected string, number or buffer");

        return 0;
    }

    int buffer_bitwise_lshift(lua_State* L)
    {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");

        if (lua::isnumber(L, 2)) {
            push_buffer(L, data->bitwise_lshift(lua::tonumber(L, 2)));
        }
        else if (lua::isstring(L, 2)) {
            Buffer* temp = new Buffer(lua::tocstring(L, 2));
            push_buffer(L, data->bitwise_lshift(temp->to_integer()));
            delete temp;
            return 1;
        }
        else if (Class::is(L, 2, "buffer")) {
            Buffer* temp = (Buffer*)Class::to(L, 2);
            push_buffer(L, data->bitwise_lshift(temp->to_integer()));
            return 1;
        }

        luaL::argerror(L, 2, "expected string, number or buffer");

        return 0;
    }

    int buffer_bitwise_rshift(lua_State* L)
    {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");

        if (lua::isnumber(L, 2)) {
            push_buffer(L, data->bitwise_rshift(lua::tonumber(L, 2)));
        }
        else if (lua::isstring(L, 2)) {
            Buffer* temp = new Buffer(lua::tocstring(L, 2));
            push_buffer(L, data->bitwise_rshift(temp->to_integer()));
            delete temp;
            return 1;
        }
        else if (Class::is(L, 2, "buffer")) {
            Buffer* temp = (Buffer*)Class::to(L, 2);
            push_buffer(L, data->bitwise_rshift(temp->to_integer()));
            return 1;
        }

        luaL::argerror(L, 2, "expected string, number or buffer");

        return 0;
    }

    int buffer_bitwise_rol(lua_State* L)
    {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");

        if (lua::isnumber(L, 2)) {
            push_buffer(L, data->bitwise_rol(lua::tonumber(L, 2)));
        }
        else if (lua::isstring(L, 2)) {
            Buffer* temp = new Buffer(lua::tocstring(L, 2));
            push_buffer(L, data->bitwise_rol(temp->to_integer()));
            delete temp;
            return 1;
        }
        else if (Class::is(L, 2, "buffer")) {
            Buffer* temp = (Buffer*)Class::to(L, 2);
            push_buffer(L, data->bitwise_rol(temp->to_integer()));
            return 1;
        }

        luaL::argerror(L, 2, "expected string, number or buffer");

        return 0;
    }

    int buffer_bitwise_ror(lua_State* L)
    {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");

        if (lua::isnumber(L, 2)) {
            push_buffer(L, data->bitwise_ror(lua::tonumber(L, 2)));
        }
        else if (lua::isstring(L, 2)) {
            Buffer* temp = new Buffer(lua::tocstring(L, 2));
            push_buffer(L, data->bitwise_ror(temp->to_integer()));
            delete temp;
            return 1;
        }
        else if (Class::is(L, 2, "buffer")) {
            Buffer* temp = (Buffer*)Class::to(L, 2);
            push_buffer(L, data->bitwise_ror(temp->to_integer()));
            return 1;
        }

        luaL::argerror(L, 2, "expected string, number or buffer");

        return 0;
    }

    // Consumers

    int buffer_consumers_bytes(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        push_buffer(L, data->read_bytes(luaL::checknumber(L, 2)));
        return 1;
    }

    int buffer_consumers_uint8(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        if (lua::isnumber(L, 2)) {
            data->write_uint8(luaL::checknumber(L, 2));
            return 0;
        }
        lua::pushnumber(L, static_cast<uint8_t>(data->read_uint8()));
        return 1;
    }

    int buffer_consumers_int8(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        if (lua::isnumber(L, 2)) {
            data->write_int8(luaL::checknumber(L, 2));
            return 0;
        }
        lua::pushnumber(L, data->read_int8());
        return 1;
    }

    int buffer_consumers_uint16(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        if (lua::isnumber(L, 2)) {
            data->write_uint16(luaL::checknumber(L, 2));
            return 0;
        }
        lua::pushnumber(L, data->read_uint16());
        return 1;
    }

    int buffer_consumers_int16(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        if (lua::isnumber(L, 2)) {
            data->write_int16(luaL::checknumber(L, 2));
            return 0;
        }
        lua::pushnumber(L, data->read_int16());
        return 1;
    }

    int buffer_consumers_uint32(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        if (lua::isnumber(L, 2)) {
            data->write_uint32(luaL::checknumber(L, 2));
            return 0;
        }
        lua::pushnumber(L, data->read_uint32());
        return 1;
    }

    int buffer_consumers_int32(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        if (lua::isnumber(L, 2)) {
            data->write_int32(luaL::checknumber(L, 2));
            return 0;
        }
        lua::pushnumber(L, data->read_int32());
        return 1;
    }

    int buffer_consumers_uint64(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        if (lua::isnumber(L, 2)) {
            data->write_uint64(luaL::checknumber(L, 2));
            return 0;
        }
        lua::pushnumber(L, data->read_uint32());
        return 1;
    }

    int buffer_consumers_int64(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        if (lua::isnumber(L, 2)) {
            data->write_int64(luaL::checknumber(L, 2));
            return 0;
        }
        lua::pushnumber(L, data->read_int64());
        return 1;
    }

    int buffer_consumers_uleb128(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        if (lua::isnumber(L, 2)) {
            data->write_uleb128(luaL::checknumber(L, 2));
            return 0;
        }
        lua::pushnumber(L, data->read_uleb128());
        return 1;
    }

    // Conversions

    int buffer_tonumber(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        lua::pushnumber(L, data->to_integer());
        return 1;
    }

    int buffer_tostring(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        lua::pushcstring(L, data->to_string());
        return 1;
    }

    int buffer_tohex(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        lua::pushcstring(L, data->to_hex());
        return 1;
    }

    int buffer_totable(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        auto vec = data->to_vector();

        lua::newtable(L); // TODO: use regular table creation with pre-alloc
        int index = 0;
        for (auto& byte : vec) {
            lua::pushnumber(L, ++index);
            lua::pushnumber(L, static_cast<uint8_t>(byte));
            lua::settable(L, -3);
        }

        return 1;
    }

    int buffer_tobinary(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        auto vec = data->to_binary();

        lua::newtable(L); // TODO: use regular table creation with pre-alloc
        int index = 0;
        for (auto bit : vec) {
            lua::pushnumber(L, ++index);
            lua::pushnumber(L, bit); // TODO: should this be pushboolean instead?
            lua::settable(L, -3);
        }

        return 1;
    }

    // Metatable

    int buffer__gc(lua_State* L) {
        if (Class::is(L, 1, "buffer")) {
            Buffer* data = (Buffer*)Class::to(L, 1);
            delete data;
        }
        return 0;
    }

    int buffer__tostring(lua_State* L) {
        Buffer* data = (Buffer*)Class::check(L, 1, "buffer");
        lua::pushcstring(L, "buffer: " + std::to_string(data->size()));
        return 1;
    }

    void push_buffer_internal(lua_State* L, Buffer* data)
    {
        if (!Class::existsbyname(L, "buffer")) {
            Class::create(L, "buffer");

            lua::newtable(L);

            lua::pushcfunction(L, buffer_new);
            lua::setfield(L, -2, "clone");

            // Basics

            lua::pushcfunction(L, buffer_size);
            lua::setfield(L, -2, "size");

            lua::pushcfunction(L, buffer_peek);
            lua::setfield(L, -2, "peek");

            lua::pushcfunction(L, buffer_insert);
            lua::setfield(L, -2, "insert");

            lua::pushcfunction(L, buffer_push);
            lua::setfield(L, -2, "push");

            lua::pushcfunction(L, buffer_push_back);
            lua::setfield(L, -2, "push_back");

            lua::pushcfunction(L, buffer_remove);
            lua::setfield(L, -2, "remove");

            lua::pushcfunction(L, buffer_shift);
            lua::setfield(L, -2, "shift");

            lua::pushcfunction(L, buffer_pop);
            lua::setfield(L, -2, "pop");

            lua::pushcfunction(L, buffer_substitute);
            lua::setfield(L, -2, "substitute");

            // Arithmetic

            lua::pushcfunction(L, buffer_arithmetic_add);
            lua::setfield(L, -2, "add");

            lua::pushcfunction(L, buffer_arithmetic_sub);
            lua::setfield(L, -2, "sub");

            lua::pushcfunction(L, buffer_arithmetic_mul);
            lua::setfield(L, -2, "mul");

            lua::pushcfunction(L, buffer_arithmetic_div);
            lua::setfield(L, -2, "div");

            lua::pushcfunction(L, buffer_arithmetic_pow);
            lua::setfield(L, -2, "pow");

            // Bitwise
            
            lua::pushcfunction(L, buffer_bitwise_not);
            lua::setfield(L, -2, "bnot");

            lua::pushcfunction(L, buffer_bitwise_or);
            lua::setfield(L, -2, "bor");

            lua::pushcfunction(L, buffer_bitwise_and);
            lua::setfield(L, -2, "band");

            lua::pushcfunction(L, buffer_bitwise_xor);
            lua::setfield(L, -2, "bxor");

            lua::pushcfunction(L, buffer_bitwise_lshift);
            lua::setfield(L, -2, "lshift");

            lua::pushcfunction(L, buffer_bitwise_rshift);
            lua::setfield(L, -2, "rshift");

            lua::pushcfunction(L, buffer_bitwise_rol);
            lua::setfield(L, -2, "rol");

            lua::pushcfunction(L, buffer_bitwise_ror);
            lua::setfield(L, -2, "ror");

            // Consumers

            lua::pushcfunction(L, buffer_consumers_bytes);
            lua::setfield(L, -2, "bytes");

            lua::pushcfunction(L, buffer_consumers_uint8);
            lua::setfield(L, -2, "uint8");

            lua::pushcfunction(L, buffer_consumers_int8);
            lua::setfield(L, -2, "int8");

            lua::pushcfunction(L, buffer_consumers_uint16);
            lua::setfield(L, -2, "uint16");

            lua::pushcfunction(L, buffer_consumers_int16);
            lua::setfield(L, -2, "int16");

            lua::pushcfunction(L, buffer_consumers_uint32);
            lua::setfield(L, -2, "uint32");

            lua::pushcfunction(L, buffer_consumers_int32);
            lua::setfield(L, -2, "int32");

            lua::pushcfunction(L, buffer_consumers_uint64);
            lua::setfield(L, -2, "uint64");

            lua::pushcfunction(L, buffer_consumers_int64);
            lua::setfield(L, -2, "int64");

            lua::pushcfunction(L, buffer_consumers_uleb128);
            lua::setfield(L, -2, "uint64");

            // Conversions

            lua::pushcfunction(L, buffer_tonumber);
            lua::setfield(L, -2, "tonumber");

            lua::pushcfunction(L, buffer_tostring);
            lua::setfield(L, -2, "tostring");

            lua::pushcfunction(L, buffer_tohex);
            lua::setfield(L, -2, "tohex");

            lua::pushcfunction(L, buffer_totable);
            lua::setfield(L, -2, "totable");

            lua::pushcfunction(L, buffer_tobinary);
            lua::setfield(L, -2, "tobinary");

            lua::setfield(L, -2, "__index");

            // TODO: Add basic operator overrides to metatable

            lua::pushcfunction(L, buffer__gc);
            lua::setfield(L, -2, "__gc");

            lua::pushcfunction(L, buffer__tostring);
            lua::setfield(L, -2, "__tostring");

            lua::pop(L);
        }

        Class::spawn(L, new Buffer(data), "buffer");
    }

    // TODO: Use generics later on for this..?
    void push_buffer(lua_State* L, Buffer* data)
    {
        push_buffer_internal(L, data);
    }

    void push_buffer(lua_State* L, long long data)
    {
        Buffer* temp = new Buffer(data);
        push_buffer_internal(L, temp);
        delete temp;
    }

    void push_buffer(lua_State* L, std::vector<std::byte> data)
    {
        Buffer* temp = new Buffer(data);
        push_buffer_internal(L, temp);
        delete temp;
    }

    void push_buffer(lua_State* L, std::vector<bool> data)
    {
        Buffer* temp = new Buffer(data);
        push_buffer_internal(L, temp);
        delete temp;
    }

    void push_buffer(lua_State* L, std::string data)
    {
        Buffer* temp = new Buffer(data);
        push_buffer_internal(L, temp);
        delete temp;
    }

    int buffer_fromnumber(lua_State* L)
    {
        push_buffer(L, luaL::checknumber(L, 1));
        return 1;
    }

    int buffer_fromstring(lua_State* L)
    {
        push_buffer(L, luaL::checkcstring(L, 1));
        return 1;
    }

    int buffer_fromhex(lua_State* L)
    {
        std::string hex_string = luaL::checkcstring(L, 1);

        if (hex_string.size() % 2 != 0) {
            return 0;
        }

        std::vector<std::byte> bytes;
        for (size_t i = 0; i < hex_string.size(); i += 2) {
            std::byte byte = std::byte(
                (std::stoi(hex_string.substr(i, 1), nullptr, 16) << 4) |
                std::stoi(hex_string.substr(i + 1, 1), nullptr, 16));
            bytes.push_back(byte);
        }

        push_buffer(L, bytes);

        return 1;
    }

    int buffer_frombytes(lua_State* L)
    {
        luaL::checktable(L, 1);

        std::vector<std::byte> bytes;

        size_t size = lua::objlen(L, 1);

        for (size_t i = 1; i <= size; i++) {
            lua::pushnumber(L, i);
            lua::gettable(L, 1);

            if (lua::isnumber(L, -1)) {
                bytes.push_back(std::byte(static_cast<uint8_t>(lua::tonumber(L, -1))));
                lua::pop(L);
                continue;
            }

            lua::pop(L);
            break;
        }

        push_buffer(L, bytes);

        return 1;
    }

    int buffer_frombinary(lua_State* L)
    {
        luaL::checktable(L, 1);

        std::vector<bool> binary;

        size_t size = lua::objlen(L, 1);

        for (size_t i = 1; i <= size; i++) {
            lua::pushnumber(L, i);
            lua::gettable(L, 1);

            if (lua::isnumber(L, -1)) {
                binary.push_back(lua::tonumber(L, -1) > 0);
                lua::pop(L);
                continue;
            }

            if (lua::isboolean(L, -1)) {
                binary.push_back(lua::toboolean(L, -1));
                lua::pop(L);
                continue;
            }

            lua::pop(L);
            break;
        }

        push_buffer(L, binary);

        return 1;
    }

    void push(lua_State* L, UMODULE hndle)
    {
        lua::newtable(L);

        // TODO: we should have C++'s sizeof for different datatypes as static enums

        lua::pushcfunction(L, buffer_new);
        lua::setfield(L, -2, "new");

        lua::pushcfunction(L, buffer_fromhex);
        lua::setfield(L, -2, "hex");

        lua::pushcfunction(L, buffer_fromstring);
        lua::setfield(L, -2, "string");

        lua::pushcfunction(L, buffer_fromnumber);
        lua::setfield(L, -2, "number");

        lua::pushcfunction(L, buffer_frombytes);
        lua::setfield(L, -2, "bytes");

        lua::pushcfunction(L, buffer_frombinary);
        lua::setfield(L, -2, "binary");
    }

    void api() {
        Reflection::add("buffer", push);
    }
}