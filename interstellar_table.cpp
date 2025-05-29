#include <string.h>
#include "interstellar_table.hpp"
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <sstream>
#include <optional>
#include <algorithm>
#include <unordered_set>

namespace INTERSTELLAR_NAMESPACE::Table {
    using namespace API;

    #define noderef(r)	(mref((r), Engine::Node))
    #define nextnode(n)	(mref((n)->next, Engine::Node))

    bool is_lua_array(lua_State* L, int index, size_t& size) {
        if (!lua::istable(L, index)) return false;
        using namespace Engine;

        lua::pushvalue(L, index);
        lua::pushnumber(L, 0);
        lua::gettable(L, -2);
        
        if (!lua::isnil(L, -1)) {
            lua::pop(L, 2);
            return false;
        }

        lua::pop(L, 2);

        TValue* tv = lua::toraw(L, index);
        GCtab* t = (GCtab*)gcV(tv);

        bool gap = false;
        size = 0;
        for (uint32_t i = 1; i < t->asize; ++i) {
            if (tvisnil(&tvref(t->array)[i])) {
                gap = true;
            }
            else if (gap) {
                return false;
            } else {
                size++;
            }
        }

        for (uint32_t i = 0; i <= t->hmask; i++) {
            Node* n = &noderef(t->node)[i];
            if (!tvisnil(&n->val)) {
                return false;
            }
        }

        return true;
    }

    rapidjson::Value lua_to_json(lua_State* L, int index, rapidjson::Document::AllocatorType& allocator, std::unordered_set<Engine::GCobj*> cyclic = {}) {
        using namespace Engine;

        TValue* tv = lua::toraw(L, index);
        GCobj* gcobj = gcV(tv);

        if (cyclic.find(gcobj) == cyclic.end()) {
            cyclic.emplace(gcobj);
        }
        else {
            return rapidjson::Value("[cyclic]", allocator);
        }

        if (index < 0) index = lua::gettop(L) + index + 1;

        size_t size;
        if (is_lua_array(L, index, size)) {
            rapidjson::Value array(rapidjson::kArrayType);

            for (size_t i = 0; i < size; i++) {
                lua::pushnumber(L, i + 1);
                lua::gettable(L, -2);
                int value_type = lua::gettype(L, -1);

                if (value_type == datatype::nil) {
                    lua::pop(L);
                    continue;
                }

                rapidjson::Value value;
                switch (value_type) {
                case datatype::boolean:  value.SetBool(lua::toboolean(L, -1)); break;
                case datatype::number:
                    if (lua::isinteger(L, -1)) {
                        value.SetInt64(lua::tointeger(L, -1));
                    }
                    else {
                        value.SetDouble(lua::tonumber(L, -1));
                    }
                    break;
                case datatype::string:
                    value.SetString(lua::tocstring(L, -1).c_str(), allocator);
                    break;
                case datatype::table:
                    value = lua_to_json(L, -1, allocator, cyclic);
                    break;
                case datatype::function:
                case datatype::proto:
                case datatype::lightuserdata:
                case datatype::userdata:
                    value.SetString(lua::toastring(L, -1).c_str(), allocator);
                    break;
                default:
                    value.SetString("[unsupported]", allocator);
                    break;
                }

                lua::pop(L);
                array.PushBack(value, allocator);
            }

            cyclic.erase(gcobj);

            return array;
        }

        rapidjson::Value object(rapidjson::kObjectType);

        lua::pushnil(L);
        while (lua::next(L, index)) {
            int key_type = lua::gettype(L, -2);
            int value_type = lua::gettype(L, -1);

            std::string key = "[unsupported]";
            std::optional<int> numeric_key;

            if (key_type == datatype::string) {
                key = lua::tocstring(L, -2);
            }
            else if (key_type == datatype::number) {
                numeric_key = static_cast<int>(lua::tonumber(L, -2));
            }
            else {
                lua::pop(L);
                continue;
            }

            if (value_type == datatype::nil) {
                lua::pop(L);
                continue;
            }

            rapidjson::Value value;
            switch (value_type) {
            case datatype::boolean:  value.SetBool(lua::toboolean(L, -1)); break;
            case datatype::number:
                if (lua::isinteger(L, -1)) {
                    value.SetInt64(lua::tointeger(L, -1));
                }
                else {
                    value.SetDouble(lua::tonumber(L, -1));
                }
                break;
            case datatype::string:
                value.SetString(lua::tocstring(L, -1).c_str(), allocator);
                break;
            case datatype::table:
                value = lua_to_json(L, -1, allocator, cyclic);
                break;
            case datatype::function:
            case datatype::proto:
            case datatype::lightuserdata:
            case datatype::userdata:
                value.SetString(lua::toastring(L, -1).c_str(), allocator);
                break;
            default:
                value.SetString("[unsupported]", allocator);
                break;
            }

            lua::pop(L);

            rapidjson::Value rkey;
            if (numeric_key.has_value()) {
                std::string skey = std::to_string(numeric_key.value());
                rkey.SetString(skey.c_str(), allocator);
            }
            else {
                rkey.SetString(key.c_str(), allocator);
            }

            object.AddMember(rkey, value, allocator);
        }

        cyclic.erase(gcobj);

        return object;
    }

    void json_to_lua(lua_State* L, const rapidjson::Value& value) {
        using namespace rapidjson;

        if (value.IsNull()) {
            lua::pushnil(L);
        }
        else if (value.IsBool()) {
            lua::pushboolean(L, value.GetBool());
        }
        else if (value.IsInt64() || value.IsUint64()) {
            lua::pushnumber(L, static_cast<lua_Number>(value.GetInt64()));
        }
        else if (value.IsDouble()) {
            lua::pushnumber(L, value.GetDouble());
        }
        else if (value.IsString()) {
            lua::pushstring(L, value.GetString());
        }
        else if (value.IsArray()) {
            lua::newtable(L);
            int i = 1;
            for (auto& element : value.GetArray()) {
                lua::pushnumber(L, i++);
                json_to_lua(L, element);
                lua::settable(L, -3);
            }
        }
        else if (value.IsObject()) {
            lua::newtable(L);
            for (auto itr = value.MemberBegin(); itr != value.MemberEnd(); ++itr) {
                lua::pushcstring(L, itr->name.GetString());
                json_to_lua(L, itr->value);
                lua::settable(L, -3);
            }
        }
        else {
            lua::pushcstring(L, "[unsupported json type]");
        }
    }

    int isarray(lua_State* L)
    {
        luaL::checktable(L, 1);
        size_t size;
        if (is_lua_array(L, 1, size)) {
            lua::pushnumber(L, size);
            return 1;
        }
        lua::pushboolean(L, false);
        return 1;
    }

    int tojson(lua_State* L)
    {
        luaL::checktable(L, 1);
        rapidjson::Document doc;
        rapidjson::Value val = lua_to_json(L, 1, doc.GetAllocator());

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        val.Accept(writer);

        lua::pushcstring(L, buffer.GetString());
        return 1;
    }

    int fromjson(lua_State* L)
    {
        std::string data = luaL::checkcstring(L, 1);

        rapidjson::Document builder;
        builder.Parse(data.c_str());

        if (builder.HasParseError()) {
            std::stringstream o;
            o << "JSON parse error: " << builder.GetParseError() << std::endl;
            luaL::error(L, o.str().c_str());
            return 0;
        }

        json_to_lua(L, builder);

        return 1;
    }

    int usage(lua_State* L)
    {
        luaL::checktable(L, 1);

        using namespace Engine;

        TValue* tv = lua::toraw(L, 1);
        GCtab* t = (GCtab*)gcV(tv);

        lua::pushnumber(L, t->asize);
        lua::pushnumber(L, t->hmask);

        return 2;
    }

    int alloc(lua_State* L)
    {
        int asize = luaL::checknumber(L, 1);
        if (asize < 0) {
            luaL::argerror(L, 1, "invalid array size");
            return 0;
        }

        int hbits = luaL::checknumber(L, 2);
        if (hbits < 0) {
            luaL::argerror(L, 2, "invalid hash size");
            return 0;
        }

        lua::createtable(L, asize, hbits);

        return 1;
    }

    void push(lua_State* L, UMODULE hndle)
    {
        lua::pushvalue(L, indexer::global);
        lua::getfield(L, -1, "table");
        lua::remove(L, -2);

        lua::pushcfunction(L, alloc);
        lua::setfield(L, -2, "alloc");

        lua::pushcfunction(L, usage);
        lua::setfield(L, -2, "usage");

        lua::pushcfunction(L, isarray);
        lua::setfield(L, -2, "isarray");

        lua::pushcfunction(L, tojson);
        lua::setfield(L, -2, "tojson");

        lua::pushcfunction(L, fromjson);
        lua::setfield(L, -2, "fromjson");
    }

    void api() {
        Reflection::add("table", push);
    }
}