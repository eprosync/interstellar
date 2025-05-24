#include "interstellar_table.hpp"
#include <nlohmann/json.hpp>

namespace INTERSTELLAR_NAMESPACE::Table {
    using namespace API;

    bool is_lua_array(lua_State* L, int index, size_t& size) {
        if (!lua::istable(L, index)) return false;

        if (index < 0) index = lua::gettop(L) + index + 1;

        size_t count = 0;
        size_t max_index = 0;

        lua::pushnil(L);
        while (lua::next(L, index)) {
            if (lua::gettype(L, -2) != datatype::number || !lua::isnumber(L, -2)) {
                lua::pop(L, 1);
                return false;
            }

            lua_Number k = lua::tonumber(L, -2);
            if (k < 1) {
                lua::pop(L, 1);
                return false;
            }

            if (k > max_index) max_index = static_cast<int>(k);
            ++count;

            lua::pop(L, 1);
        }

        size = max_index;

        return count == max_index;
    }

    nlohmann::json lua_to_json(lua_State* L, int index, std::vector<Engine::GCobj*> references = std::vector<Engine::GCobj*>()) {
        using namespace nlohmann;
        using namespace Engine;

        TValue* tv = lua::toraw(L, index);
        GCobj* gcobj = gcV(tv);

        if (std::find(references.begin(), references.end(), gcobj) == references.end()) {
            references.push_back(gcobj);
        }
        else {
            return "[cyclic]";
        }

        json builder = json::array();

        if (index < 0) index = lua::gettop(L) + index + 1;
        
        size_t size;
        if (is_lua_array(L, index, size)) {
            for (size_t i = 0; i < size; i++) {
                lua::pushnumber(L, i + 1);
                lua::gettable(L, -2);
                int value_type = lua::gettype(L, -1);

                if (value_type == datatype::nil) {
                    lua::pop(L);
                    continue;
                }

                nlohmann::json value;
                switch (value_type) {
                    case datatype::boolean:  value = lua::toboolean(L, -1); break;
                    case datatype::number: {
                        if (lua::isinteger(L, -1))
                        {
                            value = lua::tointeger(L, -1);
                        }
                        else {
                            value = lua::tonumber(L, -1);
                        }
                        break;
                    }
                    case datatype::string:          value = lua::tocstring(L, -1); break;
                    case datatype::table:           value = lua_to_json(L, -1, references); break;
                    case datatype::function:        value = lua::toastring(L, -1); break;
                    case datatype::proto:           value = lua::toastring(L, -1); break;
                    case datatype::lightuserdata:   value = lua::toastring(L, -1); break;
                    case datatype::userdata:        value = lua::toastring(L, -1); break;
                    default:                        value = "[unsupported]"; break;
                }

                lua::pop(L);
                builder[i] = value;
            }

            references.pop_back();

            return builder;
        }

        builder = json::object();

        lua::pushnil(L);
        while (lua::next(L, index)) {
            int key_type = lua::gettype(L, -2);
            int value_type = lua::gettype(L, -1);

            std::string key = "[unsupported]";
            std::optional<int> index;

            if (key_type == datatype::string) {
                key = lua::tocstring(L, -2);
            }
            else if (key_type == datatype::number) {
                index = static_cast<int>(lua::tonumber(L, -2));
            }
            else {
                lua::pop(L);
                continue;
            }

            if (value_type == datatype::nil) {
                lua::pop(L);
                continue;
            }

            nlohmann::json value;
            switch (value_type) {
                case datatype::boolean:  value = lua::toboolean(L, -1); break;
                case datatype::number: {
                    if (lua::isinteger(L, -1))
                    {
                        value = lua::tointeger(L, -1);
                    }
                    else {
                        value = lua::tonumber(L, -1);
                    }
                    break;
                }
                case datatype::string:   value = lua::tocstring(L, -1); break;
                case datatype::table:    value = lua_to_json(L, -1, references); break;
                default:                 value = "[unsupported]"; break;
            }

            lua::pop(L);

            if (index.has_value()) {
                builder[std::to_string(index.value())] = value;
            }
            else {
                builder[key] = value;
            }
        }

        references.pop_back();

        return builder;
    }

    void json_to_lua(lua_State* L, const nlohmann::json& value) {
        using nlohmann::json;

        switch (value.type()) {
        case json::value_t::null:
            lua::pushnil(L);
            break;

        case json::value_t::boolean:
            lua::pushboolean(L, value.get<bool>());
            break;

        case json::value_t::number_integer:
            lua::pushnumber(L, value.get<lua_Number>());
            break;

        case json::value_t::number_unsigned:
            lua::pushnumber(L, static_cast<lua_Number>(value.get<uint64_t>()));
            break;

        case json::value_t::number_float:
            lua::pushnumber(L, value.get<lua_Number>());
            break;

        case json::value_t::string:
            lua::pushstring(L, value.get<std::string>().c_str());
            break;

        case json::value_t::array: {
            lua::newtable(L);
            int i = 0;
            for (const auto& element : value) {
                lua::pushnumber(L, ++i);
                json_to_lua(L, element);
                lua::settable(L, -3);
            }
            break;
        }

        case json::value_t::object: {
            lua::newtable(L);
            for (const auto& [key, val] : value.items()) {
                lua::pushcstring(L, key);
                json_to_lua(L, val);
                lua::settable(L, -3);
            }
            break;
        }

        default:
            lua::pushcstring(L, "[unsupported json type]");
            break;
        }
    }

    int isarray(lua_State* L)
    {
        luaL::checktable(L, 1);
        size_t size;
        lua::pushboolean(L, is_lua_array(L, 1, size));
        return 1;
    }

    int tojson(lua_State* L)
    {
        luaL::checktable(L, 1);
        nlohmann::json data = lua_to_json(L, 1);
        lua::pushcstring(L, data.dump());
        return 1;
    }

    int fromjson(lua_State* L)
    {
        std::string data = luaL::checkcstring(L, 1);

        nlohmann::json builder;
        try {
            builder = nlohmann::json::parse(data);
        }
        catch (const nlohmann::json::parse_error& e) {
            std::stringstream o;
            o << "JSON parse error at byte " << e.byte << ": " << e.what() << std::endl;
            luaL::error(L, o.str().c_str());
            return 0;
        }

        json_to_lua(L, builder);

        return 1;
    }

    void push(lua_State* L, UMODULE hndle)
    {
        lua::pushvalue(L, indexer::global);
        lua::getfield(L, -1, "table");
        lua::remove(L, -2);

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