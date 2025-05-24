#include "interstellar_os.hpp"
#include <unordered_set>
#include <unordered_map>
#include <algorithm>
#include <sstream>

#ifdef __linux
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#else
#include <string.h>
#include <stdbool.h>
#endif

namespace INTERSTELLAR_NAMESPACE::OS {
    using namespace API;

    namespace ARGV {
        struct parsed {
            bool check = false;
            std::unordered_set<std::string> flags;
            std::unordered_map<std::string, std::string> options;
            std::vector<std::string> positional;
        };

        std::string raw()
        {
            #ifdef _WIN32
                return GetCommandLineA();
            #else
                FILE* f = fopen("/proc/self/cmdline", "r");
                if (!f) return {};

                std::string result;
                int c;
                bool first = true;

                while ((c = fgetc(f)) != EOF) {
                    if (c == '\0') {
                        result += ' ';
                    } else {
                        result += static_cast<char>(c);
                    }
                }

                fclose(f);
                return result;
            #endif
        }

        int lraw(lua_State* L)
        {
            lua::pushcstring(L, raw());
            return 1;
        }

        parsed parse_args() {
            static parsed cache;

            if (cache.check) {
                return cache;
            }

            parsed parsed;
            std::istringstream iss(raw());
            std::string token;
            std::vector<std::string> tokens;

            while (iss >> token) tokens.push_back(token);

            for (size_t i = 0; i < tokens.size(); ++i) {
                std::string& t = tokens[i];

                if (t.rfind("--", 0) == 0) {
                    std::string key, value;
                    auto eq_pos = t.find('=');
                    if (eq_pos != std::string::npos) {
                        key = t.substr(2, eq_pos - 2);
                        value = t.substr(eq_pos + 1);
                    }
                    else {
                        key = t.substr(2);
                        if (i + 1 < tokens.size() && tokens[i + 1].rfind("-", 0) != 0 && tokens[i + 1].rfind("+", 0) != 0)
                            value = tokens[++i];
                    }
                    parsed.options[key] = value;
                }
                else if (t.rfind("-", 0) == 0 && t.size() > 1 && t[1] != '-') {
                    std::string key = t.substr(1);

                    bool all_single_flags = std::all_of(key.begin(), key.end(), [](char c) {
                        return std::isalpha(c) && std::islower(c);
                    });

                    bool has_following_value = (i + 1 < tokens.size()) &&
                        tokens[i + 1].rfind("-", 0) != 0 && tokens[i + 1].rfind("+", 0) != 0;

                    if (key.size() == 1 && !has_following_value) {
                        parsed.flags.insert(key);
                    }
                    else if (all_single_flags && !has_following_value) {
                        parsed.flags.insert(key);
                    }
                    else {
                        std::string value;
                        if (has_following_value) {
                            value = tokens[++i];
                        }
                        parsed.options[key] = value;
                    }
                }
                else if (t.rfind("+", 0) == 0 || (t.rfind("-", 0) == 0 && t.size() > 1 && isalpha(t[1]))) {
                    std::string key = t.substr(1);
                    std::string value;
                    if (i + 1 < tokens.size() && tokens[i + 1].rfind("-", 0) != 0 && tokens[i + 1].rfind("+", 0) != 0) {
                        value = tokens[++i];
                    }
                    parsed.options[key] = value;
                }
                else {
                    parsed.positional.push_back(t);
                }
            }

            parsed.check = true;
            cache = parsed;

            return parsed;
        }

        std::unordered_set<std::string> flags()
        {
            return parse_args().flags;
        }

        int lflags(lua_State* L)
        {
            std::unordered_set<std::string> list = flags();

            if (lua::isstring(L, 1)) {
                std::string flag = lua::tocstring(L, 1);
                if (list.find(flag) != list.end()) {
                    lua::pushboolean(L, true);
                    return 1;
                }
                lua::pushboolean(L, false);
                return 1;
            }

            lua::newtable(L);

            size_t i = 0;
            for (auto& entry : list) {
                lua::pushnumber(L, ++i);
                lua::pushcstring(L, entry);
                lua::settable(L, -3);

                lua::pushcstring(L, entry);
                lua::pushboolean(L, true);
                lua::settable(L, -3);
            }

            return 1;
        }

        bool has_flag(std::string flag) {
            std::unordered_set<std::string> list = flags();
            return list.find(flag) != list.end();
        }

        std::unordered_map<std::string, std::string> options()
        {
            return parse_args().options;
        }

        int loptions(lua_State* L)
        {
            std::unordered_map<std::string, std::string> list = options();

            if (lua::isstring(L, 1)) {
                std::string flag = lua::tocstring(L, 1);
                if (list.find(flag) != list.end()) {
                    lua::pushcstring(L, list[flag]);
                    return 1;
                }
                return 0;
            }

            lua::newtable(L);

            size_t i = 0;
            for (auto& entry : list) {
                lua::pushnumber(L, ++i);
                lua::pushcstring(L, entry.first);
                lua::settable(L, -3);

                lua::pushcstring(L, entry.first);
                lua::pushcstring(L, entry.second);
                lua::settable(L, -3);
            }

            return 1;
        }

        std::string has_option(std::string flag) {
            std::unordered_map<std::string, std::string> list = options();
            if (list.find(flag) != list.end()) {
                return list[flag];
            }
            return "";
        }

        bool exists(std::string name, std::string* value)
        {
            std::unordered_set<std::string> _flags = flags();
            std::unordered_map<std::string, std::string> _options = options();
            if (_options.find(name) != _options.end()) {
                if (value) {
                    *value = _options[name];
                }
                return true;
            }
            return _flags.find(name) != _flags.end();
        }

        std::vector<std::string> positional()
        {
            return parse_args().positional;
        }

        int lpositional(lua_State* L)
        {
            std::vector<std::string> list = positional();

            lua::newtable(L);

            size_t i = 0;
            for (auto& entry : list) {
                lua::pushnumber(L, ++i);
                lua::pushcstring(L, entry);
                lua::settable(L, -3);

                lua::pushcstring(L, entry);
                lua::pushboolean(L, true);
                lua::settable(L, -3);
            }

            return 1;
        }
    }

    void push(lua_State* L, UMODULE hndle)
    {
        lua::pushvalue(L, indexer::global);
        lua::getfield(L, -1, "os");
        lua::remove(L, -2);

        lua::newtable(L);

        lua::pushcfunction(L, ARGV::lraw);
        lua::setfield(L, -2, "raw");

        lua::pushcfunction(L, ARGV::lflags);
        lua::setfield(L, -2, "flags");

        lua::pushcfunction(L, ARGV::loptions);
        lua::setfield(L, -2, "options");

        lua::pushcfunction(L, ARGV::lpositional);
        lua::setfield(L, -2, "positional");

        lua::setfield(L, -2, "argv");
    }

    void api() {
        Reflection::add("os", push);
    }
}