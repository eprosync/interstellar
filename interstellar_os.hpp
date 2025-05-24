#pragma once
#include "interstellar.hpp"
#include <unordered_set>
#include <unordered_map>

// Interstellar: OS
// Expansion to the os library
namespace INTERSTELLAR_NAMESPACE::OS {
    namespace ARGV {
        extern std::string raw();
        extern std::unordered_set<std::string> flags();
        extern bool has_flag(std::string flag);
        extern std::unordered_map<std::string, std::string> options();
        extern std::string has_option(std::string flag);
        extern bool exists(std::string name, std::string* value = nullptr);
        extern std::vector<std::string> positional();
    }

    extern void push(API::lua_State* L, UMODULE hndle);
    extern void api();
}