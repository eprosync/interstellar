#pragma once
#include "interstellar.hpp"

namespace INTERSTELLAR_NAMESPACE::LXZ {
    typedef void (*lua_LXZ_Error) (API::lua_State* L, std::string error);
    extern void add_error(std::string name, lua_LXZ_Error callback);
    extern void remove_error(std::string name);

    extern void push(API::lua_State* L, UMODULE hndle);
    extern void api();
}