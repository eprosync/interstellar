#pragma once
#include "interstellar.hpp"

// Interstellar: OS
// Expansion to the os library
namespace INTERSTELLAR_NAMESPACE::OS {
    extern void push(API::lua_State* L, UMODULE hndle);
    extern void api();
}