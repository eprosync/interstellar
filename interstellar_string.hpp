#pragma once
#include "interstellar.hpp"

// Interstellar: String
// Expansion to the string library
namespace INTERSTELLAR_NAMESPACE::String {
    extern void push(API::lua_State* L, UMODULE hndle);
    extern void api();
}