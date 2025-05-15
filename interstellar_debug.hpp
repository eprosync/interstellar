#pragma once
#include "interstellar.hpp"

// Interstellar: Debug
// Expansion to the debug library
namespace INTERSTELLAR_NAMESPACE::Debug
{
    extern void push(API::lua_State* L, UMODULE hndle);
    extern void api();
}