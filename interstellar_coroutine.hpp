#pragma once
#include "interstellar.hpp"

// Interstellar: Coroutine
// Expansion to the coroutine library
namespace INTERSTELLAR_NAMESPACE::Coroutine
{
    extern void push(API::lua_State* L, UMODULE hndle);
    extern void api();
}