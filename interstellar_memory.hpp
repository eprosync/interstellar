#pragma once
#include "interstellar.hpp"

// Interstellar: Memory
// Access to basically commit all kinds of atrocious acts
namespace INTERSTELLAR_NAMESPACE::Memory {
    extern void runtime();
    extern void push(API::lua_State* L, UMODULE hndle);
    extern void api();
}