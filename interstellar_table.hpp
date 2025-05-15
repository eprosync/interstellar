#pragma once
#include "interstellar.hpp"

// Interstellar: Table
// Expansion to the table library
namespace INTERSTELLAR_NAMESPACE::Table {
    extern void push(API::lua_State* L, UMODULE hndle);
    extern void api();
}