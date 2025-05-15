#include "interstellar_string.hpp"

namespace INTERSTELLAR_NAMESPACE::String {
    using namespace API;

    void push(lua_State* L, UMODULE hndle)
    {
        lua::pushvalue(L, indexer::global);
        lua::getfield(L, -1, "string");
        lua::remove(L, -2);
    }

    void api() {
        Reflection::add("string", push);
    }
}