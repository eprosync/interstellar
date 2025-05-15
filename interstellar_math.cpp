#include "interstellar_math.hpp"

namespace INTERSTELLAR_NAMESPACE::Math {
    using namespace API;

    void push(lua_State* L, UMODULE hndle)
    {
        lua::pushvalue(L, indexer::global);
        lua::getfield(L, -1, "math");
        lua::remove(L, -2);
    }

    void api() {
        Reflection::add("math", push);
    }
}