#include "interstellar_bit.hpp"

namespace INTERSTELLAR_NAMESPACE::Bit {
    using namespace API;

    void push(lua_State* L, UMODULE hndle)
    {
        lua::pushvalue(L, indexer::global);
        lua::getfield(L, -1, "bit");
        lua::remove(L, -2);
    }

    void api() {
        Reflection::add("bit", push);
    }
}