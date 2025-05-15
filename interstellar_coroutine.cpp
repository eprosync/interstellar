#include "interstellar_coroutine.hpp"

namespace INTERSTELLAR_NAMESPACE::Coroutine {
    using namespace API;

    void push(lua_State* L, UMODULE hndle)
    {
        lua::pushvalue(L, indexer::global);
        lua::getfield(L, -1, "coroutine");
        lua::remove(L, -2);
    }

    void api() {
        Reflection::add("coroutine", push);
    }
}