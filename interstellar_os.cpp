#include "interstellar_os.hpp"

namespace INTERSTELLAR_NAMESPACE::OS {
    using namespace API;

    void push(lua_State* L, UMODULE hndle)
    {
        lua::pushvalue(L, indexer::global);
        lua::getfield(L, -1, "os");
        lua::remove(L, -2);
    }

    void api() {
        Reflection::add("os", push);
    }
}