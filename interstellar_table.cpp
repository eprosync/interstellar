#include "interstellar_table.hpp"

namespace INTERSTELLAR_NAMESPACE::Table {
    using namespace API;

    void push(lua_State* L, UMODULE hndle)
    {
        lua::pushvalue(L, indexer::global);
        lua::getfield(L, -1, "table");
        lua::remove(L, -2);
    }

    void api() {
        Reflection::add("table", push);
    }
}