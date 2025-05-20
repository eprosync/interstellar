#include "interstellar_string.hpp"
#include "interstellar_buffer.hpp"

namespace INTERSTELLAR_NAMESPACE::String {
    using namespace API;

    int to_buffer(lua_State* L)
    {
        Buffer::push_buffer(L, luaL::checkcstring(L, 1));
        return 1;
    }

    void push(lua_State* L, UMODULE hndle)
    {
        lua::pushvalue(L, indexer::global);
        lua::getfield(L, -1, "string");
        lua::remove(L, -2);

        lua::pushcfunction(L, to_buffer);
        lua::setfield(L, -2, "buffer");
    }

    void api() {
        Reflection::add("string", push);
    }
}