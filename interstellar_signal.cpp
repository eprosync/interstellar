#include "interstellar_signal.hpp"
#include <algorithm>

namespace INTERSTELLAR_NAMESPACE::Signal {
    using namespace API;

    std::map<std::string, lua_Signal_Error> on_error;

    void add_error(std::string name, lua_Signal_Error callback)
    {
        on_error.emplace(name, callback);
    }

    void remove_error(std::string name)
    {
        on_error.erase(name);
    }

    int _addl(lua_State* L)
    {
        std::string name = luaL::checkcstring(L, 1);
        std::string identity = luaL::checkcstring(L, 2);
        luaL::checklfunction(L, 3);

        lua::pushvalue(L, upvalueindex(1));
        Handle* handle = (Handle*)luaL::checklightuserdata(L, -1);
        lua::pop(L);

        handle->addl(L, name, identity, 3);

        return 0;
    }

    int _connectl(lua_State* L)
    {
        std::string name = luaL::checkcstring(L, 1);
        luaL::checklfunction(L, 2);
        std::string identity = luaL::checkcstring(L, 3);

        lua::pushvalue(L, upvalueindex(1));
        Handle* handle = (Handle*)luaL::checklightuserdata(L, -1);
        lua::pop(L);

        handle->addl(L, name, identity, 2);

        return 0;
    }

    int _getl(lua_State* L)
    {
        std::string name = luaL::checkcstring(L, 1);
        std::string identity = luaL::checkcstring(L, 2);

        lua::pushvalue(L, upvalueindex(1));
        Handle* handle = (Handle*)luaL::checklightuserdata(L, -1);
        lua::pop(L);

        if (int index = handle->getl(L, name, identity) != 0) {
            lua::pushref(L, index);
            return 1;
        }

        return 0;
    }

    int _removel(lua_State* L)
    {
        std::string name = luaL::checkcstring(L, 1);
        std::string identity = luaL::checkcstring(L, 2);

        lua::pushvalue(L, upvalueindex(1));
        Handle* handle = (Handle*)luaL::checklightuserdata(L, -1);
        lua::pop(L);

        handle->removel(L, name, identity);

        return 0;
    }

    std::vector<Handle*> handles;

    void cleanup(lua_State* L)
    {
        for (Handle* handle : handles) {
            handle->erase(L);
        }
    }

    Handle::Handle()
    {
        handles.push_back(this);
    }

    Handle::~Handle()
    {
        for (auto& states : callbacks) this->erase((lua_State*)states.first);
        handles.erase(std::remove(handles.begin(), handles.end(), this), handles.end());
    }

    void Handle::addl(lua_State* L, std::string name, std::string identity, int index)
    {
        uintptr_t id = Tracker::id(L);
        lua::pushvalue(L, index);
        int reference = luaL::newref(L, -1);

        if (callbacks.find(id) == callbacks.end()) callbacks.emplace(id, std::unordered_map<std::string, std::unordered_map<std::string, int>>());

        auto& list = callbacks[id];

        if (list.find(name) == list.end()) list.emplace(name, std::unordered_map<std::string, int>());

        auto& funcs = list[name];

        if (funcs.find(identity) != funcs.end()) {
            luaL::rmref(L, funcs[identity]);
            funcs.erase(identity);
        }

        funcs.emplace(identity, reference);
    }

    int Handle::getl(lua_State* L, std::string name, std::string identity)
    {
        uintptr_t id = Tracker::id(L);

        if (callbacks.find(id) == callbacks.end()) return 0;

        auto& list = callbacks[id];

        if (list.find(name) == list.end()) return 0;

        auto& funcs = list[name];

        if (funcs.find(identity) == funcs.end()) return 0;

        return funcs[identity];
    }

    void Handle::removel(lua_State* L, std::string name, std::string identity)
    {
        uintptr_t id = Tracker::id(L);

        if (callbacks.find(id) == callbacks.end()) return;

        auto& list = callbacks[id];

        if (list.find(name) == list.end()) return;

        auto& funcs = list[name];

        if (funcs.find(identity) == funcs.end()) return;

        luaL::rmref(L, funcs[identity]);
        funcs.erase(identity);
    }

    int Handle::size(lua_State* L, std::string name)
    {
        uintptr_t id = Tracker::id(L);

        if (callbacks.find(id) == callbacks.end()) return 0;

        auto& list = callbacks[id];

        if (list.find(name) == list.end()) return 0;

        auto& funcs = list[name];

        return funcs.size();
    }

    bool Handle::has(lua_State* L, std::string name)
    {
        uintptr_t id = Tracker::id(L);

        if (callbacks.find(id) == callbacks.end()) return false;

        auto& list = callbacks[id];

        if (list.find(name) == list.end()) return false;

        auto& funcs = list[name];

        return funcs.size() > 0;
    }

    void Handle::api(lua_State* L)
    {
        lua::newtable(L);
        this->api_funcs(L);
    }

    void Handle::api_funcs(lua_State* L)
    {
        lua::pushlightuserdata(L, this);
        lua::pushcclosure(L, _addl, 1);
        lua::setfield(L, -2, "add");

        lua::pushlightuserdata(L, this);
        lua::pushcclosure(L, _connectl, 1);
        lua::setfield(L, -2, "connect");

        lua::pushlightuserdata(L, this);
        lua::pushcclosure(L, _getl, 1);
        lua::pushvalue(L, -1);
        lua::setfield(L, -3, "get");
        lua::setfield(L, -2, "connection");

        lua::pushlightuserdata(L, this);
        lua::pushcclosure(L, _removel, 1);
        lua::pushvalue(L, -1);
        lua::setfield(L, -3, "remove");
        lua::setfield(L, -2, "disconnect");
    }

    void Handle::fire(lua_State* L, std::string name, int inputs)
    {
        uintptr_t id = Tracker::id(L);
        auto callbacks_itr = callbacks.find(id);
        if (callbacks_itr == callbacks.end()) {
            lua::pop(L, inputs);
            return;
        }


        auto& list = callbacks_itr->second;
        auto list_itr = list.find(name);

        if (list_itr == list.end()) {
            lua::pop(L, inputs);
            return;
        }

        auto& funcs = list_itr->second;

        for (auto const& [identity, reference] : funcs)
        {
            lua::pushref(L, reference);
            for (int i = 0; i < inputs; i++) {
                lua::pushvalue(L, -(1 + inputs));
            }

            if (lua::tcall(L, inputs, 0)) {
                std::string err = lua::tocstring(L, -1);
                lua::pop(L);
                for (auto const& handle : on_error) handle.second(L, name, identity, err);
                luaL::rmref(L, reference);
                funcs.erase(identity);
                continue;
            }
        }

        lua::pop(L, inputs);
    }

    int Handle::rfire(lua_State* L, std::string name, int inputs, int outputs)
    {
        if (outputs == 0) {
            this->fire(L, name, inputs);
            return 0;
        }

        uintptr_t id = Tracker::id(L);

        auto callbacks_itr = callbacks.find(id);
        if (callbacks_itr == callbacks.end()) {
            lua::pop(L, inputs);
            if (outputs > 0) {
                for (int i = 0; i < outputs; i++) lua::pushnil(L);
                return outputs;
            }
            return 0;
        }

        auto& list = callbacks_itr->second;
        auto list_itr = list.find(name);

        if (list_itr == list.end()) {
            lua::pop(L, inputs);
            if (outputs > 0) {
                for (int i = 0; i < outputs; i++) lua::pushnil(L);
                return outputs;
            }
            return 0;
        }

        auto& funcs = list_itr->second;

        for (auto const& [identity, reference] : funcs)
        {
            int top = lua::gettop(L);

            lua::pushref(L, reference);
            for (int i = 0; i < inputs; i++) {
                lua::pushvalue(L, -(1 + inputs));
            }

            if (lua::tcall(L, inputs, outputs)) {
                std::string err = lua::tocstring(L, -1);
                lua::pop(L);
                for (auto const& handle : on_error) handle.second(L, name, identity, err);
                luaL::rmref(L, reference);
                funcs.erase(identity);
                continue;
            }

            int res = lua::gettop(L) - top;

            if (res > 0 && !lua::isnil(L, -1)) {
                for (int i = 0; i < inputs; i++) lua::remove(L, -(1 + res));
                return res;
            }
            else {
                lua::pop(L, res);
            }
        }

        lua::pop(L, inputs);

        if (outputs > 0) {
            for (int i = 0; i < outputs; i++) lua::pushnil(L);
            return outputs;
        }

        return 0;
    }

    void Handle::clean(lua_State* L, std::string name)
    {
        if (Tracker::is_state(L) == nullptr) return;

        uintptr_t id = Tracker::id(L);

        if (callbacks.find(id) == callbacks.end()) return;

        auto& list = callbacks[id];

        if (list.find(name) == list.end()) return;

        auto& funcs = list[name];

        for (auto const& [identity, reference] : funcs)
        {
            luaL::rmref(L, reference);
        }

        list.erase(name);
    }

    void Handle::erase(lua_State* L)
    {
        uintptr_t id = Tracker::id(L);

        if (Tracker::is_state(L) != nullptr) {
            uintptr_t id = Tracker::id(L);
            if (callbacks.find(id) != callbacks.end()) {
                auto& list = callbacks[id];
                for (auto const& [name, funcs] : list)
                {
                    for (auto const& [identity, reference] : funcs)
                    {
                        luaL::rmref(L, reference);
                    }
                }
            }
        }

        callbacks.erase(id);
    }

    Handle* create()
    {
        return new Handle();
    }

    Handle* universal = create();

    lua_State* call_origin;
    std::string call_name;
    int wrapper_call(lua_State* L)
    {
        int nargs = lua::gettop(call_origin) - 2;

        for (int i = 1; i <= nargs; i++) {
            Reflection::transfer(call_origin, L, i + 2);
        }

        universal->fire(L, call_name, nargs);

        return 0;
    }

    int interstate_call(lua_State* L)
    {
        lua_State* target = Tracker::is_state(Class::check(L, 1, "lua.state"));
        if (target == nullptr) {
            luaL::error(L, "invalid lua instance");
            return 0;
        }

        std::string name = luaL::checkcstring(L, 2);

        if (target != L) {
            call_origin = L;
            call_name = name;

            if (Tracker::should_lock(target, L)) {
                bool should_notify = !Tracker::is_threaded(target);
                if (should_notify) Tracker::increment();
                Tracker::cross_lock(target, L);
                lua::pushcfunction(target, wrapper_call);
                lua::pcall(target, 0, 0, 0);
                Tracker::cross_unlock(target, L);
                if (should_notify) Tracker::decrement();
            }
            else {
                lua::pushcfunction(target, wrapper_call);
                lua::pcall(target, 0, 0, 0);
            }

            return 0;
        }

        int nargs = lua::gettop(L) - 2;

        for (int i = 1; i <= nargs; i++) {
            lua::pushvalue(L, i + 2);
        }

        universal->fire(target, name, nargs);

        return 0;
    }

    lua_State* rcall_origin;
    std::string rcall_name;
    int rcall_returns;
    int wrapper_rcall(lua_State* L)
    {
        int nargs = lua::gettop(rcall_origin) - 2;

        for (int i = 1; i <= nargs; i++) {
            Reflection::transfer(rcall_origin, L, i + 2);
        }

        rcall_returns = universal->rfire(L, rcall_name, nargs, -1);

        for (int i = rcall_returns; i >= 1; i--) {
            Reflection::transfer(L, rcall_origin, -i);
        }

        lua::pop(L, rcall_returns);

        return 0;
    }

    int interstate_rcall(lua_State* L)
    {
        lua_State* target = Tracker::is_state(Class::check(L, 1, "lua.state"));
        if (target == nullptr) {
            luaL::error(L, "invalid lua instance");
            return 0;
        }

        std::string name = luaL::checkcstring(L, 2);

        if (target != L) {
            rcall_origin = L;
            rcall_name = name;

            if (Tracker::should_lock(target, L)) {
                bool should_notify = !Tracker::is_threaded(target);
                if (should_notify) Tracker::increment();
                Tracker::cross_lock(target, L);
                lua::pushcfunction(target, wrapper_rcall);
                lua::pcall(target, 0, 0, 0);
                Tracker::cross_unlock(target, L);
                if (should_notify) Tracker::decrement();
            }
            else {
                lua::pushcfunction(target, wrapper_rcall);
                lua::pcall(target, 0, 0, 0);
            }

            return rcall_returns;
        }

        int nargs = lua::gettop(L) - 2;

        for (int i = 1; i <= nargs; i++) {
            lua::pushvalue(L, i + 2);
        }

        return universal->rfire(target, name, nargs, -1);
    }

    void push(API::lua_State* L, UMODULE hndle) {
        Tracker::add("signal", cleanup);

        lua::newtable(L);

        universal->api_funcs(L);

        lua::pushcfunction(L, interstate_rcall);
        lua::pushvalue(L, -1);
        lua::setfield(L, -3, "call");
        lua::setfield(L, -2, "fire");
    }

    void api() {
        on_error = std::map<std::string, lua_Signal_Error>();
        Reflection::add("signal", push);
    }
}