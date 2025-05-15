#pragma once
#include "interstellar.hpp"
#include <map>
#include <unordered_map>

// Interstellar: Signal
// Interstate & C++ event system
namespace INTERSTELLAR_NAMESPACE::Signal {
    typedef void (*lua_Signal_Error) (API::lua_State* L, std::string name, std::string identity, std::string error);
    extern void add_error(std::string name, lua_Signal_Error callback);
    extern void remove_error(std::string name);

    class Handle {
    public:
        Handle();
        ~Handle();
        void addl(API::lua_State* L, std::string name, std::string identity, int index);
        int getl(API::lua_State* L, std::string name, std::string identity);
        void removel(API::lua_State* L, std::string name, std::string identity);
        void api(API::lua_State* L);
        void api_funcs(API::lua_State* L);
        int size(API::lua_State* L, std::string name);
        bool has(API::lua_State* L, std::string name);
        void fire(API::lua_State* L, std::string name, int inputs = 0);
        int rfire(API::lua_State* L, std::string name, int inputs = 0, int outputs = 0);
        void clean(API::lua_State* L, std::string name);
        void erase(API::lua_State* L);
        std::unordered_map<uintptr_t, std::unordered_map<std::string, std::unordered_map<std::string, int>>> callbacks;
    };

    extern Handle* create();
    extern void push(API::lua_State* L, UMODULE hndle);
    extern void api();
}
