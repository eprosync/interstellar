#include "interstellar.hpp"
#include "interstellar_bit.hpp"
#include "interstellar_coroutine.hpp"
#include "interstellar_debug.hpp"
#include "interstellar_math.hpp"
#include "interstellar_os.hpp"
#include "interstellar_string.hpp"
#include "interstellar_table.hpp"
#include "interstellar_signal.hpp"
#include "interstellar_buffer.hpp"

#include <vector>
#include <map>
#include <unordered_map>
#include <chrono>
#include <algorithm>
#include <cmath>
#include <string_view>
#include <array>
#include <sstream>
#include <iomanip>

namespace INTERSTELLAR_NAMESPACE {
    namespace API
    {
        // Giant garble of GetProcAddress assignments
        // Oh mah gawd
        #define grab n2p
        #define cast reinterpret_cast

        // luaL functions
        namespace luaL
        {
            type::addlstring addlstring;
            type::addstring addstring;
            type::addvalue addvalue;
            type::argerror argerror;
            type::buffinit buffinit;
            type::callmeta callmeta;
            type::checkany checkany;
            type::checkinteger checkinteger;
            type::checklstring checklstring;
            type::checknumber checknumber;
            type::checkoption checkoption;
            type::checkstack checkstack;
            type::checktype checktype;
            type::checkudata checkudata;
            type::error error;
            type::execresult execresult;
            type::fileresult fileresult;
            type::findtable findtable;
            type::getmetafield getmetafield;
            type::gsub gsub;
            type::loadbuffer loadbuffer;
            type::loadbufferx loadbufferx;
            type::loadfile loadfile;
            type::loadfilex loadfilex;
            type::loadstring loadstring;
            type::newmetatable newmetatable;
            type::newstate newstate;
            type::openlib openlib;
            type::openlibs openlibs;
            type::optinteger optinteger;
            type::optlstring optlstring;
            type::optnumber optnumber;
            type::prepbuffer prepbuffer;
            type::pushmodule pushmodule;
            type::pushresult pushresult;
            type::ref ref;
            type::makelib makelib;
            type::setfuncs setfuncs;
            type::setmetatable setmetatable;
            type::testudata testudata;
            type::traceback traceback;
            type::typerror typerror;
            type::unref unref;
            type::where where;

            #ifdef INTERSTELLAR_EXTERNAL
            #define include(hndle, name, offset) \
                    { void* f = grab(hndle, "luaL_" #name); if (f == NULL) { printf("[Interstellar] couldn't locate luaL_" #name "\n"); return offset; } name = cast<type::name>(f); offset++; }

            #define includeA(hndle, real, name, offset) \
                    { void* f = grab(hndle, "luaL_" #real); if (f == NULL) { printf("[Interstellar] couldn't locate luaL_" #real "\n"); return offset; } name = cast<type::name>(f); offset++; }
            #else
            #define include(hndle, name, offset) \
                    name = cast<type::name>(Engine::luaL_##name);

            #define includeA(hndle, real, name, offset) \
                    name = cast<type::name>(Engine::luaL_##real);
            #endif

            std::string trace(lua_State* L, int index)
            {
                traceback(L, L, "", index);
                std::string trace = lua::tocstring(L, -1);
                lua::pop(L, 1);

                size_t pos = trace.find("stack traceback:");
                if (pos != std::string::npos) {
                    trace.erase(pos, 16);
                }

                std::string cleaned_trace;
                cleaned_trace.reserve(trace.size());

                bool first_char = true;
                for (size_t i = 0; i < trace.size(); ++i) {
                    if (trace[i] == '\t' && (first_char || (i > 0 && trace[i - 1] == '\n'))) {
                        continue;
                    }
                    first_char = false;
                    cleaned_trace += trace[i];
                }

                while (!cleaned_trace.empty() && cleaned_trace.front() == '\n') {
                    cleaned_trace.erase(0, 1);
                }

                return cleaned_trace.empty() ? "[C]" : cleaned_trace;
            }

            std::string checkcstring(lua_State* L, int index) {
                size_t size = 0;
                const char* str = checklstring(L, index, &size);
                return std::string(str, size);
            }

            bool checkboolean(lua_State* L, int index) {
                luaL::checktype(L, index, datatype::boolean);
                return lua::toboolean(L, index);
            }

            void checkfunction(lua_State* L, int index) {
                luaL::checktype(L, index, datatype::function);
            }

            void* checklightuserdata(lua_State* L, int index) {
                luaL::checktype(L, index, datatype::lightuserdata);
                return lua::touserdata(L, index);
            }

            void* checkuserdata(lua_State* L, int index) {
                luaL::checktype(L, index, datatype::userdata);
                return lua::touserdata(L, index);
            }

            void* checkuserdatatype(lua_State* L, int index, int type) {
                luaL::checktype(L, index, datatype::userdata);
                lua_udata data =(lua_udata)lua::touserdata(L, index);
                if (data.type != type) {
                    luaL::error(L, "userdata is not of type %d", type);
                    return nullptr;
                }
                return data.data;
            }

            void checkcfunction(lua_State* L, int index) {
                luaL::checktype(L, index, datatype::function);
                if (!lua::iscfunction(L, index)) {
                    luaL::error(L, "provided function is not a cfunction");
                }
            }

            void checklfunction(lua_State* L, int index) {
                luaL::checktype(L, index, datatype::function);
                if (lua::iscfunction(L, index)) {
                    luaL::error(L, "provided function is not a lfunction");
                }
            }

            void checkproto(lua_State* L, int index) {
                luaL::checktype(L, index, datatype::proto);
            }

            void checktable(lua_State* L, int index) {
                luaL::checktype(L, index, datatype::table);
            }

            int newref(lua_State* L, int index) {
                lua::pushvalue(L, index);
                if (index < 0) lua::remove(L, index);
                return luaL::ref(L, indexer::registry);
            }

            void rmref(lua_State* L, int reference) {
                luaL::unref(L, indexer::registry, reference);
            }

            static int writer_dump(lua_State* L, const void* p, size_t size, void* sb)
            {
                std::string& buffer = *(std::string*)sb;
                buffer.append((const char*)p, size);
                return 0;
            }

            std::string dump(lua_State* L, int index)
            {
                if (!lua::islfunction(L, index)) {
                    return "";
                }
                std::string buffer;
                lua::pushvalue(L, index);
                lua::dump(L, writer_dump, (void*)&buffer);
                lua::pop(L);
                return buffer;
            }

            int fetch(UMODULE hndle)
            {
                int start = 1;

                include(hndle, addlstring, start);
                include(hndle, addstring, start);
                include(hndle, addvalue, start);
                include(hndle, argerror, start);
                include(hndle, buffinit, start);
                include(hndle, callmeta, start);
                include(hndle, checkany, start);
                include(hndle, checkinteger, start);
                include(hndle, checklstring, start);
                include(hndle, checknumber, start);
                include(hndle, checkoption, start);
                include(hndle, checkstack, start);
                include(hndle, checktype, start);
                include(hndle, checkudata, start);
                include(hndle, error, start);
                include(hndle, execresult, start);
                include(hndle, fileresult, start);
                include(hndle, findtable, start);
                include(hndle, getmetafield, start);
                include(hndle, gsub, start);
                include(hndle, loadbuffer, start);
                include(hndle, loadbufferx, start);
                include(hndle, loadfile, start);
                include(hndle, loadfilex, start);
                include(hndle, loadstring, start);
                include(hndle, newmetatable, start);
                include(hndle, newstate, start);
                include(hndle, openlib, start);
                include(hndle, openlibs, start);
                include(hndle, optinteger, start);
                include(hndle, optlstring, start);
                include(hndle, optnumber, start);
                include(hndle, prepbuffer, start);
                /*
                #ifndef __linux
                    include(hndle, pushmodule, start);
                #endif
                */
                include(hndle, pushresult, start);
                include(hndle, ref, start);
                includeA(hndle, register, makelib, start);
                /*
                #ifndef __linux
                    include(hndle, setfuncs, start);
                    include(hndle, setmetatable, start);
                    include(hndle, testudata, start);
                #endif
                */
                include(hndle, traceback, start);
                include(hndle, typerror, start);
                include(hndle, unref, start);
                include(hndle, where, start);
                return 0;
            }
        }

        // lua functions
        namespace lua
        {
            type::atpanic atpanic;
            type::call call;
            type::checkstack checkstack;
            type::close close;
            type::concat concat;
            type::copy copy;
            type::cpcall cpcall;
            type::createtable createtable;
            type::dump dump;
            type::equal equal;
            type::error error;
            type::gc gc;
            type::getallocf getallocf;
            type::getfenv getfenv;
            type::getfield getfield;
            type::gethook gethook;
            type::gethookcount gethookcount;
            type::gethookmask gethookmask;
            type::getinfo getinfo;
            type::getlocal getlocal;
            type::getmetatable getmetatable;
            type::getstack getstack;
            type::gettable gettable;
            type::gettop gettop;
            type::getupvalue getupvalue;
            type::insert insert;
            type::iscfunction iscfunction;
            type::isnumber isnumber;
            type::isstring isstring;
            type::isuserdata isuserdata;
            type::isyieldable isyieldable;
            type::lessthan lessthan;
            type::load load;
            type::loadx loadx;
            type::newstate newstate;
            type::newthread newthread;
            type::newuserdata newuserdata;
            type::next next;
            type::objlen objlen;
            type::pcall pcall;
            type::pushboolean pushboolean;
            type::pushcclosure pushcclosure;
            type::pushfstring pushfstring;
            type::pushinteger pushinteger;
            type::pushlightuserdata pushlightuserdata;
            type::pushlstring pushlstring;
            type::pushnil pushnil;
            type::pushnumber pushnumber;
            type::pushstring pushstring;
            type::pushthread pushthread;
            type::pushvalue pushvalue;
            type::pushvfstring pushvfstring;
            type::rawequal rawequal;
            type::rawget rawget;
            type::rawgeti rawgeti;
            type::rawset rawset;
            type::rawseti rawseti;
            type::remove remove;
            type::replace replace;
            type::setallocf setallocf;
            type::setfenv setfenv;
            type::setfield setfield;
            type::sethook sethook;
            type::setlocal setlocal;
            type::setmetatable setmetatable;
            type::settable settable;
            type::settop settop;
            type::setupvalue setupvalue;
            type::status status;
            type::toboolean toboolean;
            type::tocfunction tocfunction;
            type::tointeger tointeger;
            type::tointegerx tointegerx;
            type::tolstring tolstring;
            type::tonumber tonumber;
            type::tonumberx tonumberx;
            type::topointer topointer;
            type::tothread tothread;
            type::touserdata touserdata;
            type::gettype gettype;
            type::gettypename gettypename;
            type::upvalueid upvalueid;
            type::upvaluejoin upvaluejoin;
            type::version version;
            type::xmove xmove;
            type::yield yield;

            #ifdef INTERSTELLAR_EXTERNAL
            #define include(hndle, name, offset) \
                    { void* f = grab(hndle, "lua_" #name); if (f == NULL) { printf("[Interstellar] couldn't locate lua_" #name "\n"); return offset; } name = cast<type::name>(f); offset++; }

            #define includeA(hndle, real, name, offset) \
                    { void* f = grab(hndle, "lua_" #real); if (f == NULL) { printf("[Interstellar] couldn't locate lua_" #real "\n"); return offset; } name = cast<type::name>(f); offset++; }
            #else
            #define include(hndle, name, offset) \
                    name = cast<type::name>(Engine::lua_##name);

            #define includeA(hndle, real, name, offset) \
                    name = cast<type::name>(Engine::lua_##real);
            #endif

            int fetch(UMODULE hndle)
            {
                int start = 1;

                include(hndle, atpanic, start);
                include(hndle, call, start);
                include(hndle, checkstack, start);
                include(hndle, close, start);
                include(hndle, concat, start);
                /*#ifndef __linux
                    include(hndle, copy, start);
                #endif*/
                include(hndle, cpcall, start);
                include(hndle, createtable, start);
                include(hndle, dump, start);
                include(hndle, equal, start);
                include(hndle, error, start);
                include(hndle, gc, start);
                include(hndle, getallocf, start);
                include(hndle, getfenv, start);
                include(hndle, getfield, start);
                include(hndle, gethook, start);
                include(hndle, gethookcount, start);
                include(hndle, gethookmask, start);
                include(hndle, getinfo, start);
                include(hndle, getlocal, start);
                include(hndle, getmetatable, start);
                include(hndle, getstack, start);
                include(hndle, gettable, start);
                include(hndle, gettop, start);
                include(hndle, getupvalue, start);
                include(hndle, insert, start);
                include(hndle, iscfunction, start);
                include(hndle, isnumber, start);
                include(hndle, isstring, start);
                include(hndle, isuserdata, start);
                /*#ifndef __linux
                    include(hndle, isyieldable, start);
                #endif*/
                include(hndle, lessthan, start);
                include(hndle, load, start);
                include(hndle, loadx, start);
                include(hndle, newstate, start);
                include(hndle, newthread, start);
                include(hndle, newuserdata, start);
                include(hndle, next, start);
                include(hndle, objlen, start);
                include(hndle, pcall, start);
                include(hndle, pushboolean, start);
                include(hndle, pushcclosure, start);
                include(hndle, pushfstring, start);
                include(hndle, pushinteger, start);
                include(hndle, pushlightuserdata, start);
                include(hndle, pushlstring, start);
                include(hndle, pushnil, start);
                include(hndle, pushnumber, start);
                include(hndle, pushstring, start);
                include(hndle, pushthread, start);
                include(hndle, pushvalue, start);
                include(hndle, pushvfstring, start);
                include(hndle, rawequal, start);
                include(hndle, rawget, start);
                include(hndle, rawgeti, start);
                include(hndle, rawset, start);
                include(hndle, rawseti, start);
                include(hndle, remove, start);
                include(hndle, replace, start);
                include(hndle, setallocf, start);
                include(hndle, setfenv, start);
                include(hndle, setfield, start);
                include(hndle, sethook, start);
                include(hndle, setlocal, start);
                include(hndle, setmetatable, start);
                include(hndle, settable, start);
                include(hndle, settop, start);
                include(hndle, setupvalue, start);
                include(hndle, status, start);
                include(hndle, toboolean, start);
                include(hndle, tocfunction, start);
                include(hndle, tointeger, start);
                /*#ifndef __linux
                    include(hndle, tointegerx, start);
                #endif*/
                include(hndle, tolstring, start);
                include(hndle, tonumber, start);
                /*#ifndef __linux
                    include(hndle, tonumberx, start);
                #endif*/
                include(hndle, topointer, start);
                include(hndle, tothread, start);
                include(hndle, touserdata, start);
                includeA(hndle, type, gettype, start);
                includeA(hndle, typename, gettypename, start);
                include(hndle, upvalueid, start);
                include(hndle, upvaluejoin, start);
                /*#ifndef __linux
                    include(hndle, version, start);
                #endif*/
                include(hndle, xmove, start);
                include(hndle, yield, start);
                return 0;
            }

            std::string toastring(lua_State* L, int index)
            {
                lua::pushvalue(L, index);
                lua::pushvalue(L, indexer::global);
                lua::getfield(L, -1, "tostring");
                lua::remove(L, -2);
                lua::insert(L, -2);

                if (lua::isfunction(L, -2)) {
                    if (lua::pcall(L, 1, 1, 0)) {
                        std::string err = lua::tocstring(L, -1);
                        lua::pop(L);
                        return err;
                    }

                    if (lua::isstring(L, -1)) {
                        std::string res = lua::tocstring(L, -1);
                        lua::pop(L);
                        return res;
                    }

                    lua::pop(L);

                    return "";
                }

                lua::pop(L, 2);

                return "";
            }

            bool isinteger(lua_State* L, int index)
            {
                if (!lua::isnumber(L, index)) return false;
                lua_Number num = lua::tonumber(L, index);

                // 2^53 - 1 (for doubles)
                constexpr lua_Number maximum = 9007199254740991.0;
                constexpr lua_Number minimum = -9007199254740991.0;

                if (num < minimum || num > maximum)
                    return false;

                lua_Number intpart;
                return std::modf(num, &intpart) == 0.0;
            }

            int trace(lua_State* L)
            {
                std::string msg = lua::tocstring(L, 1);
                luaL::traceback(L, L, msg.c_str(), 1);
                return 1;
            }

            int tcall(lua_State* L, int nargs, int nret) {
                int hpos = gettop(L) - nargs;
                int ret = 0;
                pushcfunction(L, trace);
                insert(L, hpos);
                ret = pcall(L, nargs, nret, hpos);
                remove(L, hpos);
                return ret;
            }

            std::string tocstring(lua_State* L, int index)
            {
                size_t size = 0;
                const char* str = tolstring(L, index, &size);
                return std::string(str, size);
            }

            void pushcstring(lua_State* L, std::string str)
            {
                pushlstring(L, str.c_str(), str.size());
            }

            void pushraw(lua_State* L, Engine::GCobj* data, uint32_t type)
            {
                using namespace Engine;
                lua::pushnil(L);
                TValue* value = lua::toraw(L, -1);
                if (type == 0) type = ~data->gch.gct;
                #if LJ_GC64
                    setgcreft(value->gcr, data, type);
                #else
                    setgcref(value->gcr, data); setitype(value, type);
                #endif
            }

            Engine::TValue* toraw(lua_State* L, int index)
            {
                using namespace Engine;
                TValue* base = L->base;
                if (index > 0) {
                    return (TValue*)(base + (index - 1));
                }
                else {
                    return (TValue*)(L->top + index);
                }
            }

            void setraw(lua_State* L, int index, Engine::GCobj* data, uint32_t type)
            {
                using namespace Engine;
                TValue* base = L->base;
                TValue* value;
                if (index > 0) {
                    value = (TValue*)(base + (index - 1));
                }
                else {
                    value = (TValue*)(L->top + index);
                }

                if (type == 0) type = ~data->gch.gct;
                
                #if LJ_GC64
                    setgcreft(value->gcr, data, type);
                #else
                    setgcref(value->gcr, data); setitype(value, type);
                #endif
            }

            void pushref(lua_State* L, int reference) {
                lua::rawgeti(L, indexer::registry, reference);
            }

            void getcfield(lua_State* L, int index, std::string str)
            {
                pushlstring(L, str.c_str(), str.size());
                gettable(L, index > 0 ? index : index - 1);
            }

            void getrfield(lua_State* L, int index, const char* str)
            {
                pushstring(L, str);
                rawget(L, index > 0 ? index : index - 1);
            }

            void getcrfield(lua_State* L, int index, std::string str)
            {
                pushlstring(L, str.c_str(), str.size());
                rawget(L, index > 0 ? index : index - 1);
            }

            void setcfield(lua_State* L, int index, std::string str)
            {
                pushlstring(L, str.c_str(), str.size());
                insert(L, -2);
                settable(L, index > 0 ? index : index - 1);
            }

            void setrfield(lua_State* L, int index, const char* str)
            {
                pushstring(L, str);
                insert(L, -2);
                rawset(L, index > 0 ? index : index - 1);
            }

            void setcrfield(lua_State* L, int index, std::string str)
            {
                pushlstring(L, str.c_str(), str.size());
                insert(L, -2);
                rawset(L, index > 0 ? index : index - 1);
            }

            bool istype(lua_State* L, int index, int type)
            {
                return gettype(L, index) == type;
            }

            bool isnil(lua_State* L, int index)
            {
                int t = gettype(L, index);
                return t == datatype::nil || t == datatype::none;
            }

            bool isboolean(lua_State* L, int index)
            {
                return gettype(L, index) == datatype::boolean;
            }

            bool islightuserdata(lua_State* L, int index)
            {
                return gettype(L, index) == datatype::lightuserdata;
            }

            bool istable(lua_State* L, int index)
            {
                return gettype(L, index) == datatype::table;
            }

            bool isfunction(lua_State* L, int index)
            {
                return gettype(L, index) == datatype::function;
            }

            bool islfunction(lua_State* L, int index)
            {
                return gettype(L, index) == datatype::function && !lua::iscfunction(L, index);
            }

            bool isuserdatatype(lua_State* L, int index, int type) {
                if (gettype(L, index) != datatype::userdata) {
                    return false;
                }
                lua_udata data = (lua_udata)lua::touserdata(L, index);
                if (data.type != type) {
                    return false;
                }
                return true;
            }

            bool isproto(lua_State* L, int index)
            {
                return gettype(L, index) == datatype::proto;
            }

            bool isthread(lua_State* L, int index)
            {
                return gettype(L, index) == datatype::thread;
            }

            void newtable(lua_State* L)
            {
                createtable(L, 0, 0);
            }

            void pop(lua_State* L, int count)
            {
                for (int a = 0; a < count; a++) remove(L, -1);
            }

            void newuserdatatype(lua_State* L, void* data, size_t size, unsigned char type) {
                lua_udata* userdata = (lua_udata*)lua::newuserdata(L, sizeof(lua_udata));
                *userdata = {
                    data,
                    type
                };
            }

            void* touserdatatype(lua_State* L, int index) {
                lua_udata* userdata = (lua_udata*)lua::touserdata(L, index);
                return userdata->data;
            }

            void pushcfunction(lua_State* L, lua_CFunction f)
            {
                pushcclosure(L, f, 0);
            }

            char unique_tochar(int index) {
                if (index < 26) return 'a' + index; // 0-25: a-z
                else return 'A' + (index - 26); // 26-51: A-Z
            }

            std::string unique_char(unsigned int num) {
                std::string result;

                num--;

                while (true) {
                    int index = num % 52;
                    result = unique_tochar(index) + result;
                    if (num < 52) break;
                    num = (num / 52) - 1;
                }

                return result;
            }

            int blank(lua_State* L) { return 0; }
            void pushlfunction(lua_State* L, Engine::GCproto* proto, Engine::GCupval* upvptr, int upvalues)
            {
                using namespace Engine;

                if (upvptr == nullptr) {
                    upvalues = proto->sizeuv;
                }

                std::string nfc = "return function() ";
                for (uint8_t i = 0; i < upvalues; i++) {
                    std::string var = unique_char(i + 1);
                    nfc = "local " + var + " " + nfc + "local " + var + "=" + var + " ";
                }
                nfc = nfc + "end";
                luaL::loadbufferx(L, nfc.c_str(), nfc.size(), "", 0);
                lua::call(L, 0, 1);

                TValue* copy = lua::toraw(L, -1);
                GCfunc* gccopy = funcV(copy);

                setmref(gccopy->l.pc, proto_bc(proto));

                if (upvalues != 0 && upvptr != nullptr) {
                    memcpy(gccopy->l.uvptr, upvptr, sizeof(GCupval) * upvalues);
                }
            }

            void pushnfunction(lua_State* L, std::string name)
            {
                std::string nfc = "                      ";
                luaL::loadbufferx(L, nfc.c_str(), nfc.size(), name.c_str(), 0);
            }

            void getfunc(lua_State* L, int index)
            {
                int type = gettype(L, index);
                if (type != datatype::function && type != datatype::number) {
                    luaL::argerror(L, 1, "invalid function or level");
                }

                if (type == datatype::number)
                {
                    int level = tonumber(L, index);
                    if (index < 0) lua::remove(L, index);
                    lua_Debug ar;
                    if (!getstack(L, level, &ar))
                        luaL::argerror(L, 1, "invalid level");

                    getinfo(L, "f", &ar);

                    if (istype(L, -1, datatype::nil))
                        luaL::error(L, "no function environment for tail call at level %d", level);
                }
                else if (type == datatype::function)
                {
                    if (index < 0) lua::remove(L, index);
                    pushvalue(L, index);
                }
            }

            void getfunci(lua_State* L, int level)
            {
                lua_Debug ar;
                if (!getstack(L, level, &ar))
                    luaL::argerror(L, 1, "invalid level");

                getinfo(L, "f", &ar);

                if (istype(L, -1, datatype::nil))
                    luaL::error(L, "no function environment for tail call at level %d", level);
            }

            int upvalues(lua_State* L, int index) {
                luaL::checkfunction(L, index);

                lua_Debug ar;
                lua::pushvalue(L, index);
                if (lua::getinfo(L, ">u", &ar)) {
                    return 0;
                }

                return ar.nups;
            }

            std::string typestack(lua_State* L, int count, int offset)
            {
                std::string stack;
                for (int i = 0; i < count; i++)
                {
                    int id = -(i + 1 + offset);
                    if (i > 0) stack += "\n";
                    stack += std::to_string(id) + ": " + std::string(lua::gettypename(L, lua::gettype(L, id)));
                }
                return stack;
            }
        }

        // luaopen functions
        namespace luaopen
        {
            type::base base;
            type::bit bit;
            type::debug debug;
            type::jit jit;
            type::math math;
            type::os os;
            type::package package;
            type::string string;
            type::table table;

            #ifdef INTERSTELLAR_EXTERNAL
            #define include(hndle, name, offset) \
                    { void* f = grab(hndle, "luaopen_" #name); if (f == NULL) { printf("[Interstellar] couldn't locate luaopen_" #name "\n"); return offset; } name = cast<type::name>(f); offset++; }

            #define includeA(hndle, real, name, offset) \
                    { void* f = grab(hndle, "luaopen_" #real); if (f == NULL) { printf("[Interstellar] couldn't locate luaopen_" #real "\n"); return offset; } name = cast<type::name>(f); offset++; }
            #else
            #define include(hndle, name, offset) \
                    name = cast<type::name>(Engine::luaopen_##name);

            #define includeA(hndle, real, name, offset) \
                    name = cast<type::name>(Engine::luaopen_##real);
            #endif

            int fetch(UMODULE hndle)
            {
                int start = 1;
                include(hndle, base, start);
                include(hndle, bit, start);
                include(hndle, debug, start);
                include(hndle, jit, start);
                include(hndle, math, start);
                include(hndle, os, start);
                include(hndle, package, start);
                include(hndle, string, start);
                include(hndle, table, start);
                return 0;
            }
        }

        int fetch(UMODULE hndle)
        {
            int ret = luaL::fetch(hndle); if (ret != 0) return ret;
            ret = lua::fetch(hndle); if (ret != 0) return ret;
            ret = luaopen::fetch(hndle); if (ret != 0) return ret;
            return 0;
        }
    }

    using namespace API;

    namespace Tracker {
        Signal::Handle* signal;

        std::unordered_map<std::string, lua_Closure>& get_opening() {
            static std::unordered_map<std::string, lua_Closure> m;
            return m;
        }

        std::unordered_map<std::string, lua_Closure>& get_closing() {
            static std::unordered_map<std::string, lua_Closure> m;
            return m;
        }

        std::unordered_map<uintptr_t, state_tracking*>& get_mapping() {
            static std::unordered_map<uintptr_t, state_tracking*> m;
            return m;
        }

        std::unordered_map<std::string, state_tracking*>& get_imapping() {
            static std::unordered_map<std::string, state_tracking*> m;
            return m;
        }

        static std::shared_ptr<std::mutex> access_mtx;
        static std::shared_ptr<std::mutex> global_mtx;
        static std::unique_ptr<std::unique_lock<std::mutex>> global_lock;
        std::atomic<unsigned int> expecting;

        void increment()
        {
            expecting++;
        }

        void decrement()
        {
            if (expecting == 0) return;
            expecting--;
        }

        void runtime()
        {
            global_lock->unlock();
            while (expecting > 0) {}
            global_lock->lock();
        }

        uintptr_t id(lua_State* L) {
            return (uintptr_t)L;
        }

        state_tracking* get_tracker(lua_State* L)
        {
            std::lock_guard<std::mutex> guard(*access_mtx);
            uintptr_t id = (uintptr_t)L;
            auto& mapping = get_mapping();
            auto res = mapping.find(id);
            if (res == mapping.end()) return nullptr;
            return res->second;
        }

        state_tracking* get_tracker(void* L)
        {
            std::lock_guard<std::mutex> guard(*access_mtx);
            uintptr_t id = (uintptr_t)L;
            auto& mapping = get_mapping();
            auto res = mapping.find(id);
            if (res == mapping.end()) return nullptr;
            return res->second;
        }

        state_tracking* get_tracker(uintptr_t L)
        {
            std::lock_guard<std::mutex> guard(*access_mtx);
            auto& mapping = get_mapping();
            auto res = mapping.find(L);
            if (res == mapping.end()) return nullptr;
            return res->second;
        }

        state_tracking* get_tracker(std::string name)
        {
            std::lock_guard<std::mutex> guard(*access_mtx);
            auto& imapping = get_imapping();
            auto res = imapping.find(name);
            if (res == imapping.end()) return nullptr;
            return res->second;
        }

        lua_State* is_state(lua_State* L) {
            std::lock_guard<std::mutex> guard(*access_mtx);
            uintptr_t id = (uintptr_t)L;
            auto& mapping = get_mapping();
            if (mapping.find(id) == mapping.end()) return nullptr;
            return (lua_State*)L;
        }

        lua_State* is_state(uintptr_t L) {
            std::lock_guard<std::mutex> guard(*access_mtx);
            auto& mapping = get_mapping();
            if (mapping.find(L) == mapping.end()) return nullptr;
            return (lua_State*)L;
        }

        lua_State* is_state(void* L) {
            std::lock_guard<std::mutex> guard(*access_mtx);
            uintptr_t id = (uintptr_t)L;
            auto& mapping = get_mapping();
            if (mapping.find(id) == mapping.end()) return nullptr;
            return (lua_State*)L;
        }

        lua_State* is_state(std::string name) {
            std::lock_guard<std::mutex> guard(*access_mtx);
            auto& imapping = get_imapping();
            auto res = imapping.find(name);
            if (res == imapping.end()) return nullptr;
            return res->second->state.self;
        }

        lua_State* get_root()
        {
            std::lock_guard<std::mutex> guard(*access_mtx);
            auto& mapping = get_mapping();
            for (auto& entry : mapping) {
                if (entry.second->root) {
                    return entry.second->state.self;
                }
            }
            return nullptr;
        }

        bool is_root(lua_State* L)
        {
            state_tracking* tracker = get_tracker(L);
            if (tracker != nullptr) {
                return tracker->root;
            }
            return false;
        }

        bool is_root(void* L)
        {
            state_tracking* tracker = get_tracker(L);
            if (tracker != nullptr) {
                return tracker->root;
            }
            return false;
        }

        bool is_root(uintptr_t L)
        {
            state_tracking* tracker = get_tracker(L);
            if (tracker != nullptr) {
                return tracker->root;
            }
            return false;
        }

        bool is_root(std::string name)
        {
            state_tracking* tracker = get_tracker(name);
            if (tracker != nullptr) {
                return tracker->root;
            }
            return false;
        }

        bool is_internal(lua_State* L)
        {
            state_tracking* tracker = get_tracker(L);
            if (tracker != nullptr) {
                return tracker->internal;
            }
            return false;
        }

        bool is_internal(void* L)
        {
            state_tracking* tracker = get_tracker(L);
            if (tracker != nullptr) {
                return tracker->internal;
            }
            return false;
        }

        bool is_internal(uintptr_t L)
        {
            state_tracking* tracker = get_tracker(L);
            if (tracker != nullptr) {
                return tracker->internal;
            }
            return false;
        }

        bool is_internal(std::string name)
        {
            state_tracking* tracker = get_tracker(name);
            if (tracker != nullptr) {
                return tracker->internal;
            }
            return false;
        }

        bool is_threaded(lua_State* L)
        {
            state_tracking* tracker = get_tracker(L);
            if (tracker != nullptr) {
                return tracker->threaded;
            }
            return false;
        }

        bool is_threaded(void* L)
        {
            state_tracking* tracker = get_tracker(L);
            if (tracker != nullptr) {
                return tracker->threaded;
            }
            return false;
        }

        bool is_threaded(uintptr_t L)
        {
            state_tracking* tracker = get_tracker(L);
            if (tracker != nullptr) {
                return tracker->threaded;
            }
            return false;
        }

        bool is_threaded(std::string name)
        {
            state_tracking* tracker = get_tracker(name);
            if (tracker != nullptr) {
                return tracker->threaded;
            }
            return false;
        }

        bool should_lock(lua_State* target, lua_State* source)
        {
            return target != source && (Tracker::is_threaded(target) || Tracker::is_threaded(target) != Tracker::is_threaded(source));
        }

        std::string get_name(lua_State* L)
        {
            std::lock_guard<std::mutex> guard(*access_mtx);
            uintptr_t id = (uintptr_t)L;
            auto& mapping = get_mapping();
            auto res = mapping.find(id);
            if (res != mapping.end()) {
                return res->second->name;
            }
            return "";
        }

        std::vector<std::pair<std::string, lua_State*>> get_states() {
            std::lock_guard<std::mutex> guard(*access_mtx);
            std::vector<std::pair<std::string, lua_State*>> list;

            auto& mapping = get_mapping();
            for (auto& object : mapping) {
                std::string name = object.second->name;
                lua_State* L = object.second->state.self;
                list.push_back(std::pair<std::string, lua_State*>(name, L));
            }

            return list;
        }

        // since cross-states should be able to talk back and forth
        static std::mutex global_cross_mutex;

        std::unordered_map<uintptr_t, unsigned int>& get_cross_trace() {
            static std::unordered_map<uintptr_t, unsigned int> m;
            return m;
        }

        std::unordered_map<uintptr_t, std::unique_ptr<std::unique_lock<std::mutex>>>& get_cross_locks() {
            static std::unordered_map<uintptr_t, std::unique_ptr<std::unique_lock<std::mutex>>> m;
            return m;
        }

        void cross_lock(lua_State* target, lua_State* source)
        {
            std::scoped_lock lock(global_cross_mutex);

            auto target_tracker = get_tracker(target);
            auto target_ptr = target_tracker->state.pointer;
            auto source_ptr = get_tracker(source)->state.pointer;

            auto& cross_trace = get_cross_trace();
            auto& cross_locks = get_cross_locks();

            if (cross_trace[target_ptr] == 0) {
                auto mutex = target_tracker->mutex;
                auto guard = std::make_unique<std::unique_lock<std::mutex>>(*mutex);
                cross_locks[target_ptr] = std::move(guard);
            }

            cross_trace[target_ptr]++;
            cross_trace[source_ptr]++;
        }

        void cross_unlock(lua_State* target, lua_State* source)
        {
            std::scoped_lock lock(global_cross_mutex);

            auto target_ptr = get_tracker(target)->state.pointer;
            auto source_ptr = get_tracker(source)->state.pointer;

            auto& cross_trace = get_cross_trace();
            auto& cross_locks = get_cross_locks();

            if (--cross_trace[target_ptr] == 0) {
                cross_locks.erase(target_ptr);
            }

            if (--cross_trace[source_ptr] == 0) {
                cross_locks.erase(source_ptr);
            }
        }

        std::unique_lock<std::mutex> lock(lua_State* L)
        {
            state_tracking* tracker = get_tracker(L);
            if (tracker == nullptr) {
                return std::unique_lock<std::mutex>();
            }
            return std::unique_lock<std::mutex>(*tracker->mutex);
        }

        std::unique_lock<std::mutex> lock(void* L)
        {
            state_tracking* tracker = get_tracker(L);
            if (tracker == nullptr) {
                return std::unique_lock<std::mutex>();
            }
            return std::unique_lock<std::mutex>(*tracker->mutex);
        }

        std::unique_lock<std::mutex> lock(uintptr_t L)
        {
            state_tracking* tracker = get_tracker(L);
            if (tracker == nullptr) {
                return std::unique_lock<std::mutex>();
            }
            return std::unique_lock<std::mutex>(*tracker->mutex);
        }

        std::unique_lock<std::mutex> lock(std::string name)
        {
            state_tracking* tracker = get_tracker(name);
            if (tracker == nullptr) {
                return std::unique_lock<std::mutex>();
            }
            return std::unique_lock<std::mutex>(*tracker->mutex);
        }

        void listen(lua_State* L, std::string name, bool internal)
        {
            uintptr_t id = (uintptr_t)L;

            if (name.size() > 0) {
                state_tracking* tracker = new state_tracking();
                tracker->threaded = false;
                tracker->internal = internal;
                tracker->name = name;
                tracker->state.self = L;
                tracker->mutex = global_mtx;

                auto& mapping = get_mapping();
                auto& imapping = get_imapping();

                std::unique_lock<std::mutex> guard_access(*access_mtx);
                mapping.emplace(id, tracker);
                imapping.emplace(name, tracker);
                if (guard_access.owns_lock()) guard_access.unlock(); guard_access.release();

                if (mapping.size() == 1) {
                    tracker->root = true;
                }

                auto& dispatch = get_opening();
                for (auto& [key, callback] : dispatch) {
                    callback(L);
                }

                for (auto& state : Tracker::get_states()) {
                    lua_State* S = state.second;

                    if (S == L) continue;

                    std::unique_lock<std::mutex> guard;
                    bool threaded = Tracker::is_threaded(S);
                    if (threaded) {
                        guard = Tracker::lock(S);
                    }

                    if (!signal->has(S, "open")) {
                        if (guard.owns_lock()) guard.unlock(); guard.release();
                        continue;
                    };

                    lua::pushcstring(S, name);
                    Reflection::push_state(S, L);
                    signal->fire(S, "open", 2);
                    if (guard.owns_lock()) guard.unlock(); guard.release();
                }
            }
        }

        void listen(lua_State* L, std::string name, std::shared_ptr<std::mutex> mtx, bool internal)
        {
            uintptr_t id = (uintptr_t)L;

            if (name.size() > 0) {
                state_tracking* tracker = new state_tracking();
                tracker->threaded = true;
                tracker->internal = internal;
                tracker->name = name;
                tracker->state.self = L;
                tracker->mutex = mtx;

                auto& mapping = get_mapping();
                auto& imapping = get_imapping();

                std::unique_lock<std::mutex> guard_access(*access_mtx);
                mapping.emplace(id, tracker);
                imapping.emplace(name, tracker);
                if (guard_access.owns_lock()) guard_access.unlock(); guard_access.release();

                if (mapping.size() == 1) {
                    tracker->root = true;
                }

                auto& dispatch = get_opening();
                for (auto& [key, callback] : dispatch) {
                    callback(L);
                }

                for (auto& state : Tracker::get_states()) {
                    lua_State* S = state.second;

                    if (S == L) continue;

                    std::unique_lock<std::mutex> guard;
                    bool threaded = Tracker::is_threaded(S);
                    if (threaded) {
                        guard = Tracker::lock(S);
                    }

                    if (!signal->has(S, "open")) {
                        if (guard.owns_lock()) guard.unlock(); guard.release();
                        continue;
                    };

                    lua::pushcstring(S, name);
                    Reflection::push_state(S, L);
                    signal->fire(S, "open", 2);
                    if (guard.owns_lock()) guard.unlock(); guard.release();
                }
            }
        }

        inline void _destruct(state_tracking* tracker)
        {
            if (tracker == nullptr) return;

            std::string name = tracker->name;
            lua_State* L = tracker->state.self;
            for (auto& state : Tracker::get_states()) {
                lua_State* S = state.second;

                if (S == L) continue;

                std::unique_lock<std::mutex> guard;
                bool threaded = Tracker::is_threaded(S);
                if (threaded) {
                    guard = Tracker::lock(S);
                }

                if (!signal->has(S, "open")) {
                    if (guard.owns_lock()) guard.unlock(); guard.release();
                    continue;
                };

                lua::pushcstring(S, name);
                Reflection::push_state(S, L);
                signal->fire(S, "open", 2);
                if (guard.owns_lock()) guard.unlock(); guard.release();
            }

            auto& mapping = get_mapping();
            auto& imapping = get_imapping();

            std::lock_guard<std::mutex> guard(*access_mtx);
            mapping.erase(tracker->state.pointer);
            imapping.erase(tracker->name);
            delete tracker;
        }

        void destroy(lua_State* L)
        {
            _destruct(get_tracker(L));
        }

        void destroy(uintptr_t L)
        {
            _destruct(get_tracker(L));
        }

        void destroy(void* L)
        {
            _destruct(get_tracker(L));
        }

        void destroy(std::string name)
        {
            _destruct(get_tracker(name));
        }

        void pre_remove(lua_State* L) {
            destroy(L);

            auto& dispatch = get_closing();
            for (auto& [key, callback] : dispatch) {
                callback(L);
            }
        }

        void post_remove(lua_State* L) {
            Class::cleanup(L);
        }

        void on_open(std::string name, lua_Closure callback)
        {
            auto& dispatch = get_opening();
            dispatch.emplace(name, callback);
        }

        void on_close(std::string name, lua_Closure callback)
        {
            auto& dispatch = get_closing();
            dispatch.emplace(name, callback);
        }

        inline void init()
        {
            signal = Signal::create();
            access_mtx = std::make_shared<std::mutex>();
            global_mtx = std::make_shared<std::mutex>();
            global_lock = std::make_unique<std::unique_lock<std::mutex>>(*global_mtx);
            global_lock->unlock();
            global_lock->lock();
        }
    }

    namespace Class {
        std::unordered_map<uintptr_t, std::vector<class_store>> mapping;
        std::unordered_map<uintptr_t, unsigned char> offsets;

        bool existsbyname(lua_State* L, std::string name)
        {
            uintptr_t id = Tracker::id(L);

            if (mapping.find(id) == mapping.end()) {
                return false;
            }

            for (auto& entry : mapping[id]) {
                if (entry.name == name) {
                    return true;
                }
            }

            return false;
        }

        class_store getbyname(lua_State* L, std::string name)
        {
            uintptr_t id = Tracker::id(L);

            if (mapping.find(id) == mapping.end()) {
                return {};
            }

            for (auto& entry : mapping[id]) {
                if (entry.name == name) {
                    return entry;
                }
            }

            return {};
        }

        bool existsbytype(lua_State* L, unsigned char type)
        {
            uintptr_t id = Tracker::id(L);

            if (mapping.find(id) == mapping.end()) {
                return false;
            }

            for (auto& entry : mapping[id]) {
                if (entry.type == type) {
                    return true;
                }
            }

            return false;
        }

        class_store getbytype(lua_State* L, unsigned char type)
        {
            uintptr_t id = Tracker::id(L);

            if (mapping.find(id) == mapping.end()) {
                return {};
            }

            for (auto& entry : mapping[id]) {
                if (entry.type == type) {
                    return entry;
                }
            }

            return {};
        }

        bool existsbyreference(lua_State* L, int reference)
        {
            uintptr_t id = Tracker::id(L);

            if (mapping.find(id) == mapping.end()) {
                return false;
            }

            for (auto& entry : mapping[id]) {
                if (entry.reference == reference) {
                    return true;
                }
            }

            return false;
        }

        class_store getbyreference(lua_State* L, int reference)
        {
            uintptr_t id = Tracker::id(L);

            if (mapping.find(id) == mapping.end()) {
                return {};
            }

            for (auto& entry : mapping[id]) {
                if (entry.reference == reference) {
                    return entry;
                }
            }

            return {};
        }

        unsigned char create(lua_State* L, std::string name)
        {
            uintptr_t id = Tracker::id(L);
            lua::newtable(L);
            lua::pushvalue(L, -1);
            int reference = luaL::newref(L, -1);

            if (offsets[id] == 0)
                offsets[id] = 51;
            unsigned char type = offsets[id]++;

            class_store entry = {
                name,
                type,
                reference
            };

            if (mapping.find(id) == mapping.end()) {
                mapping[id] = std::vector<class_store>();
            }

            mapping[id].push_back(entry);

            lua::pushcstring(L, name);
            lua::setfield(L, -2, "__class");

            lua::pushnumber(L, type);
            lua::setfield(L, -2, "__type");

            lua::pushnumber(L, reference);
            lua::setfield(L, -2, "__reference");

            return type;
        }

        void inherits(lua_State* L, std::string name, int index) {
            class_store other = getbyname(L, name);
            if (other.reference == 0) return;
            if (!lua::istable(L, index)) return;
            lua::pushvalue(L, index);

            lua::getfield(L, -1, "__index");
            if (lua::istable(L, -1)) {
                lua::pushref(L, other.reference);
                lua::setmetatable(L, -2);
            }
            else if (lua::isnil(L, -1)) {
                lua::pop(L);
                lua::newtable(L);
                lua::pushref(L, other.reference);
                lua::setmetatable(L, -2);
                lua::pushvalue(L, -1);
                lua::setfield(L, -2, "__index");
            }
            lua::pop(L);

            lua::pushref(L, other.reference);
            lua::setfield(L, -2, "__inheritance");

            lua::pop(L);
        }

        bool metatable(lua_State* L, unsigned char type) {
            class_store handle = getbytype(L, type);

            if (handle.reference == 0) {
                return false;
            }

            lua::pushref(L, handle.reference);

            return true;
        }

        bool metatable(lua_State* L, std::string name) {
            class_store handle = getbyname(L, name);

            if (handle.reference == 0) {
                return false;
            }

            lua::pushref(L, handle.reference);

            return true;
        }

        void spawn(lua_State* L, void* data, unsigned char type) {
            class_store handle = getbytype(L, type);

            class_udata* udata = (class_udata*)lua::newuserdata(L, sizeof(class_udata));
            *udata = { data, handle.type };

            if (handle.reference != 0) {
                lua::pushref(L, handle.reference);
                lua::setmetatable(L, -2);
            }
        }

        void spawn_weak(lua_State* L, void* data, unsigned char type) {
            class_store handle = getbytype(L, type);

            class_udata* udata = (class_udata*)lua::newuserdata(L, sizeof(class_udata));
            *udata = { data, handle.type };

            if (handle.reference != 0) {
                lua::newtable(L);
                lua::pushref(L, handle.reference);

                if (lua::istable(L, -1)) {
                    lua::pushnil(L);
                    while (lua::next(L, -2)) {
                        lua::pushvalue(L, -2);
                        lua::insert(L, -2);
                        lua::settable(L, -5);
                    }
                }
                lua::pop(L);
                lua::setmetatable(L, -2);
            }
        }

        void spawn_store(lua_State* L, void* data, unsigned char type) {
            class_store handle = getbytype(L, type);

            class_udata* udata = (class_udata*)lua::newuserdata(L, sizeof(class_udata));
            *udata = { data, handle.type };

            if (handle.reference != 0) {
                lua::newtable(L);
                lua::pushref(L, handle.reference);

                if (lua::istable(L, -1)) {
                    lua::pushnil(L);
                    while (lua::next(L, -2)) {
                        lua::pushvalue(L, -2);
                        lua::insert(L, -2);
                        lua::settable(L, -5);
                    }
                }
                lua::pop(L);

                lua::newtable(L);

                lua::pushvalue(L, -1);
                lua::setfield(L, -3, "__store");

                lua::pushvalue(L, -1);
                lua::pushref(L, handle.reference);
                lua::setmetatable(L, -2);
                lua::setfield(L, -3, "__index");

                lua::pushvalue(L, -1);
                lua::pushref(L, handle.reference);
                lua::setmetatable(L, -2);
                lua::setfield(L, -3, "__newindex");

                // TODO: push a cfunction here to get the true table of this...
                
                lua::pop(L);

                lua::setmetatable(L, -2);
            }
        }

        void spawn(lua_State* L, void* data, std::string name) {
            class_store handle = getbyname(L, name);

            class_udata* udata = (class_udata*)lua::newuserdata(L, sizeof(class_udata));
            *udata = { data, handle.type };
            
            if (handle.reference != 0) {
                lua::pushref(L, handle.reference);
                lua::setmetatable(L, -2);
            }
        }

        void spawn_weak(lua_State* L, void* data, std::string name) {
            class_store handle = getbyname(L, name);

            class_udata* udata = (class_udata*)lua::newuserdata(L, sizeof(class_udata));
            *udata = { data, handle.type };

            if (handle.reference != 0) {
                lua::newtable(L);
                lua::pushref(L, handle.reference);

                if (lua::istable(L, -1)) {
                    lua::pushnil(L);
                    while (lua::next(L, -2)) {
                        lua::pushvalue(L, -2);
                        lua::insert(L, -2);
                        lua::settable(L, -5);
                    }
                }
                lua::pop(L);
                lua::setmetatable(L, -2);
            }
        }

        void spawn_store(lua_State* L, void* data, std::string name) {
            class_store handle = getbyname(L, name);

            class_udata* udata = (class_udata*)lua::newuserdata(L, sizeof(class_udata));
            *udata = { data, handle.type };

            if (handle.reference != 0) {
                lua::newtable(L);
                lua::pushref(L, handle.reference);

                if (lua::istable(L, -1)) {
                    lua::pushnil(L);
                    while (lua::next(L, -2)) {
                        lua::pushvalue(L, -2);
                        lua::insert(L, -2);
                        lua::settable(L, -5);
                    }
                }
                lua::pop(L);

                lua::newtable(L);

                lua::pushvalue(L, -1);
                lua::setfield(L, -3, "__store");

                lua::pushvalue(L, -1);
                lua::pushref(L, handle.reference);
                lua::setmetatable(L, -2);
                lua::setfield(L, -3, "__index");

                lua::pushvalue(L, -1);
                lua::pushref(L, handle.reference);
                lua::setmetatable(L, -2);
                lua::setfield(L, -3, "__newindex");

                // TODO: push a cfunction here to get the true table of this...

                lua::pop(L);

                lua::setmetatable(L, -2);
            }
        }

        bool is(lua_State* L, int index, unsigned char type) {
            if (!lua::isuserdata(L, index)) {
                return false;
            }

            class_udata* udata = (class_udata*)lua::touserdata(L, index);

            if (udata == nullptr) return false;

            return udata->type == type;
        }

        bool is(lua_State* L, int index, std::string name) {
            if (!lua::isuserdata(L, index)) {
                return false;
            }

            class_udata* udata = (class_udata*)lua::touserdata(L, index);

            if (udata == nullptr) return false;

            class_store handle = getbyname(L, name);

            return udata->type == handle.type;
        }

        void* to(lua_State* L, int index)
        {
            class_udata* udata = (class_udata*)lua::touserdata(L, index);
            return udata->data;
        }

        void* check(lua_State* L, int index, unsigned char type)
        {
            class_udata* udata = (class_udata*)luaL::checkuserdata(L, index);
            class_store handle = getbytype(L, type);
            if (udata->type != handle.type) {
                luaL::error(L, "invalid userdata class, expected %s", handle.name.c_str());
                return nullptr;
            }
            return udata->data;
        }

        void* check(lua_State* L, int index, std::string name)
        {
            class_udata* udata = (class_udata*)luaL::checkuserdata(L, index);
            class_store handle = getbyname(L, name);
            if (udata->type != handle.type) {
                luaL::error(L, "invalid userdata class, expected %s", handle.name.c_str());
                return nullptr;
            }
            return udata->data;
        }

        void cleanup(lua_State* L)
        {
            uintptr_t id = Tracker::id(L);
            mapping.erase(id);
            offsets.erase(id);
        }
    }

    namespace Reflection {
        int transfer_table(lua_State* from, lua_State* to, int source, bool no_error)
        {
            lua::newtable(to);

            lua::pushvalue(from, source);
            lua::pushnil(from);

            while (lua::next(from, -2) != 0) {
                // TODO: we need to add a check for cyclic tables!
                if (lua::istable(from, -1)) {
                    if (lua::rawequal(from, -1, -3)) {
                        lua::pop(from, 1);
                        continue;
                    }
                }

                int err = transfer(from, to, -2, no_error);
                if (err != 0) {
                    lua::pop(from, 2);
                    lua::pop(to, 1);
                    return err;
                }

                err = transfer(from, to, -1, no_error);
                if (err != 0) {
                    lua::pop(from, 2);
                    lua::pop(to, 2);
                    return err;
                }

                lua::settable(to, -3);

                lua::pop(from, 1);
            }

            lua::pop(from, 1);

            return 0;
        }

        int transfer(lua_State* from, lua_State* to, int index, bool no_error)
        {
            int type = lua::gettype(from, index);

            switch (type)
            {
            case datatype::nil: {
                lua::pushnil(to);
                break;
            }
            case datatype::number: {
                lua::pushnumber(to, lua::tonumber(from, index));
                break;
            }
            case datatype::string: {
                lua::pushcstring(to, lua::tocstring(from, index));
                break;
            }
            case datatype::boolean: {
                lua::pushboolean(to, lua::toboolean(from, index));
                break;
            }
            case datatype::proto: {
                using namespace Engine;
                TValue* value = lua::toraw(from, index);
                GCproto* object = protoV(value);

                lua::pushnil(to); // TODO: prototype transfering, probably gonna have to do some alloc resize here with GC...

                break;
            }
            case datatype::function: {
                using namespace Engine;
                TValue* value = lua::toraw(from, index);
                GCfunc* object = funcV(value);

                if (object->l.ffid == FF_LUA) {
                    std::string fname = ""; // TODO: placeholder for now
                    std::string btcode = luaL::dump(from, index);

                    std::string err = Reflection::compile(to, btcode, fname);

                    if (err.size() > 0) {
                        if (no_error) {
                            return type;
                        }
                        luaL::error(to, (std::string() + "reflection transfer error: " + lua::gettypename(from, type) + " -> " + err).c_str());
                        break;
                    }
                    
                    lua_Debug ar;
                    lua::pushvalue(from, index);
                    if (lua::getinfo(from, ">u", &ar) && ar.nups > 0) {
                        for (int i = 1; i <= ar.nups; ++i) {
                            const char* name = lua::getupvalue(from, index, i);
                            if (name == nullptr) break;
                            int err = transfer(from, to, -1, no_error);
                            lua::pop(from);
                            if (err != 0) {
                                return err;
                            }
                            lua::setupvalue(to, -2, i);
                        }
                    }
                }
                else {
                    lua_Debug ar;
                    size_t upvalues = 0;
                    lua::pushvalue(from, index);
                    if (lua::getinfo(from, ">u", &ar) && ar.nups > 0) {
                        upvalues = ar.nups;

                        for (int i = 1; i <= upvalues; ++i) {
                            const char* name = lua::getupvalue(from, index, i);
                            if (name == nullptr) break;
                            int err = transfer(from, to, -1, no_error);
                            lua::pop(from);
                            if (err != 0) {
                                lua::pop(to, i);
                                return err;
                            }
                        }
                    }

                    lua::pushcclosure(to, object->c.f, upvalues);
                }

                break;
            }
            case datatype::userdata: {
                using namespace Engine;
                TValue* value = lua::toraw(from, index);
                GCobj* object = gcval(value);
                MSize len = object->ud.len;

                void* data = lua::touserdata(from, index);
                void* udata = (void*)lua::newuserdata(to, len);
                memcpy(udata, data, len);

                TValue* tvalue = lua::toraw(to, -1);
                GCobj* tobject = gcval(tvalue);
                tobject->ud.udtype = object->ud.udtype;
                tobject->ud.unused2 = object->ud.unused2;
                break;
            }
            case datatype::table: {
                if (lua::getmetatable(from, index)) {
                    lua::pop(from);
                    lua::newtable(to);
                    return 0;
                }
                int err = transfer_table(from, to, index, no_error);
                if (err != 0) {
                    return err;
                }
                break;
            }
            default: {
                if (no_error) {
                    return type;
                }
                luaL::error(to, (std::string() + "reflection unsupported datatype: " + lua::gettypename(from, type)).c_str());
                break;
            }
            }

            return 0;
        }

        std::string compile(lua_State* L, std::string source, std::string name)
        {
            if (luaL::loadbufferx(L, source.c_str(), source.size(), name.c_str(), 0) != 0) {
                size_t size = 0;
                const char* error = lua::tolstring(L, -1, &size);
                lua::pop(L);
                return std::string(error, size);
            }

            push(L);
            lua::setfenv(L, -2);

            return "";
        }

        std::string execute(lua_State* L, std::string source, std::string name)
        {
            if (luaL::loadbufferx(L, source.c_str(), source.size(), name.c_str(), 0) != 0) {
                size_t size = 0;
                const char* error = lua::tolstring(L, -1, &size);
                lua::pop(L);
                return std::string(error, size);
            }

            push(L);
            lua::setfenv(L, -2);

            if (lua::tcall(L, 0, 0) != 0) {
                size_t size = 0;
                const char* error = lua::tolstring(L, -1, &size);
                lua::pop(L);
                return std::string(error, size);
            }

            return "";
        }

        std::unordered_map<std::string, lua_Threaded>& get_threaded()
        {
            static std::unordered_map<std::string, lua_Threaded> m;
            return m;
        }

        void on_threaded(std::string name, lua_Threaded callback)
        {
            auto& dispatch = get_threaded();
            dispatch.emplace(name, callback);
        }

        namespace Task {
            typedef void (*lua_Task_Error) (API::lua_State* L, std::string error);

            std::unordered_map<std::string, lua_Task_Error>& get_on_error()
            {
                static std::unordered_map<std::string, lua_Task_Error> m = std::unordered_map<std::string, lua_Task_Error>();
                return m;
            }

            void add_error(std::string name, lua_Task_Error callback)
            {
                auto& on_error = get_on_error();
                on_error.emplace(name, callback);
            }

            void remove_error(std::string name)
            {
                auto& on_error = get_on_error();
                on_error.erase(name);
            }

            std::unordered_set<lua_State*>& get_tracing()
            {
                static std::unordered_set<lua_State*> m;
                return m;
            }

            std::unordered_map<lua_State*, std::vector<int>>& get_defers()
            {
                static std::unordered_map<lua_State*, std::vector<int>> m;
                return m;
            }

            std::unordered_map<lua_State*, std::vector<std::pair<std::chrono::steady_clock::time_point, int>>>& get_timers()
            {
                static std::unordered_map<lua_State*, std::vector<std::pair<std::chrono::steady_clock::time_point, int>>> m;
                return m;
            }

            std::unique_ptr<std::mutex>& mtx()
            {
                static std::unique_ptr<std::mutex> mtx = std::make_unique<std::mutex>();
                return mtx;
            }

            void push(lua_State* L)
            {
                std::lock_guard<std::mutex> guard(*mtx());
                auto& in_threading = get_tracing();
                in_threading.emplace(L);
            }

            void pop(lua_State* L)
            {
                std::lock_guard<std::mutex> guard(*mtx());
                auto& in_threading = get_tracing();
                in_threading.erase(L);
            }

            int lis_threaded(lua_State* L)
            {
                std::lock_guard<std::mutex> guard(*mtx());
                auto& in_threading = get_tracing();
                lua::pushboolean(L, in_threading.find(L) != in_threading.end());
                return 1;
            }

            int ldefer(lua_State* L)
            {
                luaL::checkfunction(L, 1);
                std::lock_guard<std::mutex> guard(*mtx());
                auto& defers = get_defers();
                if (defers.find(L) == defers.end()) {
                    defers.emplace(L, std::vector<int>());
                }
                defers[L].push_back(luaL::newref(L, 1));
                return 0;
            }

            int ldelay(lua_State* L)
            {
                double delay = luaL::checknumber(L, 1);
                luaL::checkfunction(L, 2);
                std::lock_guard<std::mutex> guard(*mtx());
                auto& defers = get_timers();
                if (defers.find(L) == defers.end()) {
                    defers.emplace(L, std::vector<std::pair<std::chrono::steady_clock::time_point, int>>());
                }
                auto duration = std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                    std::chrono::duration<double>(delay)
                );
                defers[L].push_back(std::pair(std::chrono::steady_clock::now() + duration, luaL::newref(L, 2)));
                return 0;
            }

            Signal::Handle* signal()
            {
                static Signal::Handle* tasker = Signal::create();
                return tasker;
            }

            void runtime_threaded(lua_State* L)
            {
                static Signal::Handle* tasker = signal();
                auto lock = Tracker::lock(L);
                Task::push(L);

                std::unique_lock<std::mutex> guard(*mtx());

                auto& defers = get_defers();
                auto idefers = defers.find(L);
                if (idefers != defers.end()) {
                    auto& list = idefers->second;
                    for (int entry : list) {
                        lua::pushref(L, entry);
                        luaL::rmref(L, entry);

                        auto it = std::find(list.begin(), list.end(), entry);
                        if (it != list.end()) list.erase(it);

                        guard.unlock();
                        if (lua::tcall(L, 0, 0)) {
                            std::string err = lua::tocstring(L, -1);
                            lua::pop(L);
                            auto& on_error = get_on_error();
                            for (auto const& handle : on_error) handle.second(L, err);
                        }
                        guard.lock();
                    }
                }

                auto& timers = get_timers();
                auto itimers = timers.find(L);
                if (itimers != timers.end()) {
                    auto& list = itimers->second;
                    auto clock = std::chrono::steady_clock::now();
                    for (auto& entry : list) {

                        if (clock < entry.first) {
                            continue;
                        }

                        lua::pushref(L, entry.second);
                        luaL::rmref(L, entry.second);

                        auto it = std::find(list.begin(), list.end(), entry);
                        if (it != list.end()) list.erase(it);

                        guard.unlock();
                        if (lua::tcall(L, 0, 0)) {
                            std::string err = lua::tocstring(L, -1);
                            lua::pop(L);
                            auto& on_error = get_on_error();
                            for (auto const& handle : on_error) handle.second(L, err);
                        }
                        guard.lock();
                    }
                }

                guard.unlock();

                if (tasker->has(L, "think")) tasker->fire(L, "think");

                auto& dispatch = get_threaded();
                for (auto& [key, callback] : dispatch) {
                    callback(L);
                }

                Task::pop(L);
                if (lock.owns_lock()) lock.unlock(); lock.release();
            }

            void runtime()
            {
                static Signal::Handle* tasker = signal();

                std::unique_lock<std::mutex> guard(*mtx());

                for (auto& state : Tracker::get_states()) {
                    lua_State* L = state.second;
                    if (Tracker::is_threaded(L)) continue;

                    auto& defers = get_defers();
                    auto idefers = defers.find(L);
                    if (idefers != defers.end()) {
                        auto& list = idefers->second;
                        for (auto& entry : list) {

                            lua::pushref(L, entry);
                            luaL::rmref(L, entry);

                            auto it = std::find(list.begin(), list.end(), entry);
                            if (it != list.end()) list.erase(it);

                            guard.unlock();
                            if (lua::tcall(L, 0, 0)) {
                                std::string err = lua::tocstring(L, -1);
                                lua::pop(L);
                                auto& on_error = get_on_error();
                                for (auto const& handle : on_error) handle.second(L, err);
                            }
                            guard.lock();
                        }
                    }

                    auto& timers = get_timers();
                    auto itimers = timers.find(L);
                    if (itimers != timers.end()) {
                        auto& list = itimers->second;
                        auto clock = std::chrono::steady_clock::now();
                        for (auto& entry : list) {

                            if (clock < entry.first) {
                                continue;
                            }

                            lua::pushref(L, entry.second);
                            luaL::rmref(L, entry.second);

                            auto it = std::find(list.begin(), list.end(), entry);
                            if (it != list.end()) list.erase(it);

                            guard.unlock();
                            if (lua::tcall(L, 0, 0)) {
                                std::string err = lua::tocstring(L, -1);
                                lua::pop(L);
                                auto& on_error = get_on_error();
                                for (auto const& handle : on_error) handle.second(L, err);
                            }
                            guard.lock();
                        }
                    }

                    if (!tasker->has(L, "think")) continue;
                    guard.unlock();
                    tasker->fire(L, "think");
                    guard.lock();
                }

                guard.unlock();
            }

            void cleanup(lua_State* L)
            {
                std::lock_guard<std::mutex> guard(*mtx());
                auto& defers = get_defers();
                defers.erase(L);
                auto& timers = get_timers();
                timers.erase(L);
            }

            void push_stack(lua_State* L, UMODULE _)
            {
                static Signal::Handle* tasker = signal();
                tasker->api_imm(L, "think");

                lua::pushcfunction(L, lis_threaded);
                lua::setfield(L, -2, "isthreaded");

                lua::pushcfunction(L, ldefer);
                lua::setfield(L, -2, "defer");

                lua::pushcfunction(L, ldelay);
                lua::setfield(L, -2, "delay");
            }

            void api()
            {
                Tracker::on_close("task", cleanup);
                Reflection::add("task", push_stack);
            }
        }

        std::unordered_map<std::string, lua_Runtime>& get_runtimes()
        {
            static std::unordered_map<std::string, lua_Runtime> m;
            return m;
        }

        void on_runtime(std::string name, lua_Runtime callback)
        {
            auto& dispatch = get_runtimes();
            dispatch.emplace(name, callback);
        }

        void runtime()
        {
            auto& dispatch = get_runtimes();
            for (auto& [key, callback] : dispatch) {
                callback();
            }
            Task::runtime();
        }

        lua_State* open(std::string name, bool internal, bool threaded)
        {
            lua_State* exists = Tracker::is_state(name);
            if (exists != nullptr) {
                return exists;
            }

            lua_State* L = luaL::newstate();

            lua::gc(L, 0, 0);
            luaL::openlibs(L);
            lua::gc(L, 1, -1);

            if (threaded) {
                static Signal::Handle* tasker = Task::signal();

                Tracker::listen(L, name, std::make_shared<std::mutex>(), internal);

                std::thread([L]() {
                    while (Tracker::is_state(L) != nullptr) {
                        Task::runtime_threaded(L);
                    }
                }).detach();
            }
            else {
                Tracker::listen(L, name, internal);
            }

            return L;
        }

        void close(lua_State* L)
        {
            if (Tracker::is_threaded(L)) {
                auto lock = Tracker::lock(L);
                Tracker::pre_remove(L);
                lua::close(L);
                Tracker::post_remove(L);
                if (lock.owns_lock()) lock.unlock(); lock.release();
            } else {
                Tracker::pre_remove(L);
                lua::close(L);
                Tracker::post_remove(L);
            }
        }

        std::vector<std::pair<std::string, lua_CFunction>> functions;
        std::vector<std::pair<std::string, lua_CPush>> libraries;

        void add(std::string name, lua_CFunction callback)
        {
            functions.push_back(std::pair(name, callback));
        }

        void add(std::string name, lua_CPush callback)
        {
            libraries.push_back(std::pair(name, callback));
        }

        void push(lua_State* L)
        {
            uintptr_t id = Tracker::id(L);

            lua::pushvalue(L, indexer::global);

            for (const auto& callback : functions) {
                lua::pushcfunction(L, callback.second);
                lua::setcfield(L, -2, callback.first);
            }

            for (const auto& callback : libraries) {
                callback.second(L, process);
                lua::setcfield(L, -2, callback.first);
            }
        }
    }

    using namespace Reflection;

    UMODULE process;
    bool started = false;
    int errorcode = 0;
    int init(std::string binary)
    {
        if (started) return errorcode; started = true;

        #ifdef INTERSTELLAR_EXTERNAL
        if (binary.size() > 0) process = mopen(binary.c_str());
        else process = mopen(NULL);
        if (process == NULL) return -1;
        #else
        process = mopen(NULL);
        #endif

        int ret = fetch(process);

        if (ret != 0) { errorcode = ret; return ret; }

        Tracker::init();
        Reflection::api();
        Reflection::Task::api();
        Signal::api();
        Coroutine::api();
        Buffer::api();
        String::api();
        Debug::api();
        Table::api();
        Math::api();
        OS::api();

        return 0;
    }

    void runtime()
    {
        Tracker::runtime();
        Reflection::runtime();
    }
}

namespace INTERSTELLAR_NAMESPACE::Reflection {
    using namespace API;

    int lua_state__tostring(lua_State* L) {
        lua_State* state = Tracker::is_state(Class::check(L, 1, "lua.state"));
        if (state == nullptr) {
            luaL::error(L, "invalid lua instance");
            return 0;
        }

        std::string name = Tracker::get_name(state);
        lua::pushcstring(L, "lua.state: " + name);
        return 1;
    }

    int lua_state_execute(lua_State* L) {
        lua_State* state = Tracker::is_state(Class::check(L, 1, "lua.state"));
        if (state == nullptr) {
            luaL::error(L, "invalid lua instance");
            return 0;
        }

        std::string source = luaL::checkcstring(L, 2);
        std::string name = luaL::checkcstring(L, 3);

        if (Tracker::is_root(state)) {
            luaL::error(L, "cannot perform this while in this lua_State");
            return 0;
        }

        std::string err;
        if (Tracker::should_lock(state, L)) {
            bool should_notify = !Tracker::is_threaded(state);
            if (should_notify) Tracker::increment();
            Tracker::cross_lock(state, L);
            err = execute(state, source, name);
            Tracker::cross_unlock(state, L);
            if (should_notify) Tracker::decrement();
        }
        else {
            err = execute(state, source, name);
        }

        if (err.size() > 0) {
            lua::pushcstring(L, err);
            return 1;
        }

        return 0;
    }

    int lua_state_compile(lua_State* L) {
        lua_State* state = Tracker::is_state(Class::check(L, 1, "lua.state"));
        if (state == nullptr) {
            luaL::error(L, "invalid lua instance");
            return 0;
        }

        std::string source = luaL::checkcstring(L, 2);
        std::string name = luaL::checkcstring(L, 3);

        if (Tracker::is_root(state)) {
            luaL::error(L, "cannot perform this while in this lua_State");
            return 0;
        }

        std::string err;
        if (Tracker::should_lock(state, L)) {
            bool should_notify = !Tracker::is_threaded(state);
            if (should_notify) Tracker::increment();
            Tracker::cross_lock(state, L);
            err = compile(state, source, name);
            Tracker::cross_unlock(state, L);
            if (should_notify) Tracker::decrement();
        }
        else {
            err = compile(state, source, name);
        }

        if (err.size() > 0) {
            lua::pushcstring(L, err);
            return 1;
        }

        return 0;
    }

    void push_state(lua_State* L, lua_State* state);

    namespace CAPI {
        std::vector<lua_State*> stack_target;
        std::vector<lua_State*> stack_origin;
        uint64_t stack_pointer;

        lua_State* get_origin()
        {
            return stack_origin.back();
        }

        lua_State* get_target()
        {
            return stack_target.back();
        }

        lua_State* from_class(lua_State* L, int index) {
            lua_State* target = Tracker::is_state(Class::check(L, 1, "lua.state"));
            if (target == nullptr) { luaL::error(L, "invalid lua instance"); return nullptr; }
            if (target == L) { luaL::error(L, "cannot interact with the same lua instance!"); return nullptr; }
            return target;
        }

        namespace Functions {
            int typestack(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushcstring(L, lua::typestack(target, luaL::checknumber(L, 2)));
                return 1;
            }

            int pushany(lua_State* L) {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                luaL::checkany(L, 2);
                Reflection::transfer(L, target, 2);
                return 0;
            }

            int getany(lua_State* L) {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                Reflection::transfer(target, L, luaL::checknumber(L, 2));
                return 1;
            }

            int gettop(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushnumber(L, lua::gettop(target)); return 1;
            }

            int gettypename(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushstring(L, lua::gettypename(target, lua::gettype(target, luaL::checknumber(L, 2)))); return 1;
            }

            int gettype(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushnumber(L, lua::gettype(target, luaL::checknumber(L, 2))); return 1;
            }

            int call(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;

                int inputs = 0;
                if (!lua::isnil(L, 2)) {
                    inputs = luaL::checknumber(L, 2);
                }

                int outputs = 0;
                if (!lua::isnil(L, 3)) {
                    outputs = luaL::checknumber(L, 3);
                }

                if (lua::tcall(target, inputs, outputs)) {
                    std::string err = lua::tocstring(target, -1);
                    lua::pop(target);
                    lua::pushcstring(L, err);
                    return 1;
                }

                return 0;
            }

            int getupvalue(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                const char* name = lua::getupvalue(target, luaL::checknumber(L, 2), luaL::checknumber(L, 3));
                lua::pushstring(L, name);
                return 1;
            }

            int setupvalue(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                const char* name = lua::setupvalue(target, luaL::checknumber(L, 2), luaL::checknumber(L, 3));
                lua::pushstring(L, name);
                return 1;
            }

            int newtable(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::newtable(target);
                return 0;
            }

            int next(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushboolean(L, lua::next(target, luaL::checknumber(L, 2)));
                return 1;
            }

            int length(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushnumber(L, lua::objlen(target, luaL::checknumber(L, 2)));
                return 1;
            }

            int settable(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::settable(target, luaL::checknumber(L, 2));
                return 0;
            }

            int gettable(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::gettable(target, luaL::checknumber(L, 2));
                return 0;
            }

            int setfield(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::setfield(target, luaL::checknumber(L, 2), luaL::checkcstring(L, 3).c_str());
                return 0;
            }

            int getfield(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::getfield(target, luaL::checknumber(L, 2), luaL::checkcstring(L, 3).c_str());
                return 0;
            }

            int getfenv(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::getfenv(target, luaL::checknumber(L, 2));
                return 0;
            }

            int setfenv(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::setfenv(target, luaL::checknumber(L, 2));
                return 0;
            }

            int getmetatable(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushboolean(L, lua::getmetatable(target, luaL::checknumber(L, 2)));
                return 1;
            }

            int setmetatable(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::setmetatable(target, luaL::checknumber(L, 2));
                return 0;
            }

            int rawget(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::rawget(target, luaL::checknumber(L, 2));
                return 0;
            }

            int rawset(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::rawset(target, luaL::checknumber(L, 2));
                return 0;
            }

            int newref(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushnumber(L, luaL::newref(target, luaL::checknumber(L, 2)));
                return 1;
            }

            int pushref(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushref(target, luaL::checknumber(L, 2));
                return 0;
            }

            int rmref(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                luaL::rmref(target, luaL::checknumber(L, 2));
                return 0;
            }

            int pop(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                int count = 1;
                if (!lua::isnil(L, 2)) count = luaL::checknumber(L, 2);
                lua::pop(target, count); return 0;
            }

            int remove(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::remove(target, luaL::checknumber(L, 2)); return 0;
            }

            int pushnil(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushnil(target); return 0;
            }

            int pushboolean(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushboolean(target, luaL::checkboolean(L, 2)); return 0;
            }

            int pushnumber(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushnumber(target, luaL::checknumber(L, 2)); return 0;
            }

            int pushstring(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushstring(target, luaL::checkcstring(L, 2).c_str()); return 0;
            }

            int pushfunction(lua_State* from)
            {
                lua_State* to = from_class(from, 1); if (to == nullptr) return 0;
                luaL::checkfunction(from, 2);

                using namespace Engine;
                TValue* value = lua::toraw(from, 2);
                GCfunc* object = funcV(value);

                if (object->l.ffid == FF_LUA) {
                    std::string fname = ""; // TODO: placeholder for now
                    std::string btcode = luaL::dump(from, 2);

                    std::string err = Reflection::compile(to, btcode, fname);

                    if (err.size() > 0) {
                        luaL::error(to, (std::string() + "reflection transfer error: " + err).c_str());
                        return 0;
                    }

                    lua_Debug ar;
                    lua::pushvalue(from, 2);
                    if (lua::getinfo(from, ">u", &ar) && ar.nups > 0) {
                        for (int i = 1; i <= ar.nups; ++i) {
                            const char* name = lua::getupvalue(from, 2, i);
                            if (name == nullptr) break;
                            int err = transfer(from, to, -1);
                            lua::pop(from);
                            if (err != 0) {
                                return err;
                            }
                            lua::setupvalue(to, -2, i);
                        }
                    }
                }
                else {
                    lua_Debug ar;
                    size_t upvalues = 0;
                    lua::pushvalue(from, 2);

                    if (lua::getinfo(from, ">u", &ar) && ar.nups > 0) {
                        upvalues = ar.nups;

                        for (int i = 1; i <= upvalues; ++i) {
                            const char* name = lua::getupvalue(from, 2, i);
                            if (name == nullptr) break;
                            int err = transfer(from, to, -1);
                            lua::pop(from);
                            if (err != 0) {
                                lua::pop(to, i);
                                return err;
                            }
                        }
                    }

                    lua::pushcclosure(to, object->c.f, upvalues);
                }

                return 0;
            }

            int pushtable(lua_State* from) {
                lua_State* to = from_class(from, 1); if (to == nullptr) return 0;
                luaL::checktable(from, 2);
                Reflection::transfer_table(from, to, 2); return 0;
            }

            int pushvalue(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushvalue(target, luaL::checknumber(L, 2)); return 0;
            }

            int isnil(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushboolean(L, lua::isnil(target, luaL::checknumber(L, 2)));
                return 1;
            }

            int isboolean(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushboolean(L, lua::isboolean(target, luaL::checknumber(L, 2)));
                return 1;
            }

            int islightuserdata(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushboolean(L, lua::islightuserdata(target, luaL::checknumber(L, 2)));
                return 1;
            }

            int isuserdata(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushboolean(L, lua::isuserdata(target, luaL::checknumber(L, 2)));
                return 1;
            }

            int isnumber(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushboolean(L, lua::isnumber(target, luaL::checknumber(L, 2)));
                return 1;
            }

            int isstring(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushboolean(L, lua::isstring(target, luaL::checknumber(L, 2)));
                return 1;
            }

            int istable(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushboolean(L, lua::istable(target, luaL::checknumber(L, 2)));
                return 1;
            }

            int isfunction(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushboolean(L, lua::isfunction(target, luaL::checknumber(L, 2)));
                return 1;
            }

            int iscfunction(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushboolean(L, lua::iscfunction(target, luaL::checknumber(L, 2)));
                return 1;
            }

            int islfunction(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushboolean(L, lua::islfunction(target, luaL::checknumber(L, 2)));
                return 1;
            }

            int isthread(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushboolean(L, lua::isthread(target, luaL::checknumber(L, 2)));
                return 1;
            }

            int istype(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                int index = luaL::checknumber(L, 2);
                int type = luaL::checknumber(L, 3);
                lua::pushboolean(L, lua::istype(target, index, type));
                return 1;
            }

            int getboolean(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushboolean(L, luaL::checkboolean(target, luaL::checknumber(L, 2))); return 1;
            }

            int getnumber(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushnumber(L, luaL::checknumber(target, luaL::checknumber(L, 2))); return 1;
            }

            int getstring(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                lua::pushcstring(L, luaL::checkcstring(target, luaL::checknumber(L, 2))); return 1;
            }

            int wrapper_transfer(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                int num_args = lua::gettop(L);
                int top = lua::gettop(target);

                lua::pushvalue(L, upvalueindex(1));
                lua_CFunction func = (lua_CFunction)luaL::checklightuserdata(L, -1);
                lua::pop(L);

                lua::pushcfunction(target, func);

                for (int i = 2; i <= num_args; i++) {
                    Reflection::transfer(L, target, i);
                }

                if (lua::pcall(target, num_args-1, -1, 0)) {
                    std::string err = lua::tocstring(target, -1);
                    lua::pop(target);
                    luaL::error(L, err.c_str());
                    return 0;
                }

                int diff = lua::gettop(target) - top;

                int returns = 0;
                for (int i = 1; i <= diff; i++) {
                    returns++;
                    Reflection::transfer(target, L, -1);
                    lua::pop(target);
                }

                return returns;
            }

            int wrapper_output(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                int top = lua::gettop(target);

                lua::pushvalue(L, upvalueindex(1));
                lua_CFunction func = (lua_CFunction)luaL::checklightuserdata(L, -1);
                lua::pop(L);

                lua::pushvalue(L, upvalueindex(2));
                int count = luaL::checknumber(L, -1);
                lua::pop(L);

                if (lua::pcall(target, count, -1, 0)) {
                    std::string err = lua::tocstring(target, -1);
                    lua::pop(target);
                    luaL::error(L, err.c_str());
                    return 0;
                }

                int diff = lua::gettop(target) - top;

                int returns = 0;
                for (int i = 1; i <= diff; i++) {
                    returns++;
                    Reflection::transfer(target, L, -1);
                    lua::pop(target);
                }

                return returns;
            }

            int wrapper_input(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;
                int num_args = lua::gettop(L);
                int top = lua::gettop(target);

                lua::pushvalue(L, upvalueindex(1));
                lua_CFunction func = (lua_CFunction)luaL::checklightuserdata(L, -1);
                lua::pop(L);

                lua::pushcfunction(target, func);

                for (int i = 2; i <= num_args; i++) {
                    Reflection::transfer(L, target, i);
                }

                if (lua::pcall(target, num_args-1, 0, 0)) {
                    std::string err = lua::tocstring(target, -1);
                    lua::pop(target);
                    luaL::error(L, err.c_str());
                    return 0;
                }

                return 0;
            }

            int wrapper(lua_State* L)
            {
                lua_State* target = from_class(L, 1); if (target == nullptr) return 0;

                lua::pushvalue(L, upvalueindex(1));
                lua_CFunction func = (lua_CFunction)luaL::checklightuserdata(L, -1);
                lua::pop(L);

                lua::pushvalue(L, upvalueindex(2));
                int count = luaL::checknumber(L, -1);
                lua::pop(L);

                lua::pushcfunction(target, func);

                if (lua::pcall(target, count, -1, 0)) {
                    std::string err = lua::tocstring(target, -1);
                    lua::pop(target);
                    luaL::error(L, err.c_str());
                    return 0;
                }

                return 0;
            }

            int api(lua_State* L) {
                lua_State* target = get_target();
                Reflection::push(target);
                return 1;
            }

            std::map<uintptr_t, int> reference;

            void cleanup(lua_State* L)
            {
                reference.erase(Tracker::id(L));
            }

            std::vector<std::pair<std::string, lua_CFunction>> functions;
            std::vector<std::pair<std::string, lua_CAPIPush>> libraries;

            void add(std::string name, lua_CFunction callback)
            {
                functions.push_back(std::pair(name, callback));
            }

            void add(std::string name, lua_CAPIPush callback)
            {
                libraries.push_back(std::pair(name, callback));
            }

            void push(lua_State* L)
            {
                Tracker::on_close("capi", cleanup);

                lua::pushcfunction(L, api); lua::setfield(L, -2, "api");

                lua::pushcfunction(L, typestack); lua::setfield(L, -2, "typestack");
                lua::pushcfunction(L, pushany); lua::setfield(L, -2, "pushany");
                lua::pushcfunction(L, getany); lua::setfield(L, -2, "getany");
                lua::pushcfunction(L, pop); lua::setfield(L, -2, "pop");
                lua::pushcfunction(L, remove); lua::setfield(L, -2, "remove");
                lua::pushcfunction(L, gettype); lua::setfield(L, -2, "gettype");
                lua::pushcfunction(L, gettypename); lua::setfield(L, -2, "gettypename");
                lua::pushcfunction(L, gettop); lua::setfield(L, -2, "gettop");

                lua::pushcfunction(L, call); lua::setfield(L, -2, "call");
                lua::pushcfunction(L, getupvalue); lua::setfield(L, -2, "getupvalue");
                lua::pushcfunction(L, setupvalue); lua::setfield(L, -2, "setupvalue");
                lua::pushcfunction(L, newref); lua::setfield(L, -2, "newref");
                lua::pushcfunction(L, pushref); lua::setfield(L, -2, "pushref");
                lua::pushcfunction(L, rmref); lua::setfield(L, -2, "rmref");
                lua::pushcfunction(L, newtable); lua::setfield(L, -2, "newtable");
                lua::pushcfunction(L, next); lua::setfield(L, -2, "next");
                lua::pushcfunction(L, length); lua::setfield(L, -2, "length");
                lua::pushcfunction(L, setfenv); lua::setfield(L, -2, "setfenv");
                lua::pushcfunction(L, getfenv); lua::setfield(L, -2, "getfenv");
                lua::pushcfunction(L, setmetatable); lua::setfield(L, -2, "setmetatable");
                lua::pushcfunction(L, getmetatable); lua::setfield(L, -2, "getmetatable");
                lua::pushcfunction(L, settable); lua::setfield(L, -2, "settable");
                lua::pushcfunction(L, gettable); lua::setfield(L, -2, "gettable");
                lua::pushcfunction(L, setfield); lua::setfield(L, -2, "setfield");
                lua::pushcfunction(L, getfield); lua::setfield(L, -2, "getfield");
                lua::pushcfunction(L, rawget); lua::setfield(L, -2, "rawget");
                lua::pushcfunction(L, rawset); lua::setfield(L, -2, "rawset");

                lua::pushcfunction(L, getboolean); lua::setfield(L, -2, "getboolean");
                lua::pushcfunction(L, getnumber); lua::setfield(L, -2, "getnumber");
                lua::pushcfunction(L, getstring); lua::setfield(L, -2, "getstring");

                lua::pushcfunction(L, pushnil); lua::setfield(L, -2, "pushnil");
                lua::pushcfunction(L, pushboolean); lua::setfield(L, -2, "pushboolean");
                lua::pushcfunction(L, pushnumber); lua::setfield(L, -2, "pushnumber");
                lua::pushcfunction(L, pushstring); lua::setfield(L, -2, "pushstring");
                lua::pushcfunction(L, pushfunction); lua::setfield(L, -2, "pushfunction");
                lua::pushcfunction(L, pushtable); lua::setfield(L, -2, "pushtable");
                lua::pushcfunction(L, pushvalue); lua::setfield(L, -2, "pushvalue");

                lua::pushcfunction(L, isnil); lua::setfield(L, -2, "isnil");
                lua::pushcfunction(L, isboolean); lua::setfield(L, -2, "isboolean");
                lua::pushcfunction(L, islightuserdata); lua::setfield(L, -2, "islightuserdata");
                lua::pushcfunction(L, isnumber); lua::setfield(L, -2, "isnumber");
                lua::pushcfunction(L, isstring); lua::setfield(L, -2, "isstring");
                lua::pushcfunction(L, isfunction); lua::setfield(L, -2, "isfunction");
                lua::pushcfunction(L, iscfunction); lua::setfield(L, -2, "iscfunction");
                lua::pushcfunction(L, islfunction); lua::setfield(L, -2, "islfunction");
                lua::pushcfunction(L, istable); lua::setfield(L, -2, "istable");
                lua::pushcfunction(L, isuserdata); lua::setfield(L, -2, "isuserdata");
                lua::pushcfunction(L, isthread); lua::setfield(L, -2, "isthread");
                lua::pushcfunction(L, istype); lua::setfield(L, -2, "istype");

                for (const auto& callback : functions) {
                    lua::pushcfunction(L, callback.second);
                    lua::setcfield(L, -2, callback.first);
                }

                for (const auto& callback : libraries) {
                    callback.second(L);
                    lua::setcfield(L, -2, callback.first);
                }
            }
        }

        void interstate_input(lua_State* L, lua_CFunction func)
        {
            lua::pushlightuserdata(L, (void*)func);
            lua::pushcclosure(L, Functions::wrapper_input, 1);
        }

        void interstate_output(lua_State* L, lua_CFunction func, int count)
        {
            lua::pushlightuserdata(L, (void*)func);
            lua::pushnumber(L, count);
            lua::pushcclosure(L, Functions::wrapper_output, 2);
        }

        void interstate_transfer(lua_State* L, lua_CFunction func)
        {
            lua::pushlightuserdata(L, (void*)func);
            lua::pushcclosure(L, Functions::wrapper_transfer, 1);
        }

        void interstate(lua_State* L, lua_CFunction func, int count)
        {
            lua::pushlightuserdata(L, (void*)func);
            lua::pushnumber(L, count);
            lua::pushcclosure(L, Functions::wrapper, 2);
        }

        void push(lua_State* origin, lua_State* target)
        {
            stack_origin.push_back(origin);
            stack_target.push_back(target);
            push_state(origin, target);
        }

        void pop()
        {
            stack_origin.pop_back();
            stack_target.pop_back();
        }

        int stack_handler(lua_State* L)
        {
            stack_pointer = lua::gettop(L);
            lua_State* origin = stack_origin.back();
            lua::pushvalue(origin, 2);
            push_state(origin, L);
            if (lua::pcall(origin, 1, -1, 0)) {
                std::string err = lua::tocstring(origin, -1);
                lua::pop(origin);
                luaL::error(L, err.c_str());
                return 0;
            }
            return 0;
        }

        int stackl(lua_State* L)
        {
            luaL::checktype(L, 1, datatype::function);

            lua_State* state_target = Tracker::is_state(Class::check(L, 2, "lua.state"));
            if (state_target == nullptr) {
                luaL::error(L, "invalid lua instance");
                return 0;
            }

            if (Tracker::is_root(state_target)) {
                luaL::error(L, "cannot access this function in this lua_State");
                return 0;
            }

            if (state_target == L) {
                luaL::error(L, "cannot target the same lua_State as current");
                return 0;
            }

            int top = lua::gettop(L);

            if (Tracker::should_lock(state_target, L)) {
                bool should_notify = !Tracker::is_threaded(state_target);
                if (should_notify) Tracker::increment();
                Tracker::cross_lock(state_target, L);

                push(L, state_target);
                lua::pushcfunction(state_target, stack_handler);
                if (lua::pcall(state_target, 0, 0, 0)) {
                    pop();
                    size_t size = 0;
                    std::string err = lua::tocstring(state_target, -1);
                    lua::pop(state_target);
                    Tracker::cross_unlock(state_target, L);
                    if (should_notify) Tracker::decrement();
                    luaL::error(L, err.c_str());
                    return 0;
                }
                pop();
                
                Tracker::cross_unlock(state_target, L);
                if (should_notify) Tracker::decrement();
            }
            else {
                push(L, state_target);
                lua::pushcfunction(state_target, stack_handler);
                if (lua::pcall(state_target, 0, 0, 0)) {
                    pop();
                    size_t size = 0;
                    std::string err = lua::tocstring(state_target, -1);
                    lua::pop(state_target);
                    luaL::error(L, err.c_str());
                    return 0;
                }
                pop();
            }

            return lua::gettop(L) - top;
        }

        int lua_state_stack(lua_State* L)
        {
            luaL::checktype(L, 2, datatype::function);

            lua_State* state_target = Tracker::is_state(Class::check(L, 1, "lua.state"));
            if (state_target == nullptr) {
                luaL::error(L, "invalid lua instance");
                return 0;
            }

            if (Tracker::is_root(state_target)) {
                luaL::error(L, "cannot access this function in this lua_State");
                return 0;
            }

            if (state_target == L) {
                luaL::error(L, "cannot target the same lua_State as current");
                return 0;
            }

            int top = lua::gettop(L);

            if (Tracker::should_lock(state_target, L)) {
                bool should_notify = !Tracker::is_threaded(state_target);
                if (should_notify) Tracker::increment();
                Tracker::cross_lock(state_target, L);

                push(L, state_target);
                lua::pushcfunction(state_target, stack_handler);
                if (lua::pcall(state_target, 0, 0, 0)) {
                    pop();
                    size_t size = 0;
                    std::string err = lua::tocstring(state_target, -1);
                    lua::pop(state_target);
                    Tracker::cross_unlock(state_target, L);
                    if (should_notify) Tracker::decrement();
                    luaL::error(L, err.c_str());
                    return 0;
                }
                pop();

                Tracker::cross_unlock(state_target, L);
                if (should_notify) Tracker::decrement();
            }
            else {
                push(L, state_target);
                lua::pushcfunction(state_target, stack_handler);
                if (lua::pcall(state_target, 0, 0, 0)) {
                    pop();
                    size_t size = 0;
                    std::string err = lua::tocstring(state_target, -1);
                    lua::pop(state_target);
                    luaL::error(L, err.c_str());
                    return 0;
                }
                pop();
            }

            return lua::gettop(L) - top;
        }
    }

    void push_state(lua_State* L, lua_State* state) {
        if (!Class::existsbyname(L, "lua.state")) {
            Class::create(L, "lua.state");

            lua::newtable(L);

            lua::pushcfunction(L, lua_state_execute);
            lua::setfield(L, -2, "execute");

            lua::pushcfunction(L, lua_state_compile);
            lua::setfield(L, -2, "compile");

            lua::pushcfunction(L, CAPI::lua_state_stack);
            lua::setfield(L, -2, "stack");

            CAPI::Functions::push(L);

            lua::setfield(L, -2, "__index");

            lua::pushcfunction(L, lua_state__tostring);
            lua::setfield(L, -2, "__tostring");

            lua::pop(L);
        }

        Class::spawn(L, state, "lua.state");
    }

    int compilel(lua_State* L)
    {
        std::string source = luaL::checkcstring(L, 1);
        std::string name = luaL::checkcstring(L, 2);

        std::string err = compile(L, source, name);

        if (err.size() > 0) {
            lua::pushcstring(L, err);
            return 1;
        }

        return 1;
    }

    int executel(lua_State* L)
    {
        std::string source = luaL::checkcstring(L, 1);
        std::string name = luaL::checkcstring(L, 2);

        lua_State* state_target = L;
        if (!lua::isnil(L, 3)) {
            lua_State* target = Tracker::is_state(Class::check(L, 3, "lua.state"));
            if (target == nullptr) {
                luaL::error(L, "invalid lua instance");
                return 0;
            }

            if (Tracker::is_root(target)) {
                luaL::error(L, "cannot perform this while in this lua_State");
                return 0;
            }

            state_target = target;
        }

        std::string err;
        
        if (Tracker::should_lock(state_target, L)) {
            bool should_notify = !Tracker::is_threaded(state_target);
            if (should_notify) Tracker::increment();
            Tracker::cross_lock(state_target, L);
            err = execute(state_target, source, name);
            Tracker::cross_unlock(state_target, L);
            if (should_notify) Tracker::decrement();
        }
        else {
            err = execute(state_target, source, name);
        }

        if (err.size() > 0) {
            lua::pushcstring(L, err);
            return 1;
        }

        return 0;
    }

    int getl(lua_State* L)
    {
        std::string name = luaL::checkcstring(L, 1);
        lua_State* N = Tracker::is_state(name);
        if (N == nullptr) {
            return 0;
        }
        push_state(L, N);
        return 1;
    }

    int all_l(lua_State* L)
    {
        lua::newtable(L);
        auto list = Tracker::get_states();

        for (auto& pair : list) {
            push_state(L, pair.second);
            lua::setcfield(L, -2, pair.first);
        }

        return 1;
    }

    int current_l(lua_State* L)
    {
        push_state(L, L);
        return 1;
    }

    int is_l(lua_State* L)
    {
        lua::pushboolean(L, luaL::checkcstring(L, 1) == Tracker::get_name(L));
        return 1;
    }

    int name_l(lua_State* L)
    {
        lua_State* target = Tracker::is_state(Class::check(L, 1, "lua.state"));
        if (target == nullptr) {
            luaL::error(L, "invalid lua instance");
            return 0;
        }
        std::string name = Tracker::get_name(target);
        if (name.size() < 1) {
            name = "unknown";
        }
        lua::pushcstring(L, name);
        return 1;
    }

    int printl(lua_State* L)
    {
        int nargs = lua::gettop(L);
        std::vector<std::string> args;

        for (int i = 1; i <= nargs; ++i) {
            if (lua::isstring(L, i) || lua::isnumber(L, i)) {
                args.push_back(lua::tocstring(L, i));
            }
            else {
                lua::pushvalue(L, upvalueindex(1));
                lua::pushvalue(L, i);
                lua::call(L, 1, 1);
                args.push_back(lua::tocstring(L, -1));
                lua::pop(L, 1);
            }
        }

        std::string line;
        for (size_t i = 0; i < args.size(); ++i) {
            line += args[i];
            if (i < args.size() - 1) {
                line += "\t";
            }
        }

        std::string name = Tracker::get_name(L);
        if (name.size() < 1) {
            name = "unknown";
        }

        line = "[" + name + "] " + line + "\n";

        printf(line.c_str());

        /*lua_State* target = Tracker::get_root();
        if (target == nullptr) return 0;

        lua::pushvalue(target, indexer::global);
        lua::getfield(target, -1, "print");
        lua::remove(target, -2);

        if (lua::isfunction(target, -1)) {
            lua::pushcstring(target, line);
            lua::pcall(target, 1, 0, 0);
        }
        else {
            lua::pop(target);
        }*/

        return 0;
    }

    int openl(lua_State* L)
    {
        std::string name = luaL::checkcstring(L, 1);

        if (name.size() < 1)
        {
            luaL::error(L, "lua_State must be given a valid name");
            return 0;
        }

        lua_State* exists = Tracker::is_state(name);

        if (exists != nullptr) {
            push_state(L, exists);
            return 1;
        }

        lua_State* state;

        if (lua::isboolean(L, 2) && lua::toboolean(L, 2)) {
            state = Reflection::open(name, false, true);

            auto lock = Tracker::lock(state);

            lua::pushvalue(state, indexer::global);
            lua::getfield(state, -1, "tostring");
            lua::pushcclosure(state, printl, 1);
            lua::setfield(state, -2, "print");

            if (lock.owns_lock()) lock.unlock(); lock.release();
        }
        else {
            state = Reflection::open(name, false, false);
            lua::pushvalue(state, indexer::global);
            lua::getfield(state, -1, "tostring");
            lua::pushcclosure(state, printl, 1);
            lua::setfield(state, -2, "print");
        }

        push_state(L, state);

        return 1;
    }

    int closel(lua_State* L)
    {
        lua_State* target = Tracker::is_state(Class::check(L, 1, "lua.state"));
        if (target == nullptr) {
            luaL::error(L, "invalid lua instance");
            return 0;
        }

        if (Tracker::is_internal(target)) {
            luaL::error(L, "cannot close internal lua_State");
            return 0;
        }

        Reflection::close(target);

        return 0;
    }

    void push(lua_State* L, UMODULE handle)
    {
        lua::newtable(L);

        lua::pushcfunction(L, compilel);
        lua::setfield(L, -2, "compile");

        lua::pushcfunction(L, executel);
        lua::setfield(L, -2, "execute");

        lua::pushcfunction(L, is_l);
        lua::setfield(L, -2, "is");

        lua::pushcfunction(L, getl);
        lua::setfield(L, -2, "get");

        lua::pushcfunction(L, all_l);
        lua::setfield(L, -2, "all");

        lua::pushcfunction(L, current_l);
        lua::setfield(L, -2, "current");

        lua::pushcfunction(L, name_l);
        lua::setfield(L, -2, "name");

        lua::pushcfunction(L, openl);
        lua::setfield(L, -2, "open");

        lua::pushcfunction(L, closel);
        lua::setfield(L, -2, "close");

        lua::pushcfunction(L, CAPI::stackl);
        lua::setfield(L, -2, "stack");

        Tracker::signal->api(L);
        lua::setfield(L, -2, "listener");
    }

    void api() {
        Reflection::add("reflection", push);
    }
}