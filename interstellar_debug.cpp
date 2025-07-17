#include <string.h>
#include "interstellar_debug.hpp"
#include <map>
#include <unordered_map>
#include <string>
#include <sstream>
#include <iomanip>
#include <atomic>

namespace INTERSTELLAR_NAMESPACE::Debug {
    using namespace API;

    Engine::cTValue* lj_debug_frame(lua_State* L, int level, int* size)
    {
        using namespace Engine;
        cTValue* frame, * nextframe, * bot = tvref(L->stack) + LJ_FR2;
        /* Traverse frames backwards. */
        for (nextframe = frame = L->base - 1; frame > bot; ) {
            if (frame_gc(frame) == (GCobj*)(L))
                level++;  /* Skip dummy frames. See lj_err_optype_call(). */
            if (level-- == 0) {
                *size = (int)(nextframe - frame);
                return frame;  /* Level found. */
            }
            nextframe = frame;
            if (frame_islua(frame)) {
                frame = frame_prevl(frame);
            }
            else {
                if (frame_isvarg(frame))
                    level++;  /* Skip vararg pseudo-frame. */
                frame = frame_prevd(frame);
            }
        }
        *size = level;
        return NULL;  /* Level not found. */
    }

    #define uddata(u)	((void *)((u)+1))
    const void* lj_obj_ptr(lua_State* L, Engine::TValue* o)
    {
        using namespace Engine;
        global_State* g = G(L);

        if (tvisudata(o))
            return uddata(udataV(o));
        else if (tvislightud(o))
            return lightudV(g, o);
        else if (LJ_HASFFI && tviscdata(o))
            return cdataptr(cdataV(o));
        else if (tvisgcv(o))
            return gcV(o);
        else
            return NULL;
    }

    std::map<uintptr_t, std::map<uintptr_t, int>> closure_link;

    int closure_wrapper(lua_State* L)
    {
        lua_Debug ar;
        if (!lua::getstack(L, 0, &ar)) {
            return 0;
        }

        if (!lua::getinfo(L, "f", &ar)) {
            return 0;
        }

        uintptr_t pointer = (uintptr_t)lj_obj_ptr(L, lua::toraw(L, -1));
        uintptr_t id = Tracker::id(L);
        lua::pop(L);

        if (closure_link.find(id) == closure_link.end()) {
            return 0;
        }

        std::map<uintptr_t, int>& linkage = closure_link[id];

        if (linkage.find(pointer) == linkage.end()) {
            return 0;
        }

        int top = lua::gettop(L);

        lua::pushref(L, linkage[pointer]);

        for (int i = 1; i <= top; i++) {
            lua::pushvalue(L, i);
        }

        int result = lua::pcall(L, top, -1, 0);

        if (result && result != 1)
        {
            size_t size = 0;
            const char* error = lua::tolstring(L, -1, &size);
            lua::pop(L);
            luaL::error(L, std::string(error, size).c_str());
            return 0;
        }

        return lua::gettop(L) - top;
    }

    uintptr_t closure_pointer = 0;
    int runtime_topointer(lua_State* L)
    {
        closure_pointer = (uintptr_t)lj_obj_ptr(L, lua::toraw(L, 1));
        return 0;
    }

    int newcclosure(lua_State* L)
    {
        luaL::checktype(L, 1, datatype::function);

        lua::pushvalue(L, 1);
        const int reference = luaL::newref(L, -1);
        lua::pushcfunction(L, closure_wrapper);
        lua::pushcfunction(L, runtime_topointer);
        lua::pushvalue(L, -2);
        lua::call(L, 1, 0);

        uintptr_t id = Tracker::id(L);

        if (closure_link.find(id) == closure_link.end()) {
            closure_link[id] = std::map<uintptr_t, int>();
        }
        closure_link[id][closure_pointer] = reference;

        return 1;
    }

    int blank(lua_State* L) { return 0; }

    int clone(lua_State* L)
    {
        using namespace Engine;

        if (lua::istype(L, 1, datatype::userdata)) {
            TValue* value = lua::toraw(L, 1);
            GCobj* object = gcval(value);
            MSize len = object->ud.len;

            void* data = lua::touserdata(L, 1);
            void* udata = (void*)lua::newuserdata(L, len);
            memcpy(udata, data, len);

            TValue* tvalue = lua::toraw(L, -1);
            GCobj* tobject = gcval(tvalue);
            tobject->ud.udtype = object->ud.udtype;
            tobject->ud.unused2 = object->ud.unused2;
            return 1;
        }
        else if (lua::istype(L, 1, datatype::function)) {
            if (lua::iscfunction(L, 1)) {
                TValue* tv_target = lua::toraw(L, 1);
                GCfunc* gc_target = funcV(tv_target);

                for (uint8_t i = 0; i < gc_target->c.nupvalues; i++) {
                    lua::pushnil(L);
                }

                lua::pushcclosure(L, blank, gc_target->c.nupvalues);
                TValue* tv_copy = lua::toraw(L, -1);
                GCfunc* gc_copy = funcV(tv_copy);

                for (uint8_t i = 0; i < gc_target->c.nupvalues; i++) {
                    gc_copy->c.upvalue[i] = gc_target->c.upvalue[i];
                }

                gc_copy->c.f = gc_target->c.f;
                gc_copy->c.env = gc_target->c.env;
                gc_copy->c.ffid = gc_target->c.ffid;
                return 1;
            }
            else {
                TValue* tv_target = lua::toraw(L, 1);
                GCfunc* gc_target = funcV(tv_target);
                GCproto* proto_target = funcproto(gc_target);

                lua::pushlfunction(L, proto_target);
                TValue* tv_copy = lua::toraw(L, -1);
                GCfunc* gc_copy = funcV(tv_copy);

                gc_copy->l.env = gc_target->l.env;
                for (uint8_t i = 0; i < gc_target->l.nupvalues; i++) {
                    gc_copy->l.uvptr[i] = gc_target->l.uvptr[i];
                }
                return 1;
            }
        }
        else {
            luaL::error(L, (std::string("unsupported datatype: ") + lua::gettypename(L, lua::gettype(L, 1))).c_str());
        }

        return 0;
    }

    int replace(lua_State* L) {
        luaL::checkany(L, 1);
        luaL::checkany(L, 2);

        if (lua::isnil(L, 1)) {
            luaL::error(L, "expected a non-nil value");
            return 0;
        }

        if (lua::isnil(L, 2)) {
            luaL::error(L, "expected a non-nil value");
            return 0;
        }

        if (lua::gettype(L, 1) != lua::gettype(L, 2)) {
            luaL::error(L, "expected same value datatype");
            return 0;
        }

        using namespace Engine;

        if (lua::istype(L, 1, datatype::userdata)) {
            TValue* target = lua::toraw(L, 1);
            GCobj* gc_target = gcval(target);
            MSize len_target = gc_target->ud.len;
            void* data_target = lua::touserdata(L, 1);

            TValue* replacer = lua::toraw(L, 2);
            GCobj* gc_replacer = gcval(replacer);
            MSize len_replacer = gc_replacer->ud.len;
            void* data_replacer = lua::touserdata(L, 2);

            if (len_replacer > len_target) {
                luaL::error(L, "userdata size exceeds target size");
                return 0;
            }

            memcpy(data_target, data_replacer, len_replacer);

            gc_target->ud.len = len_replacer;
            gc_target->ud.udtype = gc_target->ud.udtype;
        }
        else if (lua::istype(L, 1, datatype::function)) {
            if (lua::iscfunction(L, 1)) {
                if (lua::islfunction(L, 2)) {
                    luaL::error(L, "expected same function datatype");
                    return 0;
                }
                TValue* tv_target = lua::toraw(L, 1);
                GCfunc* gc_target = funcV(tv_target);

                TValue* tv_replacer = lua::toraw(L, 2);
                GCfunc* gc_replacer = funcV(tv_replacer);

                if (gc_target->c.nupvalues != gc_replacer->c.nupvalues) {
                    luaL::error(L, (std::string("expected same function upvalue count (") + std::to_string(gc_target->c.nupvalues) + " != " + std::to_string(gc_replacer->c.nupvalues) + ")").c_str());
                    return 0;
                }

                gc_target->c.f = gc_replacer->c.f;
                gc_target->c.env = gc_replacer->c.env;
                gc_target->c.ffid = gc_replacer->c.ffid;
                gc_target->c.nupvalues = gc_replacer->c.nupvalues;
                for (uint8_t i = 0; i < gc_replacer->c.nupvalues; i++) {
                    gc_target->c.upvalue[i] = gc_replacer->c.upvalue[i];
                }
            }
            else {
                if (lua::iscfunction(L, 2)) {
                    luaL::error(L, "expected same function datatype");
                    return 0;
                }
                TValue* target = lua::toraw(L, 1);
                GCfunc* gc_target = funcV(target);

                TValue* tv_replacer = lua::toraw(L, 2);
                GCfunc* gc_replacer = funcV(tv_replacer);

                if (gc_target->l.nupvalues != gc_replacer->l.nupvalues) {
                    luaL::error(L, (std::string("expected same function upvalue count (") + std::to_string(gc_target->c.nupvalues) + " != " + std::to_string(gc_replacer->c.nupvalues) + ")").c_str());
                    return 0;
                }

                GCproto* proto_replacer = funcproto(gc_replacer);
                setmref(gc_target->l.pc, proto_bc(proto_replacer));
                gc_target->l.env = gc_replacer->l.env;
                gc_target->l.nupvalues = gc_replacer->l.nupvalues;
                for (uint8_t i = 0; i < gc_replacer->l.nupvalues; i++) {
                    gc_target->l.uvptr[i] = gc_replacer->l.uvptr[i];
                }
            }
        }
        else {
            luaL::error(L, (std::string("unsupported datatype: ") + lua::gettypename(L, lua::gettype(L, 1))).c_str());
        }

        return 0;
    }

    namespace Hook {
        std::map<uintptr_t, std::map<uintptr_t, bool>> hooking_state;
        std::map<uintptr_t, std::map<uintptr_t, int>> hooking_lua_linkages;
        std::map<uintptr_t, std::map<uintptr_t, int>> hooking_lua_originals;
        std::map<uintptr_t, std::map<uintptr_t, int>> hooking_c_linkages;
        std::map<uintptr_t, std::map<uintptr_t, lua_CFunction>> hooking_c_originals;
        std::map<uintptr_t, std::map<uintptr_t, int>> hooking_mh_linkages;
        std::map<uintptr_t, std::map<uintptr_t, lua_CFunction>> hooking_mh_originals;
        std::atomic<int> inside_semaphore = 0;

        bool is(lua_State* L, int index) {
            if (!lua::isfunction(L, index)) {
                return false;
            }

            uintptr_t pointer = (uintptr_t)lj_obj_ptr(L, lua::toraw(L, index));
            uintptr_t id = Tracker::id(L);

            if (hooking_lua_linkages.find(id) != hooking_lua_linkages.end()) {
                std::map<uintptr_t, int>& linkage = hooking_lua_linkages[id];
                if (linkage.find(pointer) != linkage.end()) {
                    return true;
                }
            }

            if (hooking_c_linkages.find(id) != hooking_c_linkages.end()) {
                std::map<uintptr_t, int>& linkage = hooking_c_linkages[id];
                if (linkage.find(pointer) != linkage.end()) {
                    return true;
                }
            }

            if (lua::iscfunction(L, index) && hooking_mh_linkages.find(id) != hooking_mh_linkages.end()) {
                std::map<uintptr_t, int>& linkage = hooking_mh_linkages[id];
                using namespace Engine;
                TValue* tv_target = lua::toraw(L, index);
                uintptr_t pointer = (uintptr_t)(((GCfunc*)gcV(tv_target))->c.f);
                if (linkage.find(pointer) != linkage.end()) {
                    return true;
                }
            }

            return false;
        }

        bool is_lua(lua_State* L, int index) {
            if (!lua::islfunction(L, index)) {
                return false;
            }

            uintptr_t pointer = (uintptr_t)lj_obj_ptr(L, lua::toraw(L, index));
            uintptr_t id = Tracker::id(L);

            if (hooking_lua_linkages.find(id) != hooking_lua_linkages.end()) {
                std::map<uintptr_t, int>& linkage = hooking_lua_linkages[id];
                if (linkage.find(pointer) != linkage.end()) {
                    return true;
                }
            }

            return false;
        }

        bool is_c(lua_State* L, int index) {
            if (!lua::iscfunction(L, index)) {
                return false;
            }

            uintptr_t pointer = (uintptr_t)lj_obj_ptr(L, lua::toraw(L, index));
            uintptr_t id = Tracker::id(L);

            if (hooking_c_linkages.find(id) != hooking_c_linkages.end()) {
                std::map<uintptr_t, int>& linkage = hooking_c_linkages[id];
                if (linkage.find(pointer) != linkage.end()) {
                    return true;
                }
            }

            return false;
        }

        bool is_mh(lua_State* L, int index) {
            #ifdef MH_ALL_HOOKS
            if (!lua::iscfunction(L, index)) {
                return false;
            }
            
            using namespace Engine;
            TValue* tv_target = lua::toraw(L, index);
            uintptr_t pointer = (uintptr_t)(((GCfunc*)gcV(tv_target))->c.f);
            uintptr_t id = Tracker::id(L);

            if (hooking_mh_linkages.find(id) != hooking_mh_linkages.end()) {
                std::map<uintptr_t, int>& linkage = hooking_mh_linkages[id];
                if (linkage.find(pointer) != linkage.end()) {
                    return true;
                }
            }
            #endif

            return false;
        }

        void clear(lua_State* L) {
            uintptr_t id = Tracker::id(L);
            for (auto& pointers : hooking_lua_linkages) {
                for (auto& entry : pointers.second) {
                    luaL::rmref(L, entry.second);
                }
            }
            hooking_lua_linkages.erase(id);

            for (auto& pointers : hooking_lua_originals) {
                for (auto& entry : pointers.second) {
                    luaL::rmref(L, entry.second);
                }
            }
            hooking_lua_originals.erase(id);

            for (auto& pointers : hooking_c_linkages) {
                for (auto& entry : pointers.second) {
                    luaL::rmref(L, entry.second);
                }
            }
            hooking_c_linkages.erase(id);
            hooking_c_originals.erase(id);
            
            #ifdef MH_ALL_HOOKS
            for (auto& pointers : hooking_mh_linkages) {
                for (auto& entry : pointers.second) {
                    MH_RemoveHook((void*)entry.first);
                    luaL::rmref(L, entry.second);
                }
            }
            hooking_mh_linkages.erase(id);

            for (auto& pointers : hooking_mh_originals) {
                for (auto& entry : pointers.second) {
                    // TODO: Implementation of cleanup
                    // ^ Not needed I think...
                }
            }
            hooking_mh_originals.erase(id);
            #endif

            hooking_state.erase(id);
        }

        // for translation of lua hooking a c-function (non-MH)
        int wrapper(lua_State* L)
        {
            lua_Debug ar;
            if (!lua::getstack(L, 0, &ar)) {
                return 0;
            }

            if (!lua::getinfo(L, "f", &ar)) {
                return 0;
            }

            uintptr_t pointer = (uintptr_t)lj_obj_ptr(L, lua::toraw(L, -1));
            uintptr_t id = Tracker::id(L);
            lua::pop(L);

            if (hooking_c_linkages.find(id) == hooking_c_linkages.end()) {
                return 0;
            }

            std::map<uintptr_t, int>& linkage = hooking_c_linkages[id];

            if (linkage.find(pointer) == linkage.end()) {
                return 0;
            }

            int top = lua::gettop(L);

            lua::pushref(L, linkage[pointer]);

            for (int i = 1; i <= top; i++) {
                lua::pushvalue(L, i);
            }

            inside_semaphore++;
            int result = lua::pcall(L, top, -1, 0);
            inside_semaphore--;

            if (result && result != 1)
            {
                size_t size = 0;
                const char* error = lua::tolstring(L, -1, &size);
                lua::pop(L);
                luaL::error(L, std::string(error, size).c_str());
                return 0;
            }

            return lua::gettop(L) - top;
        }

        // for hooking with GC system
        int lsync(lua_State* L)
        {
            using namespace Engine;
            luaL::checkfunction(L, 1);
            luaL::checkfunction(L, 2);

            if (is(L, 1)) {
                luaL::error(L, "this function is already hooked");
                return 0;
            }

            uintptr_t pointer = (uintptr_t)lj_obj_ptr(L, lua::toraw(L, 1));
            uintptr_t id = Tracker::id(L);

            if (lua::iscfunction(L, 1)) { // hooking_c_linkages
                TValue* tv_target = lua::toraw(L, 1);
                GCfunc* gc_target = funcV(tv_target);

                // Create trackers for linkage & originals
                int lua_reference = luaL::newref(L, 2); // Need this to always exist & be tracked

                if (hooking_c_linkages.find(id) == hooking_c_linkages.end()) {
                    hooking_c_linkages[id] = std::map<uintptr_t, int>();
                }
                hooking_c_linkages[id][pointer] = lua_reference;

                if (hooking_c_originals.find(id) == hooking_c_originals.end()) {
                    hooking_c_originals[id] = std::map<uintptr_t, lua_CFunction>();
                }
                hooking_c_originals[id][pointer] = gc_target->c.f;

                if (hooking_state.find(id) == hooking_state.end()) {
                    hooking_state[id] = std::map<uintptr_t, bool>();
                }
                hooking_state[id][pointer] = true;

                // Create a clone acting as the original
                for (uint8_t i = 0; i < gc_target->c.nupvalues; i++) {
                    lua::pushnil(L);
                }

                lua::pushcclosure(L, blank, gc_target->c.nupvalues);

                TValue* tv_copy = lua::toraw(L, -1);
                GCfunc* gc_copy = funcV(tv_copy);

                for (uint8_t i = 0; i < gc_target->c.nupvalues; i++) {
                    gc_copy->c.upvalue[i] = gc_target->c.upvalue[i];
                }

                gc_copy->c.f = gc_target->c.f;
                gc_copy->c.env = gc_target->c.env;
                gc_copy->c.ffid = gc_target->c.ffid;

                // Remap the target function to the hook wrapper engine
                gc_target->c.f = wrapper;

                return 1; // return the cloned "original"
            }
            else { // hooking_lua_linkages
                TValue* tv_target = lua::toraw(L, 1);
                GCfunc* gc_target = funcV(tv_target);
                GCproto* proto_target = funcproto(gc_target);

                TValue* tv_replacer = lua::toraw(L, 2);
                GCfunc* gc_replacer = funcV(tv_replacer);
                GCproto* proto_replacer = funcproto(gc_replacer);

                if (gc_target->l.nupvalues != gc_replacer->l.nupvalues) {
                    luaL::error(L, (std::string("expected same function upvalue count (") + std::to_string(gc_target->c.nupvalues) + " != " + std::to_string(gc_replacer->c.nupvalues) + ")").c_str());
                    return 0;
                }

                // Create trackers for linkage & originals
                int lua_reference = luaL::newref(L, 2); // Need this to always exist & be tracked

                if (hooking_lua_linkages.find(id) == hooking_lua_linkages.end()) {
                    hooking_lua_linkages[id] = std::map<uintptr_t, int>();
                }
                hooking_lua_linkages[id][pointer] = lua_reference;

                if (hooking_state.find(id) == hooking_state.end()) {
                    hooking_state[id] = std::map<uintptr_t, bool>();
                }
                hooking_state[id][pointer] = true;

                // Create a clone acting as the original
                lua::pushlfunction(L, proto_target);
                TValue* tv_copy = lua::toraw(L, -1);
                GCfunc* gc_copy = funcV(tv_copy);

                gc_copy->l.env = gc_target->l.env;
                for (uint8_t i = 0; i < gc_target->l.nupvalues; i++) {
                    gc_copy->l.uvptr[i] = gc_target->l.uvptr[i];
                }

                lua::pushvalue(L, -1);
                int lua_original = luaL::newref(L, -1);

                if (hooking_lua_originals.find(id) == hooking_lua_originals.end()) {
                    hooking_lua_originals[id] = std::map<uintptr_t, int>();
                }
                hooking_lua_originals[id][pointer] = lua_original;

                // Remap the target function to the hook function
                setmref(gc_target->l.pc, proto_bc(proto_replacer));
                gc_target->l.env = gc_replacer->l.env;
                gc_target->l.nupvalues = gc_replacer->l.nupvalues;
                for (uint8_t i = 0; i < gc_replacer->l.nupvalues; i++) {
                    gc_target->l.uvptr[i] = gc_replacer->l.uvptr[i];
                }

                return 1; // return the cloned "original"
            }

            return 0;
        }

        #ifdef MH_ALL_HOOKS
        // for translation of c hooking a c-function
        int wrapperc(lua_State* L) {
            using namespace Engine;

            lua_Debug ar;
            if (!lua::getstack(L, 0, &ar)) {
                return 0;
            }

            if (!lua::getinfo(L, "f", &ar)) {
                return 0;
            }

            TValue* tv_target = lua::toraw(L, -1);
            GCfuncC* func_target = funcV(tv_target).c;
            uintptr_t pointer = (uintptr_t)func_target->f;
            uintptr_t id = Tracker::id(L);
            lua::pop(L);

            if (hooking_mh_linkages.find(id) == hooking_mh_linkages.end()) {
                return 0;
            }

            std::map<uintptr_t, int>& linkage = hooking_mh_linkages[id];

            if (linkage.find(pointer) == linkage.end()) {
                return 0;
            }

            int top = lua::gettop(L);

            lua::pushref(L, linkage[pointer]);

            for (int i = 1; i <= top; i++) {
                lua::pushvalue(L, i);
            }

            inside_semaphore++;
            int result = lua::pcall(L, top, -1, 0);
            inside_semaphore--;

            if (result && result != 1)
            {
                size_t size = 0;
                const char* error = lua::tolstring(L, -1, &size);
                lua::pop(L);
                luaL::error(L, std::string(error, size).c_str());
                return 0;
            }

            return lua::gettop(L) - top;
        }

        // for hooking with JMP rewrites (MH)
        int lasync(lua_State* L)
        {
            using namespace Engine;
            luaL::checkcfunction(L, 1);
            luaL::checkfunction(L, 2);

            if (is(L, 1)) {
                luaL::error(L, "this function is already hooked");
                return 0;
            }

            MH_STATUS state_initialize = MH_Initialize();
            if (state_initialize != MH_OK && state_initialize != MH_ERROR_ALREADY_INITIALIZED) {
                lua::pushboolean(L, false);
                return 1;
            }

            TValue* tv_target = lua::toraw(L, 1);
            GCfunc* gc_target = funcV(tv_target);
            uintptr_t pointer = (uintptr_t)gc_target->c.f;
            uintptr_t id = Tracker::id(L);

            int lua_reference = luaL::newref(L, 2);

            lua_CFunction wrapperc_original;
            if (MH_CreateHook((void*)gc_target->c.f, &wrapperc, reinterpret_cast<void**>(&wrapperc_original)) != MH_OK) {
                lua::pushboolean(L, false);
                return 1;
            }

            MH_EnableHook(gc_target->c.f);

            if (hooking_mh_linkages.find(id) == hooking_mh_linkages.end()) {
                hooking_mh_linkages[id] = std::map<uintptr_t, int>();
            }
            hooking_mh_linkages[id][pointer] = lua_reference;

            if (hooking_mh_originals.find(id) == hooking_mh_originals.end()) {
                hooking_mh_originals[id] = std::map<uintptr_t, lua_CFunction>();
            }
            hooking_mh_originals[id][pointer] = wrapperc_original;

            if (hooking_state.find(id) == hooking_state.end()) {
                hooking_state[id] = std::map<uintptr_t, bool>();
            }
            hooking_state[id][pointer] = true;

            for (uint8_t i = 0; i < gc_target->c.nupvalues; i++) {
                lua::pushnil(L);
            }

            lua::pushcclosure(L, wrapperc_original, gc_target->c.nupvalues);

            TValue* tv_copy = lua::toraw(L, -1);
            GCfunc* gc_copy = funcV(tv_copy);

            for (uint8_t i = 0; i < gc_target->c.nupvalues; i++) {
                gc_copy->c.upvalue[i] = gc_target->c.upvalue[i];
            }
            gc_copy->c.env = gc_target->c.env;
            gc_copy->c.ffid = gc_target->c.ffid;

            return 1;
        }
        #else
        int lasync(lua_State* L)
        {
            using namespace Engine;
            luaL::error(L, "async hooking is missing required libraries");
            return 0;
        }
        #endif

        int loriginal(lua_State* L)
        {
            using namespace Engine;
            luaL::checkfunction(L, 1);

            if (is(L, 1)) {
                luaL::error(L, "this function is not hooked");
                return 0;
            }

            uintptr_t pointer = (uintptr_t)lj_obj_ptr(L, lua::toraw(L, 1));
            uintptr_t id = Tracker::id(L);

            if (is_lua(L, 1)) {
                lua::pushref(L, hooking_lua_originals[id][pointer]);
                return 1;
            }
            else if (is_c(L, 1)) {
                lua_CFunction original = (lua_CFunction)hooking_c_originals[id][pointer];

                TValue* tv_target = lua::toraw(L, 1);
                GCfunc* gc_target = funcV(tv_target);

                for (uint8_t i = 0; i < gc_target->c.nupvalues; i++) {
                    lua::pushnil(L);
                }

                lua::pushcclosure(L, original, gc_target->c.nupvalues);

                TValue* tv_copy = lua::toraw(L, -1);
                GCfunc* gc_copy = funcV(tv_copy);

                for (uint8_t i = 0; i < gc_target->c.nupvalues; i++) {
                    gc_copy->c.upvalue[i] = gc_target->c.upvalue[i];
                }
                gc_copy->c.env = gc_target->c.env;
                gc_copy->c.ffid = gc_target->c.ffid;

                return 1;
            }
            #ifdef MH_ALL_HOOKS
            else if (is_mh(L, 1)) {
                TValue* tv_target = lua::toraw(L, 1);
                GCfunc* gc_target = funcV(tv_target);
                uintptr_t pointer = (uintptr_t)gc_target->c.f;
                lua_CFunction original = (lua_CFunction)hooking_mh_originals[id][pointer];

                for (uint8_t i = 0; i < gc_target->c.nupvalues; i++) {
                    lua::pushnil(L);
                }

                lua::pushcclosure(L, original, gc_target->c.nupvalues);

                TValue* tv_copy = lua::toraw(L, -1);
                GCfunc* gc_copy = funcV(tv_copy);

                for (uint8_t i = 0; i < gc_target->c.nupvalues; i++) {
                    gc_copy->c.upvalue[i] = gc_target->c.upvalue[i];
                }
                gc_copy->c.env = gc_target->c.env;
                gc_copy->c.ffid = gc_target->c.ffid;

                return 1;
            }
            #endif

            return 0;
        }

        int lrestore(lua_State* L)
        {
            using namespace Engine;
            luaL::checkfunction(L, 1);

            if (!is(L, 1)) {
                luaL::error(L, "this function is not hooked");
                return 0;
            }

            uintptr_t id = Tracker::id(L);

            if (is_lua(L, 1)) {
                uintptr_t pointer = (uintptr_t)lj_obj_ptr(L, lua::toraw(L, 1));
                int lua_reference = hooking_lua_linkages[id][pointer];
                int lua_original = hooking_lua_originals[id][pointer];

                if (hooking_state[id][pointer]) {
                    TValue* tv_target = lua::toraw(L, 1);
                    GCfunc* gc_target = funcV(tv_target);

                    lua::pushref(L, lua_original);
                    TValue* tv_replacer = lua::toraw(L, -1);
                    GCfunc* gc_replacer = funcV(tv_replacer);
                    GCproto* proto_replacer = funcproto(gc_replacer);

                    if (gc_target->l.nupvalues != gc_replacer->l.nupvalues) {
                        lua::pop(L);
                        luaL::error(L, (std::string("expected same function upvalue count (") + std::to_string(gc_target->c.nupvalues) + " != " + std::to_string(gc_replacer->c.nupvalues) + ")").c_str());
                        return 0;
                    }

                    setmref(gc_target->l.pc, proto_bc(proto_replacer));
                    gc_target->l.env = gc_replacer->l.env;
                    gc_target->l.nupvalues = gc_replacer->l.nupvalues;
                    for (uint8_t i = 0; i < gc_replacer->l.nupvalues; i++) {
                        gc_target->l.uvptr[i] = gc_replacer->l.uvptr[i];
                    }

                    lua::pop(L);
                }

                hooking_lua_linkages[id].erase(pointer);
                hooking_lua_originals[id].erase(pointer);
                hooking_state[id].erase(pointer);
                luaL::rmref(L, lua_reference);
                luaL::rmref(L, lua_original);
            }
            else if (is_c(L, 1)) {
                uintptr_t pointer = (uintptr_t)lj_obj_ptr(L, lua::toraw(L, 1));

                if (hooking_state[id][pointer]) {
                    TValue* tv_target = lua::toraw(L, 1);
                    GCfunc* gc_target = funcV(tv_target);
                    gc_target->c.f = hooking_c_originals[id][pointer];
                }

                luaL::rmref(L, hooking_c_linkages[id][pointer]);
                hooking_c_linkages[id].erase(pointer);
                hooking_c_originals[id].erase(pointer);
                hooking_state[id].erase(pointer);
            }
            #ifdef MH_ALL_HOOKS
            else if (is_mh(L, 1)) {
                TValue* tv_target = lua::toraw(L, 1);
                GCfunc* gc_target = funcV(tv_target);
                uintptr_t pointer = (uintptr_t)gc_target->c.f;
                MH_RemoveHook((void*)gc_target->c.f);
                hooking_mh_linkages[id].erase(pointer);
                hooking_mh_originals[id].erase(pointer);
                hooking_state[id].erase(pointer);
            }
            #endif

            lua::pushboolean(L, true); // TODO: should return a proper status boolean

            return 1;
        }

        int lis(lua_State* L)
        {
            using namespace Engine;
            luaL::checkfunction(L, 1);
            lua::pushboolean(L, is(L, 1));
            return 1;
        }

        int linside(lua_State* L)
        {
            using namespace Engine;

            for (int i = 1; i < 200; i++) {
                lua_Debug ar;
                if (!lua::getstack(L, i, &ar)) {
                    break;
                }

                if (!lua::getinfo(L, "f", &ar)) {
                    break;
                }

                uintptr_t pointer = (uintptr_t)lj_obj_ptr(L, lua::toraw(L, -1));
                uintptr_t id = Tracker::id(L);
                lua::pop(L);

                if (hooking_lua_linkages.find(id) != hooking_lua_linkages.end()) {
                    auto& entries = hooking_lua_linkages[id];
                    if (entries.find(pointer) != entries.end()) {
                        lua::pushboolean(L, true);
                        return 1;
                    }
                }
            }

            lua::pushboolean(L, inside_semaphore > 0);
            return 1;
        }

        int lactive(lua_State* L)
        {
            using namespace Engine;
            luaL::checkfunction(L, 1);

            if (!is(L, 1)) {
                lua::pushboolean(L, false);
                return 1;
            }

            uintptr_t pointer = (uintptr_t)lj_obj_ptr(L, lua::toraw(L, 1));
            uintptr_t id = Tracker::id(L);

            lua::pushboolean(L, hooking_state[id][pointer]);
            return 1;
        }

        int lenable(lua_State* L)
        {
            using namespace Engine;
            luaL::checkfunction(L, 1);

            if (!is(L, 1)) {
                luaL::error(L, "this function is not hooked");
                return 0;
            }

            uintptr_t id = Tracker::id(L);

            if (is_lua(L, 1)) {
                TValue* tv_target = lua::toraw(L, 1);
                uintptr_t pointer = (uintptr_t)lj_obj_ptr(L, tv_target);

                if (hooking_state[id][pointer]) {
                    lua::pushboolean(L, false);
                    return 1;
                }

                GCfunc* gc_target = funcV(tv_target);

                int lua_reference = hooking_lua_linkages[id][pointer];

                lua::pushref(L, lua_reference);
                TValue* tv_replacer = lua::toraw(L, -1);
                GCfunc* gc_replacer = funcV(tv_replacer);
                GCproto* proto_replacer = funcproto(gc_replacer);

                if (gc_target->l.nupvalues != gc_replacer->l.nupvalues) {
                    lua::pop(L);
                    luaL::error(L, (std::string("expected same function upvalue count (") + std::to_string(gc_target->c.nupvalues) + " != " + std::to_string(gc_replacer->c.nupvalues) + ")").c_str());
                    return 0;
                }

                setmref(gc_target->l.pc, proto_bc(proto_replacer));
                gc_target->l.env = gc_replacer->l.env;
                gc_target->l.nupvalues = gc_replacer->l.nupvalues;
                for (uint8_t i = 0; i < gc_replacer->l.nupvalues; i++) {
                    gc_target->l.uvptr[i] = gc_replacer->l.uvptr[i];
                }

                hooking_state[id][pointer] = true;
            }
            else if (is_c(L, 1)) {
                TValue* tv_target = lua::toraw(L, 1);
                uintptr_t pointer = (uintptr_t)lj_obj_ptr(L, tv_target);

                if (hooking_state[id][pointer]) {
                    lua::pushboolean(L, false);
                    return 1;
                }

                GCfunc* gc_target = funcV(tv_target);
                gc_target->c.f = wrapper;
                hooking_state[id][pointer] = true;
            }
            #ifdef MH_ALL_HOOKS
            else if (is_mh(L, 1)) {
                TValue* tv_target = lua::toraw(L, 1);
                GCfunc* gc_target = funcV(tv_target);
                uintptr_t pointer = (uintptr_t)gc_target->c.f;

                if (hooking_state[id][pointer]) {
                    lua::pushboolean(L, false);
                    return 1;
                }

                MH_EnableHook((void*)gc_target->c.f);
                hooking_state[id][pointer] = true;
            }
            #endif

            lua::pushboolean(L, true);

            return 1;
        }

        int ldisable(lua_State* L)
        {
            using namespace Engine;
            luaL::checkfunction(L, 1);

            if (!is(L, 1)) {
                luaL::error(L, "this function is not hooked");
                return 0;
            }

            uintptr_t id = Tracker::id(L);

            if (is_lua(L, 1)) {
                TValue* tv_target = lua::toraw(L, 1);
                uintptr_t pointer = (uintptr_t)lj_obj_ptr(L, tv_target);

                if (!hooking_state[id][pointer]) {
                    lua::pushboolean(L, false);
                    return 1;
                }

                GCfunc* gc_target = funcV(tv_target);

                int lua_original = hooking_lua_originals[id][pointer];

                lua::pushref(L, lua_original);
                TValue* tv_replacer = lua::toraw(L, -1);
                GCfunc* gc_replacer = funcV(tv_replacer);
                GCproto* proto_replacer = funcproto(gc_replacer);

                if (gc_target->l.nupvalues != gc_replacer->l.nupvalues) {
                    lua::pop(L);
                    luaL::error(L, (std::string("expected same function upvalue count (") + std::to_string(gc_target->c.nupvalues) + " != " + std::to_string(gc_replacer->c.nupvalues) + ")").c_str());
                    return 0;
                }

                setmref(gc_target->l.pc, proto_bc(proto_replacer));
                gc_target->l.env = gc_replacer->l.env;
                gc_target->l.nupvalues = gc_replacer->l.nupvalues;
                for (uint8_t i = 0; i < gc_replacer->l.nupvalues; i++) {
                    gc_target->l.uvptr[i] = gc_replacer->l.uvptr[i];
                }

                hooking_state[id][pointer] = false;
            }
            else if (is_c(L, 1)) {
                TValue* tv_target = lua::toraw(L, 1);
                uintptr_t pointer = (uintptr_t)lj_obj_ptr(L, tv_target);

                if (!hooking_state[id][pointer]) {
                    lua::pushboolean(L, false);
                    return 1;
                }

                GCfunc* gc_target = funcV(tv_target);
                gc_target->c.f = hooking_c_originals[id][pointer];
                hooking_state[id][pointer] = false;
            }
            #ifdef MH_ALL_HOOKS
            else if (is_mh(L, 1)) {
                TValue* tv_target = lua::toraw(L, 1);
                GCfunc* gc_target = funcV(tv_target);
                uintptr_t pointer = (uintptr_t)gc_target->c.f;

                if (!hooking_state[id][pointer]) {
                    lua::pushboolean(L, false);
                    return 1;
                }

                MH_DisableHook((void*)gc_target->c.f);
                hooking_state[id][pointer] = false;
            }
            #endif

            lua::pushboolean(L, true);

            return 1;
        }
    }

    #ifdef __linux
    #if defined(__INTEL_COMPILER) && (defined(__i386__) || defined(__x86_64__))
        static LJ_AINLINE uint32_t lj_fls(uint32_t x)
        {
            uint32_t r; __asm__("bsrl %1, %0" : "=r" (r) : "rm" (x) : "cc"); return r;
        }
    #else
    #define lj_fls(x)	((uint32_t)(__builtin_clz(x)^31))
    #endif
    #else
        static uint32_t lj_fls(uint32_t x)
        {
            unsigned long r; _BitScanReverse(&r, x); return (uint32_t)r;
        }
    #endif

    #define STRFMT_MAXBUF_PTR	(2+2*sizeof(ptrdiff_t))
    char* lj_strfmt_wptr(const void* v) {
        ptrdiff_t x = (ptrdiff_t)v;
        uint32_t i, n = STRFMT_MAXBUF_PTR;

        char* p = (char*)malloc(n + 1);
        if (!p) {
            return nullptr;
        }

        if (x == 0) {
            memcpy(p, "NULL", 5);
            return p;
        }

        // Hexadecimal pointer formatting
#if LJ_64
        n = 2 + 2 * 4 + ((x >> 32) ? 2 + 2 * (lj_fls((uint32_t)(x >> 32)) >> 3) : 0);
#endif

        p[0] = '0';
        p[1] = 'x';
        for (i = n - 1; i >= 2; i--, x >>= 4)
            p[i] = "0123456789abcdef"[(x & 15)];

        p[n] = '\0';
        return p;
    }

    int topointer(lua_State* L)
    {
        const void* pointer = lj_obj_ptr(L, lua::toraw(L, 1));

        if (lua::istype(L, 2, datatype::boolean) && lua::toboolean(L, 2)) {
            lua::pushstring(L, lj_strfmt_wptr(pointer));
        }
        else {
            lua::pushnumber(L, (uintptr_t)pointer);
        }

        return 1;
    }

    lua_State* getthread(lua_State* L, int* is_thread)
    {
        if (lua::gettype(L, 1) == 8)
        {
            *is_thread = 1;
            return lua::tothread(L, 1);
        }

        *is_thread = 0;
        return L;
    }

    lua_State* getthread(lua_State* L, int stack, int* is_thread)
    {
        if (lua::gettype(L, stack) == 8)
        {
            *is_thread = 1;
            return lua::tothread(L, stack);
        }

        *is_thread = 0;
        return L;
    }

    void checkstack(lua_State* L, lua_State* L1, int n)
    {
        if (L != L1 && !lua::checkstack(L1, n))
            luaL::error(L, "stack overflow");
    }

    int setlocal(lua_State* L)
    {
        int arg;
        lua_State* L1 = getthread(L, &arg);
        lua_Debug ar;
        if (!lua::getstack(L1, luaL::checknumber(L, arg + 1), &ar))
            return luaL::argerror(L, arg + 1, "level out of range");
        luaL::checkany(L, arg + 3);
        lua::settop(L, arg + 3);
        checkstack(L, L1, 1);
        lua::xmove(L, L1, 1);
        lua::pushstring(L, lua::setlocal(L1, &ar, luaL::checknumber(L, arg + 2)));
        return 1;
    }

    int getlocal(lua_State* L)
    {
        lua_State* L1;
        int arg;

        L1 = getthread(L, &arg);

        lua_Debug ar;
        if (!lua::getstack(L1, luaL::checknumber(L, arg + 1), &ar))
            return luaL::argerror(L, arg + 1, "level out of range");

        int idx = luaL::checknumber(L, arg + 2);
        if (idx < 1) {
            return 0;
        }

        const char* lname = lua::getlocal(L1, &ar, idx);
        if (lname) {
            lua::pushstring(L, lname);
            lua::insert(L, -2);
            return 2;
        }

        return 0;
    }

    int setupvalue(lua_State* L)
    {
        luaL::checkfunction(L, 1);
        size_t upvalue = luaL::checknumber(L, 2);
        luaL::checkany(L, 3);
        lua::pushvalue(L, 3);
        const char* name = lua::setupvalue(L, 1, upvalue);
        if (name == nullptr) return 0;
        lua::pushstring(L, name);
        return 1;
    }

    int getupvalue(lua_State* L)
    {
        luaL::checkfunction(L, 1);
        size_t upvalue = luaL::checknumber(L, 2);
        const char* name = lua::getupvalue(L, 1, upvalue);
        if (name == nullptr) return 0;
        lua::pushstring(L, name);
        lua::insert(L, -2);
        return 2;
    }

    int getconstant(lua_State* L)
    {
        using namespace Engine;

        if (!lua::isproto(L, 1) && !lua::islfunction(L, 1)) {
            luaL::error(L, "expected lfunction or proto");
            return 0;
        }

        TValue* tv_target = lua::toraw(L, 1);
        GCproto* proto_target = nullptr;
        if (lua::isproto(L, 1)) {
            proto_target = protoV(tv_target);
        }
        else {
            proto_target = funcproto(funcV(tv_target));
        }

        MSize index = luaL::checknumber(L, 2);

        auto size_n = proto_target->sizekn;
        auto size_gc = proto_target->sizekgc;

        MSize counter = 0;
        GCRef* kr = mref(proto_target->k, GCRef) - (ptrdiff_t)size_gc;
        for (MSize i = 0; i < size_gc; i++, kr++) {
            GCobj* object = gcref(*kr);
            if (++counter == index) {
                lua::pushraw(L, object);
                return 1;
            }
        }

        TValue* o = mref(proto_target->k, TValue);
        for (MSize i = 0; i < size_n; i++, o++) {
            lua_Number number = numV(o);
            if (++counter == index) {
                lua::pushnumber(L, number);
                return 1;
            }
        }

        return 0;
    }

    int getconstants(lua_State* L)
    {
        using namespace Engine;

        if (!lua::isproto(L, 1) && !lua::islfunction(L, 1)) {
            luaL::error(L, "expected lfunction or proto");
            return 0;
        }

        TValue* tv_target = lua::toraw(L, 1);
        GCproto* proto_target = nullptr;
        if (lua::isproto(L, 1)) {
            proto_target = protoV(tv_target);
        }
        else {
            proto_target = funcproto(funcV(tv_target));
        }

        auto size_n = proto_target->sizekn;
        auto size_gc = proto_target->sizekgc;

        lua::newtable(L);

        MSize counter = 0;
        GCRef* kr = mref(proto_target->k, GCRef) - (ptrdiff_t)size_gc;
        for (MSize i = 0; i < size_gc; i++, kr++) {
            GCobj* object = gcref(*kr);
            lua::pushnumber(L, ++counter);
            lua::pushraw(L, object);
            lua::settable(L, -3);
        }

        TValue* o = mref(proto_target->k, TValue);
        for (MSize i = 0; i < size_n; i++, o++) {
            lua_Number number = numV(o);
            lua::pushnumber(L, ++counter);
            lua::pushnumber(L, number);
            lua::settable(L, -3);
        }

        return 1;
    }

    int setconstant(lua_State* L)
    {
        using namespace Engine;

        if (!lua::isproto(L, 1) && !lua::islfunction(L, 1)) {
            luaL::error(L, "expected lfunction or proto");
            return 0;
        }

        TValue* tv_target = lua::toraw(L, 1);
        GCproto* proto_target = nullptr;
        if (lua::isproto(L, 1)) {
            proto_target = protoV(tv_target);
        }
        else {
            proto_target = funcproto(funcV(tv_target));
        }

        MSize index = luaL::checknumber(L, 2);
        if (lua::istype(L, 3, datatype::none)) {
            luaL::error(L, "missing value in 3rd argument");
            return 0;
        }
        TValue* data = lua::toraw(L, 3);

        auto size_n = proto_target->sizekn;
        auto size_gc = proto_target->sizekgc;

        MSize counter = 0;
        GCRef* kr = mref(proto_target->k, GCRef) - (ptrdiff_t)size_gc;
        for (MSize i = 0; i < size_gc; i++, kr++) {
            GCobj* object = gcref(*kr);
            if (++counter == index) {
                GCobj* value = gcV(data);
                setgcref(*kr, value);
                lua::pushboolean(L, true);
                return 1;
            }
        }

        TValue* o = mref(proto_target->k, TValue);
        for (MSize i = 0; i < size_n; i++, o++) {
            lua_Number number = numV(o);
            if (++counter == index) {
                o->n = data->n;
                lua::pushboolean(L, true);
                return 1;
            }
        }

        lua::pushboolean(L, false);
        return 1;
    }

    int toproto(lua_State* L)
    {
        using namespace Engine;
        luaL::checklfunction(L, 1);
        TValue* func = lua::toraw(L, 1);
        GCfunc* gcfunc = funcV(func);
        GCproto* protofunc = funcproto(gcfunc);
        lua::pushraw(L, (GCobj*)protofunc);
        return 1;
    }

    int fromproto(lua_State* L)
    {
        using namespace Engine;
        luaL::checkproto(L, 1);
        TValue* tv_target = lua::toraw(L, 1);
        GCproto* proto_target = protoV(tv_target);
        lua::pushlfunction(L, proto_target);
        return 1;
    }

    int getprotos(lua_State* L) {
        using namespace Engine;

        if (!lua::isproto(L, 1) && !lua::islfunction(L, 1)) {
            luaL::error(L, "expected lfunction or proto");
            return 0;
        }

        TValue* tv_target = lua::toraw(L, 1);
        GCproto* proto_target = nullptr;
        if (lua::isproto(L, 1)) {
            proto_target = protoV(tv_target);
        }
        else {
            proto_target = funcproto(funcV(tv_target));
        }

        auto size_gc = proto_target->sizekgc;

        lua::newtable(L);

        MSize counter = 0;
        GCRef* kr = mref(proto_target->k, GCRef) - (ptrdiff_t)size_gc;
        for (MSize i = 0; i < size_gc; i++, kr++) {
            GCobj* object = gcref(*kr);
            if (~object->gch.gct == LJ_TPROTO) {
                lua::pushnumber(L, ++counter);
                lua::pushraw(L, object);
                lua::settable(L, -3);
            }
        }

        return 1;
    }

    int tosignature(lua_State* L) {
        using namespace Engine;

        if (!lua::isproto(L, 1) && !lua::islfunction(L, 1)) {
            luaL::error(L, "expected function or proto");
            return 0;
        }

        std::string flags = "ocu";
        if (lua::isstring(L, 2)) {
            flags = lua::tocstring(L, 2);
        }

        size_t max_size = 20;
        if (lua::isnumber(L, 3)) {
            max_size = lua::tonumber(L, 3);
        }

        TValue* tv_target = lua::toraw(L, 1);
        GCfunc* func_target = nullptr;
        GCproto* proto_target = nullptr;

        std::stringstream signature;

        if (lua::isproto(L, 1)) {
            proto_target = protoV(tv_target);
            signature << "P";
        }
        else {
            func_target = funcV(tv_target);
            proto_target = funcproto(func_target);
            signature << "F";
        }

        if (flags.find('o') != std::string::npos) {
            signature << "OP";
            BCIns* bc_target = proto_bc(proto_target);
            for (uint32_t i = 0; i < (((proto_target->sizebc) < (max_size)) ? (proto_target->sizebc) : (max_size)); i++) {
                BCIns ins = bc_target[i];
                BCOp op = bc_op(ins);
                if (op >= BC__MAX) {
                    continue;
                }
                signature << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(static_cast<unsigned char>(op));
            }
        }

        auto size_n = proto_target->sizekn;
        auto size_gc = proto_target->sizekgc;

        if (flags.find('c') != std::string::npos && (size_n + size_gc) > 0) {
            signature << "CT";

            MSize counter = 0;
            GCRef* kr = mref(proto_target->k, GCRef) - (ptrdiff_t)size_gc;
            for (MSize i = 0; i < size_gc; i++, kr++) {
                GCobj* object = gcref(*kr);
                if (counter++ >= max_size) break;
                signature << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(static_cast<unsigned char>(object->gch.gct));
            }

            TValue* o = mref(proto_target->k, TValue);
            for (MSize i = 0; i < size_n; i++, o++) {
                if (counter++ >= max_size) break;
                signature << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(static_cast<unsigned char>(~LJ_TNUMX));
            }
        }

        if (func_target) {
            if (flags.find('u') != std::string::npos && func_target->l.nupvalues > 0) {
                signature << "UT";
                for (int i = 0; i < (((func_target->l.nupvalues) < (max_size)) ? (func_target->l.nupvalues) : (max_size)); ++i) {
                    GCupval* uv = (GCupval*)gcref(func_target->l.uvptr[i]);
                    signature << std::hex << std::setw(2) << std::setfill('0')
                        << static_cast<int>(static_cast<unsigned char>(~itype(mref(uv->v, TValue))));
                }
            }
        }
        else {
            if (flags.find('u') != std::string::npos && proto_target->sizeuv > 0) {
                signature << "UT" << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(static_cast<unsigned char>(proto_target->sizeuv));
            }
        }

        lua::pushcstring(L, signature.str());

        return 1;
    }

    int fromsignature(lua_State* L) {
        using namespace Engine;

        std::string _signature = luaL::checkcstring(L, 1);
        std::string signature;
        for (char ch : std::string(_signature)) {
            if (!std::isspace(static_cast<unsigned char>(ch))) {
                signature += ch;
            }
        }

        char target_type = signature.at(0);
        signature.erase(signature.begin());

        if (target_type != 'F' && target_type != 'P') {
            return 0;
        }

        global_State* gs = mref(L->glref, global_State);
        if (!gs) {
            return 0;
        }

        GCobj* gcobject = gcref(gs->gc.root);

        while (gcobject) {
            if (!isdead(gs, gcobject)) {
                uint8_t type = gcobject->gch.gct;

                if ((type == ~LJ_TFUNC && target_type == 'F') || (type == ~LJ_TPROTO && target_type == 'P')) {
                    GCfunc* func_target = nullptr;
                    GCproto* proto_target = nullptr;

                    if (type == ~LJ_TFUNC) {
                        func_target = (GCfunc*)gcobject;
                        if (func_target->l.ffid == FF_LUA) {
                            proto_target = funcproto(func_target);
                        }
                    }
                    else {
                        proto_target = (GCproto*)gcobject;
                    }

                    if (proto_target) {
                        BCIns* bc_target = proto_bc(proto_target);
                        auto size_n = proto_target->sizekn;
                        auto size_gc = proto_target->sizekgc;

                        std::string mode = "OP";
                        size_t index = 0;

                        bool found = true;
                        for (size_t i = 0; i < signature.size(); i += 2) {
                            std::string pair = signature.substr(i, 2);  // Get 2-character substring

                            if (pair == "OP" || pair == "CT" || pair == "UT") {
                                index = 0;
                                mode = pair;
                                continue;
                            }

                            if (mode == "OP") {
                                if (index > proto_target->sizebc) {
                                    found = false;
                                    break;
                                }

                                BCIns ins = bc_target[index];
                                BCOp op = bc_op(ins);

                                std::stringstream code;
                                code << std::hex << std::setw(2) << std::setfill('0')
                                    << static_cast<int>(static_cast<unsigned char>(op));

                                if (pair != code.str()) {
                                    found = false;
                                    break;
                                }

                                index++;
                            }
                            else if (mode == "CT") {
                                GCRef* kr = mref(proto_target->k, GCRef) - (ptrdiff_t)size_gc;
                                TValue* o = mref(proto_target->k, TValue);

                                if (index < size_gc) {
                                    GCobj* object = gcref(kr[index]);
                                    std::stringstream code;
                                    code << std::hex << std::setw(2) << std::setfill('0')
                                        << static_cast<int>(static_cast<unsigned char>(object->gch.gct));

                                    if (pair != code.str()) {
                                        found = false;
                                        break;
                                    }
                                }
                                else if (index - size_gc < size_n) {
                                    std::stringstream code;
                                    code << std::hex << std::setw(2) << std::setfill('0')
                                        << static_cast<int>(static_cast<unsigned char>(~LJ_TNUMX));

                                    if (pair != code.str()) {
                                        found = false;
                                        break;
                                    }
                                }
                                else {
                                    found = false;
                                    break;
                                }

                                index++;
                            }
                            else if (mode == "UT") {
                                if (func_target) {
                                    if ((index + 1) > func_target->l.nupvalues) {
                                        found = false;
                                        break;
                                    }

                                    GCupval* uv = (GCupval*)gcref(func_target->l.uvptr[index]);

                                    std::stringstream code;
                                    code << std::hex << std::setw(2) << std::setfill('0')
                                        << static_cast<int>(static_cast<unsigned char>(~itype(mref(uv->v, TValue))));

                                    if (pair != code.str()) {
                                        found = false;
                                        break;
                                    }

                                    index++;
                                }
                                else {
                                    std::stringstream code;
                                    code << std::hex << std::setw(2) << std::setfill('0')
                                        << static_cast<int>(static_cast<unsigned char>(proto_target->sizeuv));

                                    if (pair != code.str()) {
                                        found = false;
                                        break;
                                    }
                                }
                            }
                        }

                        if (found) {
                            lua::pushraw(L, gcobject);
                            return 1;
                        }
                    }
                }
            }

            gcobject = gcref(gcobject->gch.nextgc);
        }

        return 0;
    }

    int iscfunct(lua_State* L)
    {
        lua::pushboolean(L, lua::iscfunction(L, 1));
        return 1;
    }

    int islfunct(lua_State* L)
    {
        lua::pushboolean(L, lua::islfunction(L, 1));
        return 1;
    }

    int setbuiltin(lua_State* L)
    {
        int ffid = luaL::checknumber(L, 2);
        if (ffid <= 0) {
            luaL::error(L, "Cannot set this to this builtin id.");
            return 0;
        }

        luaL::checktype(L, 1, datatype::function);
        if (!lua::iscfunction(L, 1)) {
            luaL::error(L, "Must be a C function.");
            return 0;
        }

        using namespace Engine;
        GCfunc* func = funcV(lua::toraw(L, 1));
        func->c.ffid = ffid;
        return 0;
    }

    int getbuiltin(lua_State* L)
    {
        luaL::checktype(L, 1, datatype::function);
        if (!lua::iscfunction(L, 1)) {
            luaL::error(L, "Must be a C function.");
            return 0;
        }

        using namespace Engine;
        GCfunc* func = funcV(lua::toraw(L, 1));
        lua::pushnumber(L, func->c.ffid);
        return 1;
    }

    int getupvalues(lua_State* L)
    {
        luaL::checktype(L, 1, datatype::function);

        lua_Debug ar;
        lua::pushvalue(L, 1);
        if (!lua::getinfo(L, ">flnSu", &ar)) {
            return 0;
        }

        lua::newtable(L);

        if (ar.nups <= 0) {
            return 1;
        }

        for (int i = 0; i <= ar.nups; ++i) {
            const char* name = lua::getupvalue(L, 1, i);
            if (name != nullptr) {
                lua::pushstring(L, name);
                lua::pushvalue(L, -2);
                lua::settable(L, -4);
                lua::pop(L);
            }
        }

        return 1;
    }

    // TODO: this was for debugging, we can make this more reliable than just a 0 < n < 100 range now...
    int typestack(lua_State* L)
    {
        int count = luaL::checknumber(L, 1);
        if (count > 100) luaL::error(L, "Number must be smaller than 100");
        if (count < 0) luaL::error(L, "Number cannot be negative");
        lua::pushstring(L, lua::typestack(L, count).c_str());
        return 1;
    }

    int getcallstack(lua_State* L)
    {
        using namespace Engine;

        lua::newtable(L);

        for (int level = 0; level < 200; level++) {
            int size;
            cTValue* frame = lj_debug_frame(L, level, &size);
            if (!frame) break;
            GCfunc* fn = frame_func(frame);
            if (!fn) break;
            lua::pushnumber(L, level + 1);
            lua::pushraw(L, (GCobj*)fn);
            lua::settable(L, -3);
        }

        return 1;
    }

    int getbase(lua_State* L)
    {
        using namespace Engine;
        int level = 0;
        if (lua::isnumber(L, 1)) {
            level = lua::tonumber(L, 1);
        }
        int size;
        cTValue* frame = lj_debug_frame(L, level, &size);
        if (!frame) return 0;
        GCfunc* fn = frame_func(frame);
        if (!fn) return 0;
        lua::pushraw(L, (GCobj*)fn);
        return 1;
    }

    int validlevel(lua_State* L)
    {
        using namespace Engine;

        int size;
        cTValue* frame = lj_debug_frame(L, luaL::checknumber(L, 1), &size);
        if (!frame) {
            lua::pushboolean(L, false); return 1;
        }
        GCfunc* fn = frame_func(frame);
        if (!fn) {
            lua::pushboolean(L, false); return 1;
        }

        lua::pushboolean(L, true);
        return 1;
    }

    int getgc_iterator(lua_State* L)
    {
        using namespace Engine;

        global_State* gs = mref(L->glref, global_State);
        if (!gs) {
            return 0;
        }

        ptrdiff_t id = lua::tonumber(L, API::upvalueindex(1));
        GCobj* gcobject = (GCobj*)lua::touserdata(L, API::upvalueindex(2));

        while (gcobject) {
            if (!isdead(gs, gcobject)) {
                uint8_t type = gcobject->gch.gct;
                if (type == ~LJ_TUDATA
                    || type == ~LJ_TPROTO
                    || type == ~LJ_TFUNC
                    || type == ~LJ_TTAB
                    || type == ~LJ_TCDATA)
                {
                    lua::pushnumber(L, id++);
                    lua::pushraw(L, gcobject);

                    lua::pushnumber(L, id);
                    lua::replace(L, API::upvalueindex(1));

                    gcobject = gcref(gcobject->gch.nextgc);
                    lua::pushlightuserdata(L, gcobject);
                    lua::replace(L, API::upvalueindex(2));

                    return 2;
                }
            }

            gcobject = gcref(gcobject->gch.nextgc);
        }

        return 0;
    }

    int getgc(lua_State* L)
    {
        using namespace Engine;

        if (lua::isboolean(L, 1) && lua::toboolean(L, 1)) {
            global_State* gs = mref(L->glref, global_State);
            if (!gs) return 0;
            lua::pushnumber(L, 1);
            lua::pushlightuserdata(L, gcref(gs->gc.root));
            lua::pushcclosure(L, getgc_iterator, 2);
            return 1;
        }

        global_State* gs = mref(L->glref, global_State);
        if (!gs) {
            lua::newtable(L);
            return 1;
        }

        lua::newtable(L);

        ptrdiff_t id = 1;
        GCobj* gcobject = gcref(gs->gc.root);

        while (gcobject) {
            if (!isdead(gs, gcobject)) {
                uint8_t type = gcobject->gch.gct;

                switch (type) {
                case ~LJ_TUDATA: {
                    lua::pushnumber(L, id++);
                    lua::pushraw(L, gcobject);
                    lua::settable(L, -3);
                    break;
                }
                case ~LJ_TPROTO: {
                    lua::pushnumber(L, id++);
                    lua::pushraw(L, gcobject);
                    lua::settable(L, -3);
                    break;
                }
                case ~LJ_TFUNC: {
                    lua::pushnumber(L, id++);
                    lua::pushraw(L, gcobject);
                    lua::settable(L, -3);
                    break;
                }
                case ~LJ_TTAB: {
                    lua::pushnumber(L, id++);
                    lua::pushraw(L, gcobject);
                    lua::settable(L, -3);
                    break;
                }
                case ~LJ_TCDATA: {
                    lua::pushnumber(L, id++);
                    lua::pushraw(L, gcobject);
                    lua::settable(L, -3);
                    break;
                }
                default:
                    break;
                }
            }

            gcobject = gcref(gcobject->gch.nextgc);
        }

        return 1;
    }

    int tscan(lua_State* L) {
        using namespace Engine;
        luaL::checktable(L, 1);
        luaL::checkfunction(L, 2);
        size_t max = 50;

        if (lua::isnumber(L, 3)) {
            max = lua::tonumber(L, 3);
        }

        GCobj* root = gcV(lua::toraw(L, 1));
        std::vector<GCobj*> cache;
        cache.push_back(root);
        std::unordered_map<GCobj*, std::vector<std::string>> resolution;
        resolution[root] = std::vector<std::string>();

        size_t count = 0;
        while (cache.size() > 0 && count < max) {
            count++;
            GCobj* entry = *cache.erase(cache.begin());
            uint8_t type = entry->gch.gct;

            if (type == ~LJ_TTAB) {
                lua::pushraw(L, entry);

                lua::pushvalue(L, 2);
                lua::pushvalue(L, -2);

                if (lua::tcall(L, 1, 1)) {
                    lua::remove(L, -2);
                    return 1;
                }

                if (lua::isboolean(L, -1) && lua::toboolean(L, -1)) {
                    lua::pop(L, 2);
                    lua::pushraw(L, entry);
                    lua::newtable(L);
                    if (resolution.find(entry) != resolution.end()) {
                        int i = 0;
                        for (auto& path : resolution[entry]) {
                            lua::pushnumber(L, ++i);
                            lua::pushcstring(L, path);
                            lua::settable(L, -3);
                        }
                    }
                    return 2;
                }

                lua::pop(L);

                // meta scanning
                if (lua::getmetatable(L, -1)) {
                    lua::remove(L, -2);

                    lua::getrfield(L, -1, "__index");
                    lua::remove(L, -2);

                    if (lua::istable(L, -1) || lua::islfunction(L, -1)) {
                        GCobj* target = gcV(lua::toraw(L, -1));
                        cache.push_back(target);
                        std::vector updated(resolution[entry]);
                        updated.push_back("M");
                        resolution[target] = updated;
                        lua::pop(L);
                    }
                    else {
                        lua::pop(L);
                    }
                }
            }
            else if (type == ~LJ_TFUNC && ((GCfunc*)entry)->l.ffid == FF_LUA) {
                lua::pushraw(L, entry);

                // upvalue scanning
                for (size_t index = 1; index <= entry->fn.l.nupvalues; index++) {
                    const char* name = lua::getupvalue(L, -1, index);
                    if (name == nullptr) break;
                    GCobj* target = gcV(lua::toraw(L, -1));
                    if (target == nullptr) {
                        lua::pop(L);
                        break;
                    }
                    uint8_t target_type = target->gch.gct;

                    if (target_type == ~LJ_TTAB || (target_type == ~LJ_TFUNC && ((GCfunc*)target)->l.ffid == FF_LUA)) {
                        cache.push_back(target);
                        std::vector updated = std::vector(resolution[entry]);
                        updated.push_back("U." + std::to_string(index));
                        resolution[target] = updated;
                    }

                    lua::pop(L);
                }

                lua::pop(L);

                // constant scanning
                GCproto* proto_target = funcproto((GCfunc*)entry);
                auto size_n = proto_target->sizekn;
                auto size_gc = proto_target->sizekgc;

                GCRef* kr = mref(proto_target->k, GCRef) - (ptrdiff_t)size_gc;
                for (MSize index = 0; index < size_gc; index++, kr++) {
                    GCobj* target = gcref(*kr);
                    if (target == nullptr) continue;
                    uint8_t target_type = target->gch.gct;

                    if (target_type == ~LJ_TTAB || (target_type == ~LJ_TFUNC && ((GCfunc*)target)->l.ffid == FF_LUA)) {
                        cache.push_back(target);
                        std::vector updated = std::vector(resolution[entry]);
                        updated.push_back("C." + std::to_string(index + 1));
                        resolution[target] = updated;
                    }
                }
            }
        }

        return 0;
    }

    int tresolve(lua_State* L) {
        using namespace Engine;
        luaL::checktable(L, 1);
        luaL::checktable(L, 2);

        size_t size = lua::objlen(L, 2);
        for (size_t i = 1; i <= size; i++) {
            lua::pushnumber(L, i);
            lua::gettable(L, 2);

            if (!lua::isstring(L, -1)) {
                lua::pop(L);
                continue;
            }

            std::string type = lua::tocstring(L, -1);
            lua::pop(L);

            char id = type.front();
            bool failure = false;

            switch (id) {
            case 'M': {
                if (!lua::istable(L, 1)) {
                    failure = true;
                    break;
                }

                if (!lua::getmetatable(L, 1)) {
                    failure = true;
                    break;
                }

                lua::getrfield(L, -1, "__index");
                lua::remove(L, -2);

                if (!lua::istable(L, -1) && !lua::isfunction(L, -1)) {
                    lua::pop(L);
                    failure = true;
                    break;
                }

                lua::replace(L, 1);

                break;
            }
            case 'U': {
                if (!lua::isfunction(L, 1)) {
                    failure = true;
                    break;
                }

                size_t uv = 0;
                size_t dotPos = type.find('.');
                if (dotPos != std::string::npos && dotPos + 1 < type.size()) {
                    uv = std::stoul(type.substr(dotPos + 1));
                }

                if (uv == 0) {
                    failure = true;
                    break;
                }

                const char* name = lua::getupvalue(L, 1, uv);

                if (name == nullptr) {
                    failure = true;
                    break;
                }

                if (!lua::istable(L, -1) && !lua::isfunction(L, -1)) {
                    lua::pop(L);
                    failure = true;
                    break;
                }

                lua::replace(L, 1);

                break;
            }
            case 'C': {
                if (!lua::islfunction(L, 1)) {
                    failure = true;
                    break;
                }

                size_t ct = 0;
                size_t dotPos = type.find('.');
                if (dotPos != std::string::npos && dotPos + 1 < type.size()) {
                    ct = std::stoul(type.substr(dotPos + 1));
                }

                if (ct == 0) {
                    failure = true;
                    break;
                }

                TValue* tv_target = lua::toraw(L, 1);
                GCproto* proto_target = funcproto(funcV(tv_target));

                if (ct - 1 > proto_target->sizekgc) {
                    failure = true;
                    break;
                }

                GCRef* kr = mref(proto_target->k, GCRef) - (ptrdiff_t)proto_target->sizekgc;
                GCobj* object = gcref(kr[ct - 1]);

                if (object == nullptr) {
                    failure = true;
                    break;
                }

                lua::pushraw(L, object);

                if (!lua::istable(L, -1) && !lua::isfunction(L, -1)) {
                    lua::pop(L);
                    failure = true;
                    break;
                }

                lua::replace(L, 1);

                break;
            }
            default: failure = true;
            }

            if (failure) {
                return 0;
            }
        }

        lua::pushvalue(L, 1);

        return 1;
    }

    int frompointer(lua_State* L)
    {
        uintptr_t pointer = luaL::checknumber(L, 1);

        using namespace Engine;
        global_State* gs = mref(L->glref, global_State);
        if (!gs) {
            return 0;
        }

        GCobj* gcobject = gcref(gs->gc.root);

        while (gcobject) {
            if (!isdead(gs, gcobject)) {
                uint8_t type = gcobject->gch.gct;

                switch (type) {
                case ~LJ_TUDATA: {
                    lua::pushraw(L, gcobject);
                    lua::pushcfunction(L, runtime_topointer);
                    lua::pushvalue(L, -2);
                    lua::call(L, 1, 0);
                    if (closure_pointer == pointer) {
                        return 1;
                    }
                    lua::pop(L);
                    break;
                }
                case ~LJ_TPROTO: {
                    lua::pushraw(L, gcobject);
                    lua::pushcfunction(L, runtime_topointer);
                    lua::pushvalue(L, -2);
                    lua::call(L, 1, 0);
                    if (closure_pointer == pointer) {
                        return 1;
                    }
                    lua::pop(L);
                    break;
                }
                case ~LJ_TFUNC: {
                    lua::pushraw(L, gcobject);
                    lua::pushcfunction(L, runtime_topointer);
                    lua::pushvalue(L, -2);
                    lua::call(L, 1, 0);
                    if (closure_pointer == pointer) {
                        return 1;
                    }
                    lua::pop(L);
                    break;
                }
                case ~LJ_TTAB: {
                    lua::pushraw(L, gcobject);
                    lua::pushcfunction(L, runtime_topointer);
                    lua::pushvalue(L, -2);
                    lua::call(L, 1, 0);
                    if (closure_pointer == pointer) {
                        return 1;
                    }
                    lua::pop(L);
                    break;
                }
                default:
                    break;
                }
            }

            gcobject = gcref(gcobject->gch.nextgc);
        }

        return 0;
    }

    void cleanup(lua_State* L) {
        uintptr_t id = Tracker::id(L);
        closure_link.erase(id);
        Hook::clear(L);
    }

    int _registry(lua_State* L) {
        lua::pushvalue(L, indexer::registry);
        return 1;
    }

    int global(lua_State* L) {
        lua::pushvalue(L, indexer::global);
        return 1;
    }

    int env(lua_State* L) {
        lua::pushvalue(L, indexer::env);
        return 1;
    }

    int dump(lua_State* L) {
        if (!lua::isproto(L, 1) && !lua::islfunction(L, 1)) {
            luaL::argerror(L, 1, "expected function or proto");
        }

        if (lua::isproto(L, 1)) {
            using namespace Engine;
            TValue* tv_target = lua::toraw(L, 1);
            GCproto* proto_target = protoV(tv_target);
            lua::pushlfunction(L, proto_target);
            lua::pushcstring(L, luaL::dump(L, -1));
            lua::remove(L, -2);
        }
        else {
            lua::pushcstring(L, luaL::dump(L, 1));
        }

        return 1;
    }

    void push(lua_State* L, UMODULE hndle)
    {
        Tracker::on_close("debug", cleanup);

        lua::pushvalue(L, indexer::global);
        lua::getfield(L, -1, "debug");
        lua::remove(L, -2);

        lua::pushcfunction(L, _registry);
        lua::setfield(L, -2, "getregistry");

        lua::pushcfunction(L, _registry);
        lua::setfield(L, -2, "registry");

        lua::pushcfunction(L, global);
        lua::setfield(L, -2, "global");

        lua::pushcfunction(L, env);
        lua::setfield(L, -2, "env");

        lua::pushcfunction(L, dump);
        lua::setfield(L, -2, "dump");

        lua::pushcfunction(L, newcclosure);
        lua::setfield(L, -2, "newcclosure");

        lua::newtable(L);

            lua::pushcfunction(L, Hook::lsync);
            lua::setfield(L, -2, "sync");

            lua::pushcfunction(L, Hook::lasync);
            lua::setfield(L, -2, "async");

            lua::pushcfunction(L, Hook::lrestore);
            lua::setfield(L, -2, "restore");

            lua::pushcfunction(L, Hook::loriginal);
            lua::setfield(L, -2, "original");

            lua::pushcfunction(L, Hook::lis);
            lua::setfield(L, -2, "is");

            lua::pushcfunction(L, Hook::linside);
            lua::setfield(L, -2, "inside");

            lua::pushcfunction(L, Hook::lactive);
            lua::setfield(L, -2, "active");

            lua::pushcfunction(L, Hook::lenable);
            lua::setfield(L, -2, "enable");

            lua::pushcfunction(L, Hook::ldisable);
            lua::setfield(L, -2, "disable");

        lua::setfield(L, -2, "hook");

        lua::pushcfunction(L, clone);
        lua::setfield(L, -2, "clone");

        lua::pushcfunction(L, replace);
        lua::setfield(L, -2, "replace");

        lua::pushcfunction(L, topointer);
        lua::setfield(L, -2, "topointer");

        lua::pushcfunction(L, frompointer);
        lua::setfield(L, -2, "frompointer");

        lua::pushcfunction(L, getconstant);
        lua::setfield(L, -2, "getconstant");

        lua::pushcfunction(L, getconstants);
        lua::setfield(L, -2, "getconstants");

        lua::pushcfunction(L, setconstant);
        lua::setfield(L, -2, "setconstant");

        lua::pushcfunction(L, toproto);
        lua::setfield(L, -2, "toproto");

        lua::pushcfunction(L, fromproto);
        lua::setfield(L, -2, "fromproto");

        lua::pushcfunction(L, getprotos);
        lua::setfield(L, -2, "getprotos");

        lua::pushcfunction(L, tosignature);
        lua::setfield(L, -2, "tosignature");

        lua::pushcfunction(L, fromsignature);
        lua::setfield(L, -2, "fromsignature");

        lua::pushcfunction(L, tscan);
        lua::setfield(L, -2, "tscan");

        lua::pushcfunction(L, tresolve);
        lua::setfield(L, -2, "tresolve");

        lua::pushcfunction(L, iscfunct);
        lua::setfield(L, -2, "iscfunction");

        lua::pushcfunction(L, islfunct);
        lua::setfield(L, -2, "islfunction");

        lua::pushcfunction(L, setbuiltin);
        lua::setfield(L, -2, "setbuiltin");

        lua::pushcfunction(L, getbuiltin);
        lua::setfield(L, -2, "getbuiltin");

        lua::pushcfunction(L, getlocal);
        lua::setfield(L, -2, "getlocal");

        lua::pushcfunction(L, setlocal);
        lua::setfield(L, -2, "setlocal");

        lua::pushcfunction(L, getupvalue);
        lua::setfield(L, -2, "getupvalue");

        lua::pushcfunction(L, setupvalue);
        lua::setfield(L, -2, "setupvalue");

        lua::pushcfunction(L, getupvalues);
        lua::setfield(L, -2, "getupvalues");

        lua::pushcfunction(L, validlevel);
        lua::setfield(L, -2, "validlevel");

        lua::pushcfunction(L, getcallstack);
        lua::setfield(L, -2, "getcallstack");

        lua::pushcfunction(L, typestack);
        lua::setfield(L, -2, "typestack");

        lua::pushcfunction(L, getgc);
        lua::setfield(L, -2, "getgc");

        lua::pushcfunction(L, getbase);
        lua::setfield(L, -2, "getbase");
    }

    using namespace Reflection::CAPI;

    int capi_registry(lua_State* L) {
        lua_State* target = Reflection::CAPI::from_class(L, 1); if (target == nullptr) return 0;
        lua::pushvalue(target, indexer::registry);
        return 0;
    }

    int capi_global(lua_State* L) {
        lua_State* target = Reflection::CAPI::from_class(L, 1); if (target == nullptr) return 0;
        lua::pushvalue(target, indexer::global);
        return 0;
    }

    int capi_env(lua_State* L) {
        lua_State* target = Reflection::CAPI::from_class(L, 1); if (target == nullptr) return 0;
        lua::pushvalue(target, indexer::env);
        return 0;
    }

    int capi_newcclosure(lua_State* L)
    {
        lua_State* target = Reflection::CAPI::from_class(L, 1); if (target == nullptr) return 0;
        int index = luaL::checknumber(L, 2);
        lua::pushcfunction(L, newcclosure);
        lua::pushvalue(target, index);
        lua::call(target, 1, 1);
        return 0;
    }

    int capi_clone(lua_State* L)
    {
        lua_State* target = Reflection::CAPI::from_class(L, 1); if (target == nullptr) return 0;
        int index = luaL::checknumber(L, 2);
        lua::pushcfunction(L, clone);
        lua::pushvalue(target, index);
        lua::call(target, 1, 1);
        return 0;
    }

    int capi_replace(lua_State* L)
    {
        lua_State* target = Reflection::CAPI::from_class(L, 1); if (target == nullptr) return 0;
        int _target = luaL::checknumber(L, 2);
        int value = luaL::checknumber(L, 3);
        lua::pushcfunction(L, replace);
        lua::pushvalue(target, _target);
        lua::pushvalue(target, value);
        lua::call(target, 2, 0);
        return 0;
    }

    int capi_topointer(lua_State* L)
    {
        lua_State* target = Reflection::CAPI::from_class(L, 1); if (target == nullptr) return 0;
        int index = luaL::checknumber(L, 2);
        const void* pointer = lj_obj_ptr(L, lua::toraw(target, index));

        if (lua::istype(L, 3, datatype::boolean) && lua::toboolean(L, 3)) {
            lua::pushstring(L, lj_strfmt_wptr(pointer));
        }
        else {
            lua::pushnumber(L, (uintptr_t)pointer);
        }

        return 1;
    }

    int capi_frompointer(lua_State* L)
    {
        lua_State* target = Reflection::CAPI::from_class(L, 1); if (target == nullptr) return 0;
        int ptr = luaL::checknumber(L, 2);
        lua::pushcfunction(L, frompointer);
        lua::pushvalue(target, ptr);
        lua::call(target, 1, 1);
        return 0;
    }

    int capi_getgc(lua_State* L)
    {
        lua_State* target = Reflection::CAPI::from_class(L, 1); if (target == nullptr) return 0;
        lua::pushcfunction(target, getgc);
        lua::call(target, 0, 1);
        return 0;
    }

    void api() {
        Reflection::add("debug", push);
        Reflection::CAPI::Functions::add("registry", capi_registry);
        Reflection::CAPI::Functions::add("global", capi_global);
        Reflection::CAPI::Functions::add("env", capi_env);
        Reflection::CAPI::Functions::add("newcclosure", capi_newcclosure);
        Reflection::CAPI::Functions::add("clone", capi_clone);
        Reflection::CAPI::Functions::add("replace", capi_replace);
        Reflection::CAPI::Functions::add("topointer", capi_topointer);
        Reflection::CAPI::Functions::add("frompointer", capi_frompointer);
        Reflection::CAPI::Functions::add("getgc", capi_getgc);
    }
}