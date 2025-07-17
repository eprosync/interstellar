#pragma once

#ifdef __linux
#include <dlfcn.h>
#else
#include <Windows.h>
#endif

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <memory>

// TODO: prepare for more architecture support as per LuaJIT's supported OS & Archs

#define INTERSTELLAR_VERSION "1.0.0"

#ifndef INTERSTELLAR_NAMESPACE
#define INTERSTELLAR_NAMESPACE Interstellar
#endif

// Lua VM Flags (If its internal mode, shouldn't need to worry...)
// Normally it would just be X64 FR2
#if defined(__x86_64__) || defined(_M_X64)
    #define INTERSTELLAR_JIT_64
    #define INTERSTELLAR_JIT_GC64
#endif
// #define INTERSTELLAR_JIT_HASFFI
// #define INTERSTELLAR_JIT_52

// Interstellar - LuaJIT 2.1.0-beta3
namespace INTERSTELLAR_NAMESPACE {
    #ifdef __linux
    #define UMODULE void*
    static UMODULE mopen(const char* name)
    {
        return dlopen(name, RTLD_LAZY);
    }

    static void* n2p(UMODULE hndle, const char* name)
    {
        return dlsym(hndle, name);
    }
    #else
    #define UMODULE HMODULE
    static UMODULE mopen(const char* name)
    {
        return GetModuleHandleA(name);
    }

    static void* n2p(UMODULE hndle, const char* name)
    {
        return GetProcAddress(hndle, name);
    }
    #endif

    extern UMODULE process;

    // This is responsible for LuaJIT's internal functions.
    // Quite literally a copy paste from the LuaJIT's creator Mike Pall for a one-shot header file.
    // Mike Pall @ https://luajit.org/
    // TODO: This is horrible..., I really need to organize this...
    namespace Engine {
        #define INTERSTELLAR_JIT

        #ifdef INTERSTELLAR_JIT_64
            #define LJ_64 1
        #else
            #define LJ_64 0
        #endif

        #ifdef INTERSTELLAR_JIT_GC64
            #define LUAJIT_ENABLE_GC64
            #define LJ_GC64 1
            #define LJ_FR2 1
        #else
            #define LJ_GC64 0
            #define LJ_FR2 0
        #endif

        #ifdef INTERSTELLAR_JIT_HASFFI
            #define LJ_HASFFI 1
        #else
            #define LJ_HASFFI 0
            #define LUAJIT_DISABLE_FFI
        #endif

        #ifdef INTERSTELLAR_JIT_52
            #define LJ_52 1
        #else
            #define LJ_52 0
        #endif

        #ifndef INTERSTELLAR_EXTERNAL
            #pragma comment (lib, "../luajit/src/lua51.lib")
            #include "luajit/src/lua.hpp"
            #include "luajit/src/lj_state.h"
            #include "luajit/src/lj_gc.h"
            #include "luajit/src/lj_obj.h"
            #include "luajit/src/lj_func.h"
            #include "luajit/src/lj_frame.h"
            #include "luajit/src/lj_bc.h"
        #else
            #include "ljmin/lj_lua.h"
            #include "ljmin/lj_obj.h"
            #include "ljmin/lj_state.h"
            #include "ljmin/lj_gc.h"
            #include "ljmin/lj_frame.h"
            #include "ljmin/lj_bc.h"
        #endif

        /* Special sizes. */
        #define CTSIZE_INVALID	0xffffffffu

        typedef uint32_t CTInfo;	/* Type info. */
        typedef uint32_t CTSize;	/* Type size. */
        typedef uint32_t CTypeID;	/* Type ID. */
        typedef uint16_t CTypeID1;	/* Minimum-sized type ID. */

        /* C type table element. */
        typedef struct CType {
            CTInfo info;		/* Type info. */
            CTSize size;		/* Type size or other info. */
            CTypeID1 sib;		/* Sibling element. */
            CTypeID1 next;	/* Next element in hash chain. */
            GCRef name;		/* Element name (GCstr). */
        } CType;

        #define CTHASH_SIZE	128	/* Number of hash anchors. */
        #define CTHASH_MASK	(CTHASH_SIZE-1)

        /* Simplify target-specific configuration. Checked in lj_ccall.h. */
        #define CCALL_MAX_GPR		8
        #define CCALL_MAX_FPR		8

        typedef LJ_ALIGN(8) union FPRCBArg { double d; float f[2]; } FPRCBArg;

        /* C callback state. Defined here, to avoid dragging in lj_ccall.h. */

        typedef LJ_ALIGN(8) struct CCallback {
          FPRCBArg fpr[CCALL_MAX_FPR];	/* Arguments/results in FPRs. */
          intptr_t gpr[CCALL_MAX_GPR];	/* Arguments/results in GPRs. */
          intptr_t *stack;		/* Pointer to arguments on stack. */
          void *mcode;			/* Machine code for callback func. pointers. */
          CTypeID1 *cbid;		/* Callback type table. */
          MSize sizeid;			/* Size of callback type table. */
          MSize topid;			/* Highest unused callback type table slot. */
          MSize slot;			/* Current callback slot. */
        } CCallback;
        
        /* C type state. */
        typedef struct CTState {
            CType* tab;		/* C type table. */
            CTypeID top;		/* Current top of C type table. */
            MSize sizetab;	/* Size of C type table. */
            lua_State* L;		/* Lua state (needed for errors and allocations). */
            global_State* g;	/* Global state. */
            GCtab* finalizer;	/* Map of cdata to finalizer. */
            GCtab* miscmap;	/* Map of -CTypeID to metatable and cb slot to func. */
            CCallback cb;		/* Temporary callback state. */
            CTypeID1 hash[CTHASH_SIZE];  /* Hash anchors for C type table. */
        } CTState;

        /* C type numbers. Highest 4 bits of C type info. ORDER CT. */
        enum {
            /* Externally visible types. */
            CT_NUM,		/* Integer or floating-point numbers. */
            CT_STRUCT,		/* Struct or union. */
            CT_PTR,		/* Pointer or reference. */
            CT_ARRAY,		/* Array or complex type. */
            CT_MAYCONVERT = CT_ARRAY,
            CT_VOID,		/* Void type. */
            CT_ENUM,		/* Enumeration. */
            CT_HASSIZE = CT_ENUM,  /* Last type where ct->size holds the actual size. */
            CT_FUNC,		/* Function. */
            CT_TYPEDEF,		/* Typedef. */
            CT_ATTRIB,		/* Miscellaneous attributes. */
            /* Internal element types. */
            CT_FIELD,		/* Struct/union field or function parameter. */
            CT_BITFIELD,		/* Struct/union bitfield. */
            CT_CONSTVAL,		/* Constant value. */
            CT_EXTERN,		/* External reference. */
            CT_KW			/* Keyword. */
        };

        /* C type info flags.     TFFArrrr  */
        #define CTF_BOOL	0x08000000u	/* Boolean: NUM, BITFIELD. */
        #define CTF_FP		0x04000000u	/* Floating-point: NUM. */
        #define CTF_CONST	0x02000000u	/* Const qualifier. */
        #define CTF_VOLATILE	0x01000000u	/* Volatile qualifier. */
        #define CTF_UNSIGNED	0x00800000u	/* Unsigned: NUM, BITFIELD. */
        #define CTF_LONG	0x00400000u	/* Long: NUM. */
        #define CTF_VLA		0x00100000u	/* Variable-length: ARRAY, STRUCT. */
        #define CTF_REF		0x00800000u	/* Reference: PTR. */
        #define CTF_VECTOR	0x08000000u	/* Vector: ARRAY. */
        #define CTF_COMPLEX	0x04000000u	/* Complex: ARRAY. */
        #define CTF_UNION	0x00800000u	/* Union: STRUCT. */
        #define CTF_VARARG	0x00800000u	/* Vararg: FUNC. */
        #define CTF_SSEREGPARM	0x00400000u	/* SSE register parameters: FUNC. */

        #define CTF_QUAL	(CTF_CONST|CTF_VOLATILE)
        #define CTF_ALIGN	(CTMASK_ALIGN<<CTSHIFT_ALIGN)
        #define CTF_UCHAR	((char)-1 > 0 ? CTF_UNSIGNED : 0)

        /* C type info bitfields. */
        #define CTMASK_CID	0x0000ffffu	/* Max. 65536 type IDs. */
        #define CTMASK_NUM	0xf0000000u	/* Max. 16 type numbers. */
        #define CTSHIFT_NUM	28
        #define CTMASK_ALIGN	15		/* Max. alignment is 2^15. */
        #define CTSHIFT_ALIGN	16
        #define CTMASK_ATTRIB	255		/* Max. 256 attributes. */
        #define CTSHIFT_ATTRIB	16
        #define CTMASK_CCONV	3		/* Max. 4 calling conventions. */
        #define CTSHIFT_CCONV	16
        #define CTMASK_REGPARM	3		/* Max. 0-3 regparms. */
        #define CTSHIFT_REGPARM	18
        /* Bitfields only used in parser. */
        #define CTMASK_VSIZEP	15		/* Max. vector size is 2^15. */
        #define CTSHIFT_VSIZEP	4
        #define CTMASK_MSIZEP	255		/* Max. type size (via mode) is 128. */
        #define CTSHIFT_MSIZEP	8

        /* Info bits for BITFIELD. Max. size of bitfield is 64 bits. */
        #define CTBSZ_MAX	32		/* Max. size of bitfield is 32 bit. */
        #define CTBSZ_FIELD	127		/* Temp. marker for regular field. */
        #define CTMASK_BITPOS	127
        #define CTMASK_BITBSZ	127
        #define CTMASK_BITCSZ	127
        #define CTSHIFT_BITPOS	0
        #define CTSHIFT_BITBSZ	8
        #define CTSHIFT_BITCSZ	16

        #define CTINFO(ct, flags)	(((CTInfo)(ct) << CTSHIFT_NUM) + (flags))
        #define CTALIGN(al)		((CTSize)(al) << CTSHIFT_ALIGN)
        #define CTATTRIB(at)		((CTInfo)(at) << CTSHIFT_ATTRIB)

        #define ctype_type(info)	((info) >> CTSHIFT_NUM)
        #define ctype_cid(info)		((CTypeID)((info) & CTMASK_CID))
        #define ctype_align(info)	(((info) >> CTSHIFT_ALIGN) & CTMASK_ALIGN)
        #define ctype_attrib(info)	(((info) >> CTSHIFT_ATTRIB) & CTMASK_ATTRIB)
        #define ctype_bitpos(info)	(((info) >> CTSHIFT_BITPOS) & CTMASK_BITPOS)
        #define ctype_bitbsz(info)	(((info) >> CTSHIFT_BITBSZ) & CTMASK_BITBSZ)
        #define ctype_bitcsz(info)	(((info) >> CTSHIFT_BITCSZ) & CTMASK_BITCSZ)
        #define ctype_vsizeP(info)	(((info) >> CTSHIFT_VSIZEP) & CTMASK_VSIZEP)
        #define ctype_msizeP(info)	(((info) >> CTSHIFT_MSIZEP) & CTMASK_MSIZEP)
        #define ctype_cconv(info)	(((info) >> CTSHIFT_CCONV) & CTMASK_CCONV)

        /* Simple type checks. */
        #define ctype_isnum(info)	(ctype_type((info)) == CT_NUM)
        #define ctype_isvoid(info)	(ctype_type((info)) == CT_VOID)
        #define ctype_isptr(info)	(ctype_type((info)) == CT_PTR)
        #define ctype_isarray(info)	(ctype_type((info)) == CT_ARRAY)
        #define ctype_isstruct(info)	(ctype_type((info)) == CT_STRUCT)
        #define ctype_isfunc(info)	(ctype_type((info)) == CT_FUNC)
        #define ctype_isenum(info)	(ctype_type((info)) == CT_ENUM)
        #define ctype_istypedef(info)	(ctype_type((info)) == CT_TYPEDEF)
        #define ctype_isattrib(info)	(ctype_type((info)) == CT_ATTRIB)
        #define ctype_isfield(info)	(ctype_type((info)) == CT_FIELD)
        #define ctype_isbitfield(info)	(ctype_type((info)) == CT_BITFIELD)
        #define ctype_isconstval(info)	(ctype_type((info)) == CT_CONSTVAL)
        #define ctype_isextern(info)	(ctype_type((info)) == CT_EXTERN)
        #define ctype_hassize(info)	(ctype_type((info)) <= CT_HASSIZE)

        /* Combined type and flag checks. */
        #define ctype_isinteger(info) \
            (((info) & (CTMASK_NUM|CTF_BOOL|CTF_FP)) == CTINFO(CT_NUM, 0))
        #define ctype_isinteger_or_bool(info) \
            (((info) & (CTMASK_NUM|CTF_FP)) == CTINFO(CT_NUM, 0))
        #define ctype_isbool(info) \
            (((info) & (CTMASK_NUM|CTF_BOOL)) == CTINFO(CT_NUM, CTF_BOOL))
        #define ctype_isfp(info) \
            (((info) & (CTMASK_NUM|CTF_FP)) == CTINFO(CT_NUM, CTF_FP))

        #define ctype_ispointer(info) \
            ((ctype_type(info) >> 1) == (CT_PTR >> 1))  /* Pointer or array. */
        #define ctype_isref(info) \
            (((info) & (CTMASK_NUM|CTF_REF)) == CTINFO(CT_PTR, CTF_REF))

        #define ctype_isrefarray(info) \
            (((info) & (CTMASK_NUM|CTF_VECTOR|CTF_COMPLEX)) == CTINFO(CT_ARRAY, 0))
        #define ctype_isvector(info) \
            (((info) & (CTMASK_NUM|CTF_VECTOR)) == CTINFO(CT_ARRAY, CTF_VECTOR))
        #define ctype_iscomplex(info) \
            (((info) & (CTMASK_NUM|CTF_COMPLEX)) == CTINFO(CT_ARRAY, CTF_COMPLEX))

        #define ctype_isvltype(info) \
            (((info) & ((CTMASK_NUM|CTF_VLA) - (2u<<CTSHIFT_NUM))) == \
            CTINFO(CT_STRUCT, CTF_VLA))  /* VL array or VL struct. */
        #define ctype_isvlarray(info) \
            (((info) & (CTMASK_NUM|CTF_VLA)) == CTINFO(CT_ARRAY, CTF_VLA))

        #define ctype_isxattrib(info, at) \
            (((info) & (CTMASK_NUM|CTATTRIB(CTMASK_ATTRIB))) == \
            CTINFO(CT_ATTRIB, CTATTRIB(at)))

        /* Target-dependent sizes and alignments. */
        #if LJ_64
        #define CTSIZE_PTR	8
        #define CTALIGN_PTR	CTALIGN(3)
        #else
        #define CTSIZE_PTR	4
        #define CTALIGN_PTR	CTALIGN(2)
        #endif

        #define CTINFO_REF(ref) \
            CTINFO(CT_PTR, (CTF_CONST|CTF_REF|CTALIGN_PTR) + (ref))

        /* Get C data pointer. */
        extern void* cdata_getptr(void* p, CTSize sz);

        /* Set C data pointer. */
        extern void cdata_setptr(void* p, CTSize sz, const void* v);

        #define ctype_ctsG(g)		(mref((g)->ctype_state, CTState))

        /* Get C type state. */
        extern CTState* ctype_cts(lua_State* L);

        /* Check C type ID for validity when assertions are enabled. */
        extern CTypeID ctype_check(CTState* cts, CTypeID id);

        /* Get C type for C type ID. */
        extern CType* ctype_get(CTState* cts, CTypeID id);

        /* Get C type ID for a C type. */
        #define ctype_typeid(cts, ct)	((CTypeID)((ct) - (cts)->tab))

        /* Get child C type. */
        extern CType* ctype_child(CTState* cts, CType* ct);

        /* Get raw type for a C type ID. */
        extern CType* ctype_raw(CTState* cts, CTypeID id);

        /* Get raw type of the child of a C type. */
        extern CType* ctype_rawchild(CTState* cts, CType* ct);
    }

    // This contains all the API functions grabbed by interstellar with some extensions
    namespace API
    {
        // Internal Types
        typedef ptrdiff_t lua_Integer;
        typedef double lua_Number;

        namespace datatype {
            constexpr int none = (-1);
            constexpr int nil = 0;
            constexpr int boolean = 1;
            constexpr int lightuserdata = 2;
            constexpr int number = 3;
            constexpr int string = 4;
            constexpr int table = 5;
            constexpr int function = 6;
            constexpr int userdata = 7;
            constexpr int thread = 8;
            constexpr int proto = 9;
            constexpr int cdata = 10;
        }

        namespace indexer {
            constexpr int registry = -10000;
            constexpr int env = -10001;
            constexpr int global = -10002;
        }

        static int upvalueindex(int index)
        {
            return -(10002 + index);
        }
        
        // Internal Stacks
        typedef Engine::lua_State lua_State;
        typedef Engine::lua_Debug lua_Debug;
        typedef Engine::lua_Hook lua_Hook;
        typedef Engine::lua_Alloc lua_Alloc;
        typedef Engine::lua_CFunction lua_CFunction;
        typedef void* luaL_Buffer;
        typedef const char * (*lua_Reader) (lua_State *L, void *ud, size_t* *sz);
        typedef int (*lua_Writer) (lua_State *L, const void* p, size_t sz, void* ud);

        // Internal Helper
        typedef struct luaL_Reg
        {
            const char *name;
            lua_CFunction func;
        } luaL_Reg;

        typedef struct lua_udata
        {
            void* data;
            unsigned char type;
        } lua_udata;

        // luaL functions
        namespace luaL
        {
            namespace type
            {
                typedef void (*addlstring)(luaL_Buffer*, const char*, size_t);
                typedef void (*addstring)(luaL_Buffer*, const char*);
                typedef void (*addvalue)(luaL_Buffer*);
                typedef int (*argerror)(lua_State*, int, const char*);
                typedef void (*buffinit)(lua_State*, luaL_Buffer*);
                typedef int (*callmeta)(lua_State*, int, const char*);
                typedef void (*checkany)(lua_State*, int);
                typedef lua_Integer (*checkinteger)(lua_State*, int);
                typedef const char* (*checklstring)(lua_State*, int, size_t*);
                typedef lua_Number (*checknumber)(lua_State*, int);
                typedef int (*checkoption)(lua_State*, int, const char*, const char* const*);
                typedef void (*checkstack)(lua_State*, int, const char*);
                typedef void (*checktype)(lua_State*, int, int);
                typedef void* (*checkudata)(lua_State*, int, const char*);
                typedef int (*error)(lua_State*, const char*, ...);
                typedef int (*execresult)(lua_State*, int);
                typedef int (*fileresult)(lua_State*, int, const char*);
                typedef const char* (*findtable)(lua_State*, int, const char*, int);
                typedef int (*getmetafield)(lua_State*, int, const char*);
                typedef const char* (*gsub)(lua_State*, const char*, const char*, const char*);
                typedef int (*loadbuffer)(lua_State*, const char*, size_t, const char*);
                typedef int (*loadbufferx)(lua_State*, const char*, size_t, const char*, const char*);
                typedef int (*loadfile)(lua_State*, const char*);
                typedef int (*loadfilex)(lua_State*, const char*, const char*);
                typedef int (*loadstring)(lua_State*, const char*);
                typedef int (*newmetatable)(lua_State*, const char*);
                typedef lua_State* (*newstate)();
                typedef void (*openlib)(lua_State*, const char*, const luaL_Reg*, int);
                typedef void (*openlibs)(lua_State*);
                typedef lua_Integer (*optinteger)(lua_State*, int, lua_Integer);
                typedef const char* (*optlstring)(lua_State*, int, const char*, size_t*);
                typedef lua_Number (*optnumber)(lua_State*, int, lua_Number);
                typedef char* (*prepbuffer)(luaL_Buffer*);
                typedef void (*pushmodule)(lua_State*, const char*, int);
                typedef void (*pushresult)(luaL_Buffer*);
                typedef int (*ref)(lua_State*, int);
                typedef void (*makelib)(lua_State*, const char*, const luaL_Reg*);
                typedef void (*setfuncs)(lua_State*, const luaL_Reg*, int);
                typedef void (*setmetatable)(lua_State*, const char*);
                typedef void* (*testudata)(lua_State*, int, const char*);
                typedef void (*traceback)(lua_State*, lua_State*, const char*, int);
                typedef int (*typerror)(lua_State*, int, const char*);
                typedef void (*unref)(lua_State*, int, int);
                typedef void (*where)(lua_State*, int);
            }

            extern type::addlstring addlstring;
            extern type::addstring addstring;
            extern type::addvalue addvalue;
            extern type::argerror argerror;
            extern type::buffinit buffinit;
            extern type::callmeta callmeta;
            extern type::checkany checkany;
            extern type::checkinteger checkinteger;
            extern type::checklstring checklstring;
            extern type::checknumber checknumber;
            extern type::checkoption checkoption;
            extern type::checkstack checkstack;
            extern type::checktype checktype;
            extern type::checkudata checkudata;
            extern type::error error;
            extern type::execresult execresult;
            extern type::fileresult fileresult;
            extern type::findtable findtable;
            extern type::getmetafield getmetafield;
            extern type::gsub gsub;
            extern type::loadbuffer loadbuffer;
            extern type::loadbufferx loadbufferx;
            extern type::loadfile loadfile;
            extern type::loadfilex loadfilex;
            extern type::loadstring loadstring;
            extern type::newmetatable newmetatable;
            extern type::newstate newstate;
            extern type::openlib openlib;
            extern type::openlibs openlibs;
            extern type::optinteger optinteger;
            extern type::optlstring optlstring;
            extern type::optnumber optnumber;
            extern type::prepbuffer prepbuffer;
            extern type::pushmodule pushmodule;
            extern type::pushresult pushresult;
            extern type::ref ref;
            extern type::makelib makelib;
            extern type::setfuncs setfuncs;
            extern type::setmetatable setmetatable;
            extern type::testudata testudata;
            extern type::traceback traceback;
            extern type::typerror typerror;
            extern type::unref unref;
            extern type::where where;

            extern std::string trace(lua_State* L, int index);
            extern std::string checkcstring(lua_State* L, int index);
            extern bool checkboolean(lua_State* L, int index);
            extern void checkfunction(lua_State* L, int index);
            extern void* checklightuserdata(lua_State*, int index);
            extern void* checkuserdata(lua_State* L, int index);
            extern void* checkuserdatatype(lua_State* L, int index, int type);
            extern void checkcfunction(lua_State* L, int index);
            extern void checklfunction(lua_State* L, int index);
            extern void checkcdata(lua_State* L, int index);
            extern void checkproto(lua_State* L, int index);
            extern void checktable(lua_State* L, int index);
            extern int newref(lua_State* L, int index);
            extern void rmref(lua_State* L, int reference);
            extern std::string dump(lua_State* L, int index);

            extern int fetch(UMODULE hndle);
        }

        // lua functions
        namespace lua
        {
            namespace type
            {
                typedef lua_CFunction (*atpanic)(lua_State*, lua_CFunction);
                typedef void (*call)(lua_State*, int, int);
                typedef int (*checkstack)(lua_State*, int);
                typedef void (*close)(lua_State*);
                typedef void (*concat)(lua_State*, int);
                typedef void (*copy)(lua_State*, int, int);
                typedef int (*cpcall)(lua_State*, lua_CFunction, void*);
                typedef void (*createtable)(lua_State*, int, int);
                typedef int (*dump)(lua_State*, lua_Writer, void*);
                typedef int (*equal)(lua_State*, int, int);
                typedef int (*error)(lua_State*);
                typedef int (*gc)(lua_State*, int, int);
                typedef lua_Alloc (*getallocf)(lua_State*, void**);
                typedef void (*getfenv)(lua_State*, int);
                typedef void (*getfield)(lua_State*, int, const char*);
                typedef lua_Hook (*gethook)(lua_State*);
                typedef int (*gethookcount)(lua_State*);
                typedef int (*gethookmask)(lua_State*);
                typedef int (*getinfo)(lua_State*, const char*, lua_Debug*);
                typedef const char* (*getlocal)(lua_State*, const lua_Debug*, int);
                typedef int (*getmetatable)(lua_State*, int);
                typedef int (*getstack)(lua_State*, int, lua_Debug*);
                typedef void (*gettable)(lua_State*, int);
                typedef int (*gettop)(lua_State*);
                typedef const char* (*getupvalue)(lua_State*, int, int);
                typedef void (*insert)(lua_State*, int);
                typedef int (*iscfunction)(lua_State*, int);
                typedef int (*isnumber)(lua_State*, int);
                typedef int (*isstring)(lua_State*, int);
                typedef int (*isuserdata)(lua_State*, int);
                typedef int (*isyieldable)(lua_State*);
                typedef int (*lessthan)(lua_State*, int, int);
                typedef int (*load)(lua_State*, lua_Reader, void*, const char*);
                typedef int (*loadx)(lua_State*, lua_Reader, void*, const char*, const char*);
                typedef lua_State* (*newstate)(lua_Alloc, void*);
                typedef lua_State* (*newthread)(lua_State*);
                typedef void* (*newuserdata)(lua_State*, size_t);
                typedef int (*next)(lua_State*, int);
                typedef size_t (*objlen)(lua_State*, int);
                typedef int (*pcall)(lua_State*, int, int, int);
                typedef void (*pushboolean)(lua_State*, int);
                typedef void (*pushcclosure)(lua_State*, lua_CFunction, int);
                typedef const char* (*pushfstring)(lua_State*, const char*, ...);
                typedef void (*pushinteger)(lua_State*, lua_Integer);
                typedef void (*pushlightuserdata)(lua_State*, void*);
                typedef void (*pushlstring)(lua_State*, const char*, size_t);
                typedef void (*pushnil)(lua_State*);
                typedef void (*pushnumber)(lua_State*, lua_Number);
                typedef void (*pushstring)(lua_State*, const char*);
                typedef int (*pushthread)(lua_State*);
                typedef void (*pushvalue)(lua_State*, int);
                typedef const char* (*pushvfstring)(lua_State*, const char*, va_list);
                typedef int (*rawequal)(lua_State*, int, int);
                typedef void (*rawget)(lua_State*, int);
                typedef void (*rawgeti)(lua_State*, int, int);
                typedef void (*rawset)(lua_State*, int);
                typedef void (*rawseti)(lua_State*, int, int);
                typedef void (*remove)(lua_State*, int);
                typedef void (*replace)(lua_State*, int);
                typedef void (*setallocf)(lua_State*, lua_Alloc, void*);
                typedef int (*setfenv)(lua_State*, int);
                typedef void (*setfield)(lua_State*, int, const char*);
                typedef void (*sethook)(lua_State*, lua_Hook, int, int);
                typedef const char* (*setlocal)(lua_State*, const lua_Debug*, int);
                typedef int (*setmetatable)(lua_State*, int);
                typedef void (*settable)(lua_State*, int);
                typedef void (*settop)(lua_State*, int);
                typedef const char* (*setupvalue)(lua_State*, int, int);
                typedef int (*status)(lua_State*);
                typedef int (*toboolean)(lua_State*, int);
                typedef lua_CFunction (*tocfunction)(lua_State*, int);
                typedef bool (*isinteger)(lua_State*, int);
                typedef lua_Integer (*tointeger)(lua_State*, int);
                typedef lua_Integer (*tointegerx)(lua_State*, int, int*);
                typedef const char* (*tolstring)(lua_State*, int, size_t*);
                typedef lua_Number (*tonumber)(lua_State*, int);
                typedef lua_Number (*tonumberx)(lua_State*, int, int*);
                typedef const void* (*topointer)(lua_State*, int);
                typedef lua_State* (*tothread)(lua_State*, int);
                typedef void* (*touserdata)(lua_State*, int);
                typedef int (*gettype)(lua_State*, int);
                typedef const char* (*gettypename)(lua_State*, int);
                typedef void* (*upvalueid)(lua_State*, int, int);
                typedef void (*upvaluejoin)(lua_State*, int, int, int, int);
                typedef const lua_Number* (*version)(lua_State*);
                typedef void (*xmove)(lua_State*, lua_State*, int);
                typedef int (*yield)(lua_State*, int);
            }

            extern type::atpanic atpanic;
            extern type::call call;
            extern type::checkstack checkstack;
            extern type::close close;
            extern type::concat concat;
            extern type::copy copy;
            extern type::cpcall cpcall;
            extern type::createtable createtable;
            extern type::dump dump;
            extern type::equal equal;
            extern type::error error;
            extern type::gc gc;
            extern type::getallocf getallocf;
            extern type::getfenv getfenv;
            extern type::getfield getfield;
            extern type::gethook gethook;
            extern type::gethookcount gethookcount;
            extern type::gethookmask gethookmask;
            extern type::getinfo getinfo;
            extern type::getlocal getlocal;
            extern type::getmetatable getmetatable;
            extern type::getstack getstack;
            extern type::gettable gettable;
            extern type::gettop gettop;
            extern type::getupvalue getupvalue;
            extern type::insert insert;
            extern type::iscfunction iscfunction;
            extern type::isnumber isnumber;
            extern type::isstring isstring;
            extern type::isuserdata isuserdata;
            extern type::isyieldable isyieldable;
            extern type::lessthan lessthan;
            extern type::load load;
            extern type::loadx loadx;
            extern type::newstate newstate;
            extern type::newthread newthread;
            extern type::newuserdata newuserdata;
            extern type::next next;
            extern type::objlen objlen;
            extern type::pcall pcall;
            extern type::pushboolean pushboolean;
            extern type::pushcclosure pushcclosure;
            extern type::pushfstring pushfstring;
            extern type::pushinteger pushinteger;
            extern type::pushlightuserdata pushlightuserdata;
            extern type::pushlstring pushlstring;
            extern type::pushnil pushnil;
            extern type::pushnumber pushnumber;
            extern type::pushstring pushstring;
            extern type::pushthread pushthread;
            extern type::pushvalue pushvalue;
            extern type::pushvfstring pushvfstring;
            extern type::rawequal rawequal;
            extern type::rawget rawget;
            extern type::rawgeti rawgeti;
            extern type::rawset rawset;
            extern type::rawseti rawseti;
            extern type::remove remove;
            extern type::replace replace;
            extern type::setallocf setallocf;
            extern type::setfenv setfenv;
            extern type::setfield setfield;
            extern type::sethook sethook;
            extern type::setlocal setlocal;
            extern type::setmetatable setmetatable;
            extern type::settable settable;
            extern type::settop settop;
            extern type::setupvalue setupvalue;
            extern type::status status;
            extern type::toboolean toboolean;
            extern type::tocfunction tocfunction;
            extern type::tointeger tointeger;
            extern type::tointegerx tointegerx;
            extern type::tolstring tolstring;
            extern type::tonumber tonumber;
            extern type::tonumberx tonumberx;
            extern type::topointer topointer;
            extern type::tothread tothread;
            extern type::touserdata touserdata;
            extern type::gettype gettype;
            extern type::gettypename gettypename;
            extern type::upvalueid upvalueid;
            extern type::upvaluejoin upvaluejoin;
            extern type::version version;
            extern type::xmove xmove;
            extern type::yield yield;
            
            extern std::string toastring(lua_State* L, int index);
            extern int tcall(lua_State* L, int nargs, int nret);
            extern std::string tocstring(lua_State* L, int index);
            extern void pushcstring(lua_State* L, std::string str);
            extern void pushraw(lua_State* L, Engine::GCobj* data, uint32_t type = 0);
            extern Engine::TValue* toraw(lua_State* L, int index);
            extern void setraw(lua_State* L, int index, Engine::GCobj* data, uint32_t type);
            extern void pushref(lua_State* L, int reference);

            void getcfield(lua_State* L, int index, std::string str);
            void getrfield(lua_State* L, int index, const char* str);
            void getcrfield(lua_State* L, int index, std::string str);
            void setcfield(lua_State* L, int index, std::string str);
            void setrfield(lua_State* L, int index, const char* str);
            void setcrfield(lua_State* L, int index, std::string str);
            
            extern bool isinteger(lua_State* L, int index);
            extern bool istype(lua_State* L, int index, int type);
            extern bool isnil(lua_State* L, int index);
            extern bool isboolean(lua_State* L, int index);
            extern bool islightuserdata(lua_State* L, int index);
            extern bool istable(lua_State* L, int index);
            extern bool isfunction(lua_State* L, int index);
            extern bool islfunction(lua_State* L, int index);
            extern bool iscdata(lua_State* L, int index);
            extern bool isproto(lua_State* L, int index);
            extern bool isuserdatatype(lua_State* L, int index, int type);
            extern bool isthread(lua_State* L, int index);
            extern void newtable(lua_State* L);
            extern void pop(lua_State* L, int count = 1);
            extern void newuserdatatype(lua_State* L, void* data, size_t size, unsigned char type);
            extern void* touserdatatype(lua_State* L, int index);
            extern void* tocdataptr(lua_State* L, int index);
            extern void* tocdatafunc(lua_State* L, int index);
            extern void pushcfunction(lua_State* L, lua_CFunction f);
            extern void pushlfunction(lua_State* L, Engine::GCproto* proto, Engine::GCupval* upvptr = nullptr, int upvalues = 0);
            extern void pushnfunction(lua_State* L, std::string name = "");
            extern void getfunc(lua_State* L, int index);
            extern void getfunci(lua_State* L, int level);
            extern int upvalues(lua_State* L, int index);
            extern std::string typestack(lua_State* L, int count = 0, int offset = 0);

            extern int fetch(UMODULE hndle);
        }

        // luaopen functions
        namespace luaopen
        {
            namespace type
            {
                typedef int (*base)(lua_State*);
                typedef int (*bit)(lua_State*);
                typedef int (*debug)(lua_State*);
                typedef int (*jit)(lua_State*);
                typedef int (*math)(lua_State*);
                typedef int (*os)(lua_State*);
                typedef int (*package)(lua_State*);
                typedef int (*string)(lua_State*);
                typedef int (*table)(lua_State*);
            }

            extern type::base base;
            extern type::bit bit;
            extern type::debug debug;
            extern type::jit jit;
            extern type::math math;
            extern type::os os;
            extern type::package package;
            extern type::string string;
            extern type::table table;

            extern int fetch(UMODULE hndle);
        }

        extern int fetch(UMODULE hndle);
    }

    // This is used to track lua_State's by name.
    // TODO: Probably need to add some spinning locks here for the upcoming multi-threaded lua_State's
    namespace Tracker {

        union state_union {
            uintptr_t pointer;
            API::lua_State* self;
        };

        inline bool operator==(const state_union& lhs, const state_union& rhs) {
            return lhs.pointer == rhs.pointer;
        }

        struct state_tracking {
            std::string name;
            std::shared_ptr<std::mutex> mutex;
            state_union state;
            std::vector<state_union> children;
            state_union parent;
            bool threaded;
            bool internal;
        };

        typedef void (*lua_Closure) (API::lua_State* L);

        extern void increment();
        extern void decrement();
        extern void runtime();
        extern uintptr_t id(API::lua_State* L);
        extern state_tracking* get_tracker(API::lua_State* L);
        extern state_tracking* get_tracker(void* L);
        extern state_tracking* get_tracker(uintptr_t L);
        extern state_tracking* get_tracker(std::string name);
        extern API::lua_State* is_state(API::lua_State* L);
        extern API::lua_State* is_state(uintptr_t L);
        extern API::lua_State* is_state(void* L);
        extern API::lua_State* is_state(std::string name);
        extern API::lua_State* get_root();
        extern bool is_root(API::lua_State* L);
        extern bool is_root(void* L);
        extern bool is_root(uintptr_t L);
        extern bool is_root(std::string name);
        extern bool is_internal(API::lua_State* L);
        extern bool is_internal(void* L);
        extern bool is_internal(uintptr_t L);
        extern bool is_internal(std::string name);
        extern bool is_threaded(API::lua_State* L);
        extern bool is_threaded(void* L);
        extern bool is_threaded(uintptr_t L);
        extern bool is_threaded(std::string name);
        extern std::vector<API::lua_State*> get_children(API::lua_State* L);
        extern std::vector<API::lua_State*> get_children(void* L);
        extern std::vector<API::lua_State*> get_children(uintptr_t L);
        extern std::vector<API::lua_State*> get_children(std::string name);
        extern API::lua_State* get_parent(API::lua_State* L);
        extern API::lua_State* get_parent(void* L);
        extern API::lua_State* get_parent(uintptr_t L);
        extern API::lua_State* get_parent(std::string name);
        extern bool should_lock(API::lua_State* target, API::lua_State* source);
        extern std::string get_name(API::lua_State* L);
        extern std::vector<std::pair<std::string, API::lua_State*>> get_states();
        extern std::unique_lock<std::mutex> lock(API::lua_State* L);
        extern std::unique_lock<std::mutex> lock(void* L);
        extern std::unique_lock<std::mutex> lock(uintptr_t L);
        extern std::unique_lock<std::mutex> lock(std::string name);
        extern void cross_lock(API::lua_State* target, API::lua_State* source);
        extern void cross_unlock(API::lua_State* target, API::lua_State* source);
        extern void listen(API::lua_State* L, std::string name, bool internal = false, API::lua_State* parent = nullptr);
        extern void listen(API::lua_State* L, std::string name, std::shared_ptr<std::mutex> guard, bool internal = false, API::lua_State* parent = nullptr);
        extern void destroy(API::lua_State* L);
        extern void destroy(uintptr_t L);
        extern void destroy(void* L);
        extern void destroy(std::string name);
        extern void pre_remove(API::lua_State* L);
        extern void post_remove(API::lua_State* L);
        extern void on_open(std::string name, lua_Closure callback);
        extern void on_close(std::string name, lua_Closure callback);
        extern inline void init();
    }

    // Responsible for tracking and handling metatables with userdatas
    // (Not made to replace already known class implementations)
    namespace Class {
        struct class_udata {
            void* data;
            unsigned char type;
        };

        struct class_store {
            std::string name = "";
            unsigned char type = 0;
            int reference = 0;
        };

        extern bool existsbyname(API::lua_State* L, std::string name);
        extern class_store getbyname(API::lua_State* L, std::string name);
        extern bool existsbytype(API::lua_State* L, unsigned char type);
        extern class_store getbytype(API::lua_State* L, unsigned char type);
        extern bool existsbyreference(API::lua_State* L, int reference);
        extern class_store getbyreference(API::lua_State* L, int reference);
        extern unsigned char create(API::lua_State* L, std::string name);
        extern void inherits(API::lua_State* L, std::string name, int index = -1);
        extern bool metatable(API::lua_State* L, unsigned char type);
        extern bool metatable(API::lua_State* L, std::string name);
        extern void spawn(API::lua_State* L, void* data, unsigned char type);
        extern void spawn_weak(API::lua_State* L, void* data, unsigned char type);
        extern void spawn_store(API::lua_State* L, void* data, unsigned char type);
        extern void spawn(API::lua_State* L, void* data, std::string name);
        extern void spawn_weak(API::lua_State* L, void* data, std::string name);
        extern void spawn_store(API::lua_State* L, void* data, std::string name);
        extern bool is(API::lua_State* L, int index, unsigned char type);
        extern bool is(API::lua_State* L, int index, std::string name);
        extern void* to(API::lua_State* L, int index);
        extern void* check(API::lua_State* L, int index, unsigned char type);
        extern void* check(API::lua_State* L, int index, std::string name);
        extern void cleanup(API::lua_State* L);
    }

    // Responsible for what context we execute in & provide
    // For state grabbing, this isn't internal (yet) so please find them yourself
	namespace Reflection
    {
        typedef void (*lua_Threaded) (API::lua_State* L);
        typedef void (*lua_Runtime) ();

        namespace Task {
            typedef void (*lua_Task_Error) (API::lua_State* L, std::string error);
            extern void add_error(std::string name, lua_Task_Error callback);
            extern void remove_error(std::string name);
        }
        
        extern void on_threaded(std::string name, lua_Threaded callback);
        extern void on_runtime(std::string name, lua_Runtime callback);
        extern void runtime();

        extern int transfer_table(API::lua_State* from, API::lua_State* to, int source, bool no_error = false);
        extern int transfer(API::lua_State* from, API::lua_State* to, int index, bool no_error = false);

        // Compiles lua to a function, pushing it onto the stack, string is returned if there is an error
        extern std::string compile(API::lua_State* L, std::string source, std::string name);

        // Compiles & executes lua, string is returned if there is an error
        extern std::string execute(API::lua_State* L, std::string source, std::string name);

        // Opens a new lua_State
        extern API::lua_State* open(std::string name, bool internal = false, bool threaded = false, API::lua_State* parent = nullptr);

        // Closes a lua_State
        extern void close(API::lua_State* L);

        typedef void (*lua_CPush) (API::lua_State* L, UMODULE hndle);

        // Adds a cfunction to the API stack
        extern void add(std::string name, API::lua_CFunction callback);

        // Adds a custom table to the API stack (please create your own table)
        extern void add(std::string name, lua_CPush callback);

        // Pushes the API interface, you can technically call this anywhere
        extern void push(API::lua_State* L);
    }

    // Initializes and calls Internal's fetch API, returns a number for failure
    extern int init(std::string binary);

    // The critical runtime responsible for all of interstellar
    extern void runtime();
}

// Interstellar: Reflection
// Allows for compiling and execution of lua
namespace INTERSTELLAR_NAMESPACE::Reflection {
    extern int compilel(API::lua_State* L);
    extern int executel(API::lua_State* L);
    
    // CAPI is our way of talking to LuaJIT designated C API through Lua
    // Yes, its a mess and man do I wish I hadn't done this...
    namespace CAPI {
        typedef void (*lua_CAPIPush) (API::lua_State* L);
        namespace Functions {
            extern void add(std::string name, API::lua_CFunction callback);
            extern void add(std::string name, lua_CAPIPush callback);
        }
        extern API::lua_State* get_origin();
        extern API::lua_State* get_target();
        extern API::lua_State* from_class(API::lua_State* L, int index);
        extern void interstate_input(API::lua_State* L, API::lua_CFunction func);
        extern void interstate_output(API::lua_State* L, API::lua_CFunction func, int count = 0);
        extern void interstate_transfer(API::lua_State* L, API::lua_CFunction func);
        extern void interstate(API::lua_State* L, API::lua_CFunction func, int count = 0);
    }

    extern void push_state(API::lua_State* L, API::lua_State* state);
    extern void push(API::lua_State* L, UMODULE hndle);
    extern void api();
}