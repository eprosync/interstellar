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
            #include "luajit/lua.hpp"
            #include "luajit/lj_state.h"
            #include "luajit/lj_gc.h"
            #include "luajit/lj_obj.h"
            #include "luajit/lj_func.h"
        #else
            // Hi, this is the one-shot section of required LuaJIT files.
            // This entire section here is from Mike Pall, see his license bellow.
            
            /*
            ** LuaJIT -- a Just-In-Time Compiler for Lua. http://luajit.org/
            **
            ** Copyright (C) 2005-2017 Mike Pall. All rights reserved.
            **
            ** Permission is hereby granted, free of charge, to any person obtaining
            ** a copy of this software and associated documentation files (the
            ** "Software"), to deal in the Software without restriction, including
            ** without limitation the rights to use, copy, modify, merge, publish,
            ** distribute, sublicense, and/or sell copies of the Software, and to
            ** permit persons to whom the Software is furnished to do so, subject to
            ** the following conditions:
            **
            ** The above copyright notice and this permission notice shall be
            ** included in all copies or substantial portions of the Software.
            **
            ** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
            ** EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
            ** MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
            ** IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
            ** CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
            ** TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
            ** SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
            **
            ** [ MIT license: http://www.opensource.org/licenses/mit-license.php ]
            */

            #ifdef __linux
                #define LJ_ALIGN(n)	__attribute__((aligned(n)))
            #else
                #define LJ_ALIGN(n)	__declspec(align(n))
            #endif
            
            #define LJ_ENDIAN_LOHI(lo, hi)		lo hi

            #define LJ_TNIL			(~0u)
            #define LJ_TFALSE		(~1u)
            #define LJ_TTRUE		(~2u)
            #define LJ_TLIGHTUD		(~3u)
            #define LJ_TSTR			(~4u)
            #define LJ_TUPVAL		(~5u)
            #define LJ_TTHREAD		(~6u)
            #define LJ_TPROTO		(~7u)
            #define LJ_TFUNC		(~8u)
            #define LJ_TTRACE		(~9u)
            #define LJ_TCDATA		(~10u)
            #define LJ_TTAB			(~11u)
            #define LJ_TUDATA		(~12u)
            /* This is just the canonical number type used in some places. */
            #define LJ_TNUMX		(~13u)

            /* Integers have itype == LJ_TISNUM doubles have itype < LJ_TISNUM */
            #if LJ_64 && !LJ_GC64
            #define LJ_TISNUM		0xfffeffffu
            #else
            #define LJ_TISNUM		LJ_TNUMX
            #endif
            #define LJ_TISTRUECOND		LJ_TFALSE
            #define LJ_TISPRI		LJ_TTRUE
            #define LJ_TISGCV		(LJ_TSTR+1)
            #define LJ_TISTABUD		LJ_TTAB
            #if LJ_GC64
            #define LJ_GCVMASK		(((uint64_t)1 << 47) - 1)
            #endif

            #if LJ_GC64
            #define mref(r, t)	((t *)(void *)(r).ptr64)

            #define setmref(r, p)	((r).ptr64 = (uint64_t)(void *)(p))
            #define setmrefr(r, v)	((r).ptr64 = (v).ptr64)
            #else
            #define mref(r, t)	((t *)(void *)(uintptr_t)(r).ptr32)

            #define setmref(r, p)	((r).ptr32 = (uint32_t)(uintptr_t)(void *)(p))
            #define setmrefr(r, v)	((r).ptr32 = (v).ptr32)
            #endif

            /* Memory reference */
            typedef struct MRef {
                #if LJ_GC64
                  uint64_t ptr64;	/* True 64 bit pointer. */
                #else
                  uint32_t ptr32;	/* Pseudo 32 bit pointer. */
                #endif
            } MRef;

            /* GCobj reference */
            typedef struct GCRef {
                #if LJ_GC64
                  uint64_t gcptr64;	/* True 64 bit pointer. */
                #else
                  uint32_t gcptr32;	/* Pseudo 32 bit pointer. */
                #endif
            } GCRef;

            /* Frame link. */
            typedef union {
                int32_t ftsz;		/* Frame type and size of previous frame. */
                MRef pcr;		/* Or PC for Lua frames. */
            } FrameLink;

            /* Tagged value. */
            typedef LJ_ALIGN(8) union TValue {
                uint64_t u64;		/* 64 bit pattern overlaps number. */
                double n;		/* Number object overlaps split tag/value object. */
                #if LJ_GC64
                GCRef gcr;		/* GCobj reference with tag. */
                int64_t it64;
                struct {
                    LJ_ENDIAN_LOHI(
                        int32_t i;	/* Integer value. */
                    , uint32_t it;	/* Internal object tag. Must overlap MSW of number. */
                        )
                };
                #else
                struct {
                    LJ_ENDIAN_LOHI(
                        union {
                        GCRef gcr;	/* GCobj reference (if any). */
                        int32_t i;	/* Integer value. */
                    };
                    , uint32_t it;	/* Internal object tag. Must overlap MSW of number. */
                        )
                };
                #endif
                #if LJ_FR2
                int64_t ftsz;		/* Frame type and size of previous frame, or PC. */
                #else
                struct {
                    LJ_ENDIAN_LOHI(
                        GCRef func;	/* Function for next frame (or dummy L). */
                    , FrameLink tp;	/* Link to previous frame. */
                        )
                } fr;
                #endif
                struct {
                    LJ_ENDIAN_LOHI(
                        uint32_t lo;	/* Lower 32 bits of number. */
                    , uint32_t hi;	/* Upper 32 bits of number. */
                        )
                } u32;
            } TValue;

            typedef const TValue cTValue;

            /* Macros to test types. */
            #if LJ_GC64
                #define itype(o)	((uint32_t)((o)->it64 >> 47))
                #define tvisnil(o)	((o)->it64 == -1)
            #else
                #define itype(o)	((o)->it)
                #define tvisnil(o)	(itype(o) == LJ_TNIL)
            #endif
            #define tvisfalse(o)	(itype(o) == LJ_TFALSE)
            #define tvistrue(o)	(itype(o) == LJ_TTRUE)
            #define tvisbool(o)	(tvisfalse(o) || tvistrue(o))
            #if LJ_64 && !LJ_GC64
                #define tvislightud(o)	(((int32_t)itype(o) >> 15) == -2)
            #else
                #define tvislightud(o)	(itype(o) == LJ_TLIGHTUD)
            #endif
            #define tvisstr(o)	(itype(o) == LJ_TSTR)
            #define tvisfunc(o)	(itype(o) == LJ_TFUNC)
            #define tvisthread(o)	(itype(o) == LJ_TTHREAD)
            #define tvisproto(o)	(itype(o) == LJ_TPROTO)
            #define tviscdata(o)	(itype(o) == LJ_TCDATA)
            #define tvistab(o)	(itype(o) == LJ_TTAB)
            #define tvisudata(o)	(itype(o) == LJ_TUDATA)
            #define tvisnumber(o)	(itype(o) <= LJ_TISNUM)
            #define tvisint(o)	(LJ_DUALNUM && itype(o) == LJ_TISNUM)
            #define tvisnum(o)	(itype(o) < LJ_TISNUM)

            #define tvistruecond(o)	(itype(o) < LJ_TISTRUECOND)
            #define tvispri(o)	(itype(o) >= LJ_TISPRI)
            #define tvistabud(o)	(itype(o) <= LJ_TISTABUD)  /* && !tvisnum() */
            #define tvisgcv(o)	((itype(o) - LJ_TISGCV) > (LJ_TNUMX - LJ_TISGCV))

            #if LJ_GC64
                #define setitype(o, i)		((o)->it = ((i) << 15))
                #define setnilV(o)		((o)->it64 = -1)
                #define setpriV(o, x)		((o)->it64 = (int64_t)~((uint64_t)~(x)<<47))
                #define setboolV(o, x)		((o)->it64 = (int64_t)~((uint64_t)((x)+1)<<47))
            #else
                #define setitype(o, i)		((o)->it = (i))
                #define setnilV(o)		((o)->it = LJ_TNIL)
                #define setboolV(o, x)		((o)->it = LJ_TFALSE-(uint32_t)(x))
                #define setpriV(o, i)		(setitype((o), (i)))
            #endif

            #define tvref(r)	(mref(r, TValue))

            /* Bitmasks for marked field of GCobj. */
            #define LJ_GC_WHITE0	0x01
            #define LJ_GC_WHITE1	0x02
            #define LJ_GC_BLACK	0x04
            #define LJ_GC_FINALIZED	0x08
            #define LJ_GC_WEAKKEY	0x08
            #define LJ_GC_WEAKVAL	0x10
            #define LJ_GC_CDATA_FIN	0x10
            #define LJ_GC_FIXED	0x20
            #define LJ_GC_SFIXED	0x40

            #define LJ_GC_WHITES	(LJ_GC_WHITE0 | LJ_GC_WHITE1)
            #define LJ_GC_COLORS	(LJ_GC_WHITES | LJ_GC_BLACK)
            #define LJ_GC_WEAK	(LJ_GC_WEAKKEY | LJ_GC_WEAKVAL)

            /* Macros to test and set GCobj colors. */
            #define iswhite(x)	((x)->gch.marked & LJ_GC_WHITES)
            #define isblack(x)	((x)->gch.marked & LJ_GC_BLACK)
            #define isgray(x)	(!((x)->gch.marked & (LJ_GC_BLACK|LJ_GC_WHITES)))
            #define tviswhite(x)	(tvisgcv(x) && iswhite(gcV(x)))
            #define otherwhite(g)	(g->gc.currentwhite ^ LJ_GC_WHITES)
            #define isdead(g, v)	((v)->gch.marked & otherwhite(g) & LJ_GC_WHITES)

            /* Common GC header for all collectable objects. */
            #define GCHeader	GCRef nextgc; uint8_t marked; uint8_t gct

            #if LJ_GC64
                #define gcref(r)	((GCobj *)(r).gcptr64)
                #define gcrefp(r, t)	((t *)(void *)(r).gcptr64)
                #define gcrefu(r)	((r).gcptr64)
                #define gcrefeq(r1, r2)	((r1).gcptr64 == (r2).gcptr64)

                #define setgcref(r, gc)	((r).gcptr64 = (uint64_t)&(gc)->gch)
                #define setgcreft(r, gc, it) \
                    (r).gcptr64 = (uint64_t)&(gc)->gch | (((uint64_t)(it)) << 47)
                #define setgcrefp(r, p)	((r).gcptr64 = (uint64_t)(p))
                #define setgcrefnull(r)	((r).gcptr64 = 0)
                #define setgcrefr(r, v)	((r).gcptr64 = (v).gcptr64)
            #else
                #define gcref(r)	((GCobj *)(uintptr_t)(r).gcptr32)
                #define gcrefp(r, t)	((t *)(void *)(uintptr_t)(r).gcptr32)
                #define gcrefu(r)	((r).gcptr32)
                #define gcrefeq(r1, r2)	((r1).gcptr32 == (r2).gcptr32)

                #define setgcref(r, gc)	((r).gcptr32 = (uint32_t)(uintptr_t)&(gc)->gch)
                #define setgcrefp(r, p)	((r).gcptr32 = (uint32_t)(uintptr_t)(p))
                #define setgcrefnull(r)	((r).gcptr32 = 0)
                #define setgcrefr(r, v)	((r).gcptr32 = (v).gcptr32)
            #endif

            /* Macros to get tagged values. */
            #if LJ_GC64
            #define gcval(o)	((GCobj *)(gcrefu((o)->gcr) & LJ_GCVMASK))
            #else
            #define gcval(o)	(gcref((o)->gcr))
            #endif
            #define boolV(o)	(LJ_TFALSE - itype(o))
            #if LJ_64
            #define U64x(hi, lo)    (((uint64_t)0x##hi << 32) + (uint64_t)0x##lo)
            #define lightudV(o) (void *)((o)->u64 & U64x(00007fff,ffffffff))
            #else
            #define lightudV(o)	gcrefp((o)->gcr, void)
            #endif
            #define gcV(o)		gcval(o)
            #define strV(o)		&gcval(o)->str
            #define funcV(o)	&gcval(o)->fn
            #define threadV(o)	&gcval(o)->th
            #define protoV(o)	&gcval(o)->pt
            #define cdataV(o)	&gcval(o)->cd
            #define tabV(o)		&gcval(o)->tab
            #define udataV(o)	&gcval(o)->ud
            #define numV(o)		(o)->n
            #define intV(o)		(int32_t)(o)->i

            #define strref(r)	(&gcref((r))->str)
            #define strdata(s)	((const char *)((s)+1))
            #define strdatawr(s)	((char *)((s)+1))
            #define strVdata(o)	strdata(strV(o))
            #define sizestring(s)	(sizeof(struct GCstr)+(s)->len+1)

            #define GCfuncHeader \
                GCHeader; uint8_t ffid; uint8_t nupvalues; \
                GCRef env; GCRef gclist; MRef pc

            struct lua_State;
            typedef int (*lua_CFunction)(lua_State* L);

            typedef struct GCfuncC {
                GCfuncHeader;
                lua_CFunction f;	/* C function to be called. */
                TValue upvalue[1];	/* Array of upvalues (TValue). */
            } GCfuncC;

            typedef struct GCfuncL {
                GCfuncHeader;
                GCRef uvptr[1];	/* Array of _pointers_ to upvalue objects (GCupval). */
            } GCfuncL;

            typedef union GCfunc {
                GCfuncC c;
                GCfuncL l;
            } GCfunc;

            typedef uint32_t MSize;
            #if LJ_GC64
            typedef uint64_t GCSize;
            #else
            typedef uint32_t GCSize;
            #endif

            #define FF_LUA		0
            #define FF_C		1
            #define isluafunc(fn)	((fn)->c.ffid == FF_LUA)
            #define iscfunc(fn)	((fn)->c.ffid == FF_C)
            #define isffunc(fn)	((fn)->c.ffid > FF_C)
            #define funcproto(fn) \
              (GCproto *)(mref((fn)->l.pc, char)-sizeof(GCproto))
            #define sizeCfunc(n)	(sizeof(GCfuncC)-sizeof(TValue)+sizeof(TValue)*(n))
            #define sizeLfunc(n)	(sizeof(GCfuncL)-sizeof(GCRef)+sizeof(GCRef)*(n))

            /* Flags for prototype. */
            #define PROTO_CHILD		0x01	/* Has child prototypes. */
            #define PROTO_VARARG		0x02	/* Vararg function. */
            #define PROTO_FFI		0x04	/* Uses BC_KCDATA for FFI datatypes. */
            #define PROTO_NOJIT		0x08	/* JIT disabled for this function. */
            #define PROTO_ILOOP		0x10	/* Patched bytecode with ILOOP etc. */
            /* Only used during parsing. */
            #define PROTO_HAS_RETURN	0x20	/* Already emitted a return. */
            #define PROTO_FIXUP_RETURN	0x40	/* Need to fixup emitted returns. */
            /* Top bits used for counting created closures. */
            #define PROTO_CLCOUNT		0x20	/* Base of saturating 3 bit counter. */
            #define PROTO_CLC_BITS		3
            #define PROTO_CLC_POLY		(3*PROTO_CLCOUNT)  /* Polymorphic threshold. */

            #define PROTO_UV_LOCAL		0x8000	/* Upvalue for local slot. */
            #define PROTO_UV_IMMUTABLE	0x4000	/* Immutable upvalue. */

            #define proto_bc(pt)		((BCIns *)((char *)(pt) + sizeof(GCproto)))
            #define proto_bcpos(pt, pc)	((BCPos)((pc) - proto_bc(pt)))
            #define proto_uv(pt)		(mref((pt)->uv, uint16_t))

            #define proto_chunkname(pt)	(strref((pt)->chunkname))
            #define proto_chunknamestr(pt)	(strdata(proto_chunkname((pt))))
            #define proto_lineinfo(pt)	(mref((pt)->lineinfo, const void))
            #define proto_uvinfo(pt)	(mref((pt)->uvinfo, const uint8_t))
            #define proto_varinfo(pt)	(mref((pt)->varinfo, const uint8_t))

            /* Per-thread state object. */
            struct lua_State {
                GCHeader;
                uint8_t dummy_ffid;	/* Fake FF_C for curr_funcisL() on dummy frames. */
                uint8_t status;	/* Thread status. */
                MRef glref;		/* Link to global state. */
                GCRef gclist;		/* GC chain. */
                TValue* base;		/* Base of currently executing function. */
                TValue* top;		/* First free slot in the stack. */
                MRef maxstack;	/* Last free slot in the stack. */
                MRef stack;		/* Stack base. */
                GCRef openupval;	/* List of open upvalues in the stack. */
                GCRef env;		/* Thread environment (table of globals). */
                void* cframe;		/* End of C stack frame chain. */
                MSize stacksize;	/* True stack size (incl. LJ_STACK_EXTRA). */
            };

            typedef struct GChead {
                GCHeader;
                uint8_t unused1;
                uint8_t unused2;
                GCRef env;
                GCRef gclist;
                GCRef metatable;
            } GChead;

            /* String object header. String payload follows. */
            typedef struct GCstr {
                GCHeader;
                uint8_t reserved;	/* Used by lexer for fast lookup of reserved words. */
                uint8_t unused;
                MSize hash;		/* Hash of string. */
                MSize len;		/* Size of string. */
            } GCstr;

            /* Userdata object. Payload follows. */
            typedef struct GCudata {
                GCHeader;
                uint8_t udtype;	/* Userdata type. */
                uint8_t unused2;
                GCRef env;		/* Should be at same offset in GCfunc. */
                MSize len;		/* Size of payload. */
                GCRef metatable;	/* Must be at same offset in GCtab. */
                uint32_t align1;	/* To force 8 byte alignment of the payload. */
            } GCudata;

            /* C data object. Payload follows. */
            typedef struct GCcdata {
                GCHeader;
                uint16_t ctypeid;	/* C type ID. */
            } GCcdata;

            /* Prepended to variable-sized or realigned C data objects. */
            typedef struct GCcdataVar {
                uint16_t offset;	/* Offset to allocated memory (relative to GCcdata). */
                uint16_t extra;	/* Extra space allocated (incl. GCcdata + GCcdatav). */
                MSize len;		/* Size of payload. */
            } GCcdataVar;

            #define cdataptr(cd)	((void *)((cd)+1))
            #define cdataisv(cd)	((cd)->marked & 0x80)
            #define cdatav(cd)	((GCcdataVar *)((char *)(cd) - sizeof(GCcdataVar)))
            #define cdatavlen(cd)	check_exp(cdataisv(cd), cdatav(cd)->len)
            #define sizecdatav(cd)	(cdatavlen(cd) + cdatav(cd)->extra)
            #define memcdatav(cd)	((void *)((char *)(cd) - cdatav(cd)->offset))

            typedef int32_t BCLine;  /* Bytecode line number. */

            typedef struct GCproto {
                GCHeader;
                uint8_t numparams;	/* Number of parameters. */
                uint8_t framesize;	/* Fixed frame size. */
                MSize sizebc;		/* Number of bytecode instructions. */
            #if LJ_GC64
                uint32_t unused_gc64;
            #endif
                GCRef gclist;
                MRef k;		/* Split constant array (points to the middle). */
                MRef uv;		/* Upvalue list. local slot|0x8000 or parent uv idx. */
                MSize sizekgc;	/* Number of collectable constants. */
                MSize sizekn;		/* Number of lua_Number constants. */
                MSize sizept;		/* Total size including colocated arrays. */
                uint8_t sizeuv;	/* Number of upvalues. */
                uint8_t flags;	/* Miscellaneous flags (see below). */
                uint16_t trace;	/* Anchor for chain of root traces. */
                /* ------ The following fields are for debugging/tracebacks only ------ */
                GCRef chunkname;	/* Name of the chunk this function was defined in. */
                BCLine firstline;	/* First line of the function definition. */
                BCLine numline;	/* Number of lines for the function definition. */
                MRef lineinfo;	/* Compressed map from bytecode ins. to source line. */
                MRef uvinfo;		/* Upvalue names. */
                MRef varinfo;		/* Names and compressed extents of local variables. */
            } GCproto;

            typedef struct GCupval {
                GCHeader;
                uint8_t closed;	/* Set if closed (i.e. uv->v == &uv->u.value). */
                uint8_t immutable;	/* Immutable value. */
                union {
                    TValue tv;		/* If closed: the value itself. */
                    struct {		/* If open: double linked list, anchored at thread. */
                        GCRef prev;
                        GCRef next;
                    };
                };
                MRef v;		/* Points to stack slot (open) or above (closed). */
                uint32_t dhash;	/* Disambiguation hash: dh1 != dh2 => cannot alias. */
            } GCupval;

            typedef struct GCtab {
                GCHeader;
                uint8_t nomm;		/* Negative cache for fast metamethods. */
                int8_t colo;		/* Array colocation. */
                MRef array;		/* Array part. */
                GCRef gclist;
                GCRef metatable;	/* Must be at same offset in GCudata. */
                MRef node;		/* Hash part. */
                uint32_t asize;	/* Size of array part (keys [0, asize-1]). */
                uint32_t hmask;	/* Hash part mask (size of hash part - 1). */
            #if LJ_GC64
                MRef freetop;		/* Top of free elements. */
            #endif
            } GCtab;

            typedef union GCobj {
                GChead gch;
                GCstr str;
                GCupval uv;
                lua_State th;
                GCproto pt;
                GCfunc fn;
                GCcdata cd;
                GCtab tab;
                GCudata ud;
            } GCobj;

            /* Garbage collector state. */
            typedef struct GCState {
                GCSize total;		/* Memory currently allocated. */
                GCSize threshold;	/* Memory threshold. */
                uint8_t currentwhite;	/* Current white color. */
                uint8_t state;	/* GC state. */
                uint8_t nocdatafin;	/* No cdata finalizer called. */
                uint8_t unused2;
                MSize sweepstr;	/* Sweep position in string table. */
                GCRef root;		/* List of all collectable objects. */
                MRef sweep;		/* Sweep position in root list. */
                GCRef gray;		/* List of gray objects. */
                GCRef grayagain;	/* List of objects for atomic traversal. */
                GCRef weak;		/* List of weak tables (to be cleared). */
                GCRef mmudata;	/* List of userdata (to be finalized). */
                GCSize debt;		/* Debt (how much GC is behind schedule). */
                GCSize estimate;	/* Estimate of memory actually in use. */
                MSize stepmul;	/* Incremental GC step granularity. */
                MSize pause;		/* Pause between successive GC cycles. */
            } GCState;

            /* Resizable string buffer. Need this here, details in lj_buf.h. */
            typedef struct SBuf {
                MRef p;		/* String buffer pointer. */
                MRef e;		/* String buffer end pointer. */
                MRef b;		/* String buffer base. */
                MRef L;		/* lua_State, used for buffer resizing. */
            } SBuf;

            /* Hash node. */
            typedef struct Node {
                TValue val;		/* Value object. Must be first field. */
                TValue key;		/* Key object. */
                MRef next;		/* Hash chain. */
            #if !LJ_GC64
                MRef freetop;		/* Top of free elements (stored in t->node[0]). */
            #endif
            } Node;

            /* -- Lua stack frame ----------------------------------------------------- */

            /* Frame type markers in LSB of PC (4-byte aligned) or delta (8-byte aligned:
            **
            **    PC  00  Lua frame
            ** delta 001  C frame
            ** delta 010  Continuation frame
            ** delta 011  Lua vararg frame
            ** delta 101  cpcall() frame
            ** delta 110  ff pcall() frame
            ** delta 111  ff pcall() frame with active hook
            */
            enum {
              FRAME_LUA, FRAME_C, FRAME_CONT, FRAME_VARG,
              FRAME_LUAP, FRAME_CP, FRAME_PCALL, FRAME_PCALLH
            };
            #define FRAME_TYPE		3
            #define FRAME_P			4
            #define FRAME_TYPEP		(FRAME_TYPE|FRAME_P)

            /* Macros to access and modify Lua frames. */
            #if LJ_FR2
            /* Two-slot frame info, required for 64 bit PC/GCRef:
            **
            **                   base-2  base-1      |  base  base+1 ...
            **                  [func   PC/delta/ft] | [slots ...]
            **                  ^-- frame            | ^-- base   ^-- top
            **
            ** Continuation frames:
            **
            **   base-4  base-3  base-2  base-1      |  base  base+1 ...
            **  [cont      PC ] [func   PC/delta/ft] | [slots ...]
            **                  ^-- frame            | ^-- base   ^-- top
            */
            #define frame_gc(f)		(gcval((f)-1))
            #define frame_ftsz(f)		((ptrdiff_t)(f)->ftsz)
            #define frame_pc(f)		((const BCIns *)frame_ftsz(f))
            #define setframe_gc(f, p, tp)	(setgcVraw((f)-1, (p), (tp)))
            #define setframe_ftsz(f, sz)	((f)->ftsz = (sz))
            #define setframe_pc(f, pc)	((f)->ftsz = (int64_t)(intptr_t)(pc))
            #else
            /* One-slot frame info, sufficient for 32 bit PC/GCRef:
            **
            **              base-1              |  base  base+1 ...
            **              lo     hi           |
            **             [func | PC/delta/ft] | [slots ...]
            **             ^-- frame            | ^-- base   ^-- top
            **
            ** Continuation frames:
            **
            **  base-2      base-1              |  base  base+1 ...
            **  lo     hi   lo     hi           |
            ** [cont | PC] [func | PC/delta/ft] | [slots ...]
            **             ^-- frame            | ^-- base   ^-- top
            */
            #define frame_gc(f)		(gcref((f)->fr.func))
            #define frame_ftsz(f)		((ptrdiff_t)(f)->fr.tp.ftsz)
            #define frame_pc(f)		(mref((f)->fr.tp.pcr, const BCIns))
            #define setframe_gc(f, p, tp)	(setgcref((f)->fr.func, (p)), UNUSED(tp))
            #define setframe_ftsz(f, sz)	((f)->fr.tp.ftsz = (int32_t)(sz))
            #define setframe_pc(f, pc)	(setmref((f)->fr.tp.pcr, (pc)))
            #endif

            #define frame_type(f)		(frame_ftsz(f) & FRAME_TYPE)
            #define frame_typep(f)		(frame_ftsz(f) & FRAME_TYPEP)
            #define frame_islua(f)		(frame_type(f) == FRAME_LUA)
            #define frame_isc(f)		(frame_type(f) == FRAME_C)
            #define frame_iscont(f)		(frame_typep(f) == FRAME_CONT)
            #define frame_isvarg(f)		(frame_typep(f) == FRAME_VARG)
            #define frame_ispcall(f)	((frame_ftsz(f) & 6) == FRAME_PCALL)

            #define frame_func(f)		(&frame_gc(f)->fn)
            #define frame_delta(f)		(frame_ftsz(f) >> 3)
            #define frame_sized(f)		(frame_ftsz(f) & ~FRAME_TYPEP)

            enum { LJ_CONT_TAILCALL, LJ_CONT_FFI_CALLBACK };  /* Special continuations. */

            #if LJ_FR2
            #define frame_contpc(f)		(frame_pc((f)-2))
            #define frame_contv(f)		(((f)-3)->u64)
            #else
            #define frame_contpc(f)		(frame_pc((f)-1))
            #define frame_contv(f)		(((f)-1)->u32.lo)
            #endif
            #if LJ_FR2
            #define frame_contf(f)		((ASMFunction)(uintptr_t)((f)-3)->u64)
            #elif LJ_64
            #define frame_contf(f) \
              ((ASMFunction)(void *)((intptr_t)lj_vm_asm_begin + \
			             (intptr_t)(int32_t)((f)-1)->u32.lo))
            #else
            #define frame_contf(f)		((ASMFunction)gcrefp(((f)-1)->gcr, void))
            #endif
            #define frame_iscont_fficb(f) \
              (LJ_HASFFI && frame_contv(f) == LJ_CONT_FFI_CALLBACK)

            #define frame_prevl(f)		((f) - (1+LJ_FR2+bc_a(frame_pc(f)[-1])))
            #define frame_prevd(f)		((TValue *)((char *)(f) - frame_sized(f)))
            #define frame_prev(f)		(frame_islua(f)?frame_prevl(f):frame_prevd(f))

            /* Types for handling bytecodes. Need this here, details in lj_bc.h. */
            typedef uint32_t BCIns;  /* Bytecode instruction. */
            typedef uint32_t BCPos;  /* Bytecode position. */
            typedef uint32_t BCReg;  /* Bytecode register. */
            typedef int32_t BCLine;  /* Bytecode line number. */

            /* Bytecode instruction format, 32 bit wide, fields of 8 or 16 bit:
            **
            ** +----+----+----+----+
            ** | B  | C  | A  | OP | Format ABC
            ** +----+----+----+----+
            ** |    D    | A  | OP | Format AD
            ** +--------------------
            ** MSB               LSB
            **
            ** In-memory instructions are always stored in host byte order.
            */

            /* Operand ranges and related constants. */
            #define BCMAX_A		0xff
            #define BCMAX_B		0xff
            #define BCMAX_C		0xff
            #define BCMAX_D		0xffff
            #define BCBIAS_J	0x8000
            #define NO_REG		BCMAX_A
            #define NO_JMP		(~(BCPos)0)

            /* Macros to get instruction fields. */
            #define bc_op(i)	((BCOp)((i)&0xff))
            #define bc_a(i)		((BCReg)(((i)>>8)&0xff))
            #define bc_b(i)		((BCReg)((i)>>24))
            #define bc_c(i)		((BCReg)(((i)>>16)&0xff))
            #define bc_d(i)		((BCReg)((i)>>16))
            #define bc_j(i)		((ptrdiff_t)bc_d(i)-BCBIAS_J)

            /* Macros to set instruction fields. */
            #define setbc_byte(p, x, ofs) \
              ((uint8_t *)(p))[LJ_ENDIAN_SELECT(ofs, 3-ofs)] = (uint8_t)(x)
            #define setbc_op(p, x)	setbc_byte(p, (x), 0)
            #define setbc_a(p, x)	setbc_byte(p, (x), 1)
            #define setbc_b(p, x)	setbc_byte(p, (x), 3)
            #define setbc_c(p, x)	setbc_byte(p, (x), 2)
            #define setbc_d(p, x) \
              ((uint16_t *)(p))[LJ_ENDIAN_SELECT(1, 0)] = (uint16_t)(x)
            #define setbc_j(p, x)	setbc_d(p, (BCPos)((int32_t)(x)+BCBIAS_J))

            /* Macros to compose instructions. */
            #define BCINS_ABC(o, a, b, c) \
              (((BCIns)(o))|((BCIns)(a)<<8)|((BCIns)(b)<<24)|((BCIns)(c)<<16))
            #define BCINS_AD(o, a, d) \
              (((BCIns)(o))|((BCIns)(a)<<8)|((BCIns)(d)<<16))
            #define BCINS_AJ(o, a, j)	BCINS_AD(o, a, (BCPos)((int32_t)(j)+BCBIAS_J))

            /* Bytecode instruction definition. Order matters, see below.
            **
            ** (name, filler, Amode, Bmode, Cmode or Dmode, metamethod)
            **
            ** The opcode name suffixes specify the type for RB/RC or RD:
            ** V = variable slot
            ** S = string const
            ** N = number const
            ** P = primitive type (~itype)
            ** B = unsigned byte literal
            ** M = multiple args/results
            */
            #define BCDEF(_) \
              /* Comparison ops. ORDER OPR. */ \
              _(ISLT,	var,	___,	var,	lt) \
              _(ISGE,	var,	___,	var,	lt) \
              _(ISLE,	var,	___,	var,	le) \
              _(ISGT,	var,	___,	var,	le) \
              \
              _(ISEQV,	var,	___,	var,	eq) \
              _(ISNEV,	var,	___,	var,	eq) \
              _(ISEQS,	var,	___,	str,	eq) \
              _(ISNES,	var,	___,	str,	eq) \
              _(ISEQN,	var,	___,	num,	eq) \
              _(ISNEN,	var,	___,	num,	eq) \
              _(ISEQP,	var,	___,	pri,	eq) \
              _(ISNEP,	var,	___,	pri,	eq) \
              \
              /* Unary test and copy ops. */ \
              _(ISTC,	dst,	___,	var,	___) \
              _(ISFC,	dst,	___,	var,	___) \
              _(IST,	___,	___,	var,	___) \
              _(ISF,	___,	___,	var,	___) \
              _(ISTYPE,	var,	___,	lit,	___) \
              _(ISNUM,	var,	___,	lit,	___) \
              \
              /* Unary ops. */ \
              _(MOV,	dst,	___,	var,	___) \
              _(NOT,	dst,	___,	var,	___) \
              _(UNM,	dst,	___,	var,	unm) \
              _(LEN,	dst,	___,	var,	len) \
              \
              /* Binary ops. ORDER OPR. VV last, POW must be next. */ \
              _(ADDVN,	dst,	var,	num,	add) \
              _(SUBVN,	dst,	var,	num,	sub) \
              _(MULVN,	dst,	var,	num,	mul) \
              _(DIVVN,	dst,	var,	num,	div) \
              _(MODVN,	dst,	var,	num,	mod) \
              \
              _(ADDNV,	dst,	var,	num,	add) \
              _(SUBNV,	dst,	var,	num,	sub) \
              _(MULNV,	dst,	var,	num,	mul) \
              _(DIVNV,	dst,	var,	num,	div) \
              _(MODNV,	dst,	var,	num,	mod) \
              \
              _(ADDVV,	dst,	var,	var,	add) \
              _(SUBVV,	dst,	var,	var,	sub) \
              _(MULVV,	dst,	var,	var,	mul) \
              _(DIVVV,	dst,	var,	var,	div) \
              _(MODVV,	dst,	var,	var,	mod) \
              \
              _(POW,	dst,	var,	var,	pow) \
              _(CAT,	dst,	rbase,	rbase,	concat) \
              \
              /* Constant ops. */ \
              _(KSTR,	dst,	___,	str,	___) \
              _(KCDATA,	dst,	___,	cdata,	___) \
              _(KSHORT,	dst,	___,	lits,	___) \
              _(KNUM,	dst,	___,	num,	___) \
              _(KPRI,	dst,	___,	pri,	___) \
              _(KNIL,	base,	___,	base,	___) \
              \
              /* Upvalue and function ops. */ \
              _(UGET,	dst,	___,	uv,	___) \
              _(USETV,	uv,	___,	var,	___) \
              _(USETS,	uv,	___,	str,	___) \
              _(USETN,	uv,	___,	num,	___) \
              _(USETP,	uv,	___,	pri,	___) \
              _(UCLO,	rbase,	___,	jump,	___) \
              _(FNEW,	dst,	___,	func,	gc) \
              \
              /* Table ops. */ \
              _(TNEW,	dst,	___,	lit,	gc) \
              _(TDUP,	dst,	___,	tab,	gc) \
              _(GGET,	dst,	___,	str,	index) \
              _(GSET,	var,	___,	str,	newindex) \
              _(TGETV,	dst,	var,	var,	index) \
              _(TGETS,	dst,	var,	str,	index) \
              _(TGETB,	dst,	var,	lit,	index) \
              _(TGETR,	dst,	var,	var,	index) \
              _(TSETV,	var,	var,	var,	newindex) \
              _(TSETS,	var,	var,	str,	newindex) \
              _(TSETB,	var,	var,	lit,	newindex) \
              _(TSETM,	base,	___,	num,	newindex) \
              _(TSETR,	var,	var,	var,	newindex) \
              \
              /* Calls and vararg handling. T = tail call. */ \
              _(CALLM,	base,	lit,	lit,	call) \
              _(CALL,	base,	lit,	lit,	call) \
              _(CALLMT,	base,	___,	lit,	call) \
              _(CALLT,	base,	___,	lit,	call) \
              _(ITERC,	base,	lit,	lit,	call) \
              _(ITERN,	base,	lit,	lit,	call) \
              _(VARG,	base,	lit,	lit,	___) \
              _(ISNEXT,	base,	___,	jump,	___) \
              \
              /* Returns. */ \
              _(RETM,	base,	___,	lit,	___) \
              _(RET,	rbase,	___,	lit,	___) \
              _(RET0,	rbase,	___,	lit,	___) \
              _(RET1,	rbase,	___,	lit,	___) \
              \
              /* Loops and branches. I/J = interp/JIT, I/C/L = init/call/loop. */ \
              _(FORI,	base,	___,	jump,	___) \
              _(JFORI,	base,	___,	jump,	___) \
              \
              _(FORL,	base,	___,	jump,	___) \
              _(IFORL,	base,	___,	jump,	___) \
              _(JFORL,	base,	___,	lit,	___) \
              \
              _(ITERL,	base,	___,	jump,	___) \
              _(IITERL,	base,	___,	jump,	___) \
              _(JITERL,	base,	___,	lit,	___) \
              \
              _(LOOP,	rbase,	___,	jump,	___) \
              _(ILOOP,	rbase,	___,	jump,	___) \
              _(JLOOP,	rbase,	___,	lit,	___) \
              \
              _(JMP,	rbase,	___,	jump,	___) \
              \
              /* Function headers. I/J = interp/JIT, F/V/C = fixarg/vararg/C func. */ \
              _(FUNCF,	rbase,	___,	___,	___) \
              _(IFUNCF,	rbase,	___,	___,	___) \
              _(JFUNCF,	rbase,	___,	lit,	___) \
              _(FUNCV,	rbase,	___,	___,	___) \
              _(IFUNCV,	rbase,	___,	___,	___) \
              _(JFUNCV,	rbase,	___,	lit,	___) \
              _(FUNCC,	rbase,	___,	___,	___) \
              _(FUNCCW,	rbase,	___,	___,	___)

            /* Bytecode opcode numbers. */
            typedef enum {
            #define BCENUM(name, ma, mb, mc, mt)	BC_##name,
            BCDEF(BCENUM)
            #undef BCENUM
              BC__MAX
            } BCOp;

            #ifdef LJ_HASFFI
                #define MMDEF_FFI(_) _(new)
            #else
                #define MMDEF_FFI(_)
            #endif

            #if LJ_52 || LJ_HASFFI
                #define MMDEF_PAIRS(_) _(pairs) _(ipairs)
            #else
                #define MMDEF_PAIRS(_)
                #define MM_pairs	255
                #define MM_ipairs	255
            #endif

            #define MMDEF(_) \
                _(index) _(newindex) _(gc) _(mode) _(eq) _(len) \
                /* Only the above (fast) metamethods are negative cached (max. 8). */ \
                _(lt) _(le) _(concat) _(call) \
                /* The following must be in ORDER ARITH. */ \
                _(add) _(sub) _(mul) _(div) _(mod) _(pow) _(unm) \
                /* The following are used in the standard libraries. */ \
                _(metatable) _(tostring) MMDEF_FFI(_) MMDEF_PAIRS(_)

            typedef enum {
            #define MMENUM(name)	MM_##name,
            MMDEF(MMENUM)
            #undef MMENUM
                MM__MAX,
                MM____ = MM__MAX,
                MM_FAST = MM_len
            } MMS;

            /* GC root IDs. */
            typedef enum {
                GCROOT_MMNAME,	/* Metamethod names. */
                GCROOT_MMNAME_LAST = GCROOT_MMNAME + MM__MAX - 1,
                GCROOT_BASEMT,	/* Metatables for base types. */
                GCROOT_BASEMT_NUM = GCROOT_BASEMT + ~LJ_TNUMX,
                GCROOT_IO_INPUT,	/* Userdata for default I/O input file. */
                GCROOT_IO_OUTPUT,	/* Userdata for default I/O output file. */
                GCROOT_MAX
            } GCRootID;

            #define LUA_IDSIZE	60	/* Size of lua_Debug.short_src. */
            struct lua_Debug {
                int event;
                const char* name;	/* (n) */
                const char* namewhat;	/* (n) `global', `local', `field', `method' */
                const char* what;	/* (S) `Lua', `C', `main', `tail' */
                const char* source;	/* (S) */
                int currentline;	/* (l) */
                int nups;		/* (u) number of upvalues */
                int linedefined;	/* (S) */
                int lastlinedefined;	/* (S) */
                char short_src[LUA_IDSIZE]; /* (S) */
                /* private part */
                int i_ci;  /* active function */
            };

            typedef void* (*lua_Alloc) (void* ud, void* ptr, size_t osize, size_t nsize);
            typedef void (*lua_Hook) (lua_State* L, lua_Debug* ar);

            /* Global state, shared by all threads of a Lua universe. */
            typedef struct global_State {
                GCRef* strhash;	/* String hash table (hash chain anchors). */
                MSize strmask;	/* String hash mask (size of hash table - 1). */
                MSize strnum;		/* Number of strings in hash table. */
                lua_Alloc allocf;	/* Memory allocator. */
                void* allocd;		/* Memory allocator data. */
                GCState gc;		/* Garbage collector. */
                volatile int32_t vmstate;  /* VM state or current JIT code trace number. */
                SBuf tmpbuf;		/* Temporary string buffer. */
                GCstr strempty;	/* Empty string. */
                uint8_t stremptyz;	/* Zero terminator of empty string. */
                uint8_t hookmask;	/* Hook mask. */
                uint8_t dispatchmode;	/* Dispatch mode. */
                uint8_t vmevmask;	/* VM event mask. */
                GCRef mainthref;	/* Link to main thread. */
                TValue registrytv;	/* Anchor for registry. */
                TValue tmptv, tmptv2;	/* Temporary TValues. */
                Node nilnode;		/* Fallback 1-element hash part (nil key and value). */
                GCupval uvhead;	/* Head of double-linked list of all open upvalues. */
                int32_t hookcount;	/* Instruction hook countdown. */
                int32_t hookcstart;	/* Start count for instruction hook counter. */
                lua_Hook hookf;	/* Hook function. */
                lua_CFunction wrapf;	/* Wrapper for C function calls. */
                lua_CFunction panic;	/* Called as a last resort for errors. */
                BCIns bc_cfunc_int;	/* Bytecode for internal C function calls. */
                BCIns bc_cfunc_ext;	/* Bytecode for external C function calls. */
                GCRef cur_L;		/* Currently executing lua_State. */
                MRef jit_base;	/* Current JIT code L->base or NULL. */
                MRef ctype_state;	/* Pointer to C type state. */
                GCRef gcroot[GCROOT_MAX];  /* GC roots. */
            } global_State;
        #endif
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
            extern bool isproto(lua_State* L, int index);
            extern bool isuserdatatype(lua_State* L, int index, int type);
            extern bool isthread(lua_State* L, int index);
            extern void newtable(lua_State* L);
            extern void pop(lua_State* L, int count = 1);
            extern void newuserdatatype(lua_State* L, void* data, size_t size, unsigned char type);
            extern void* touserdatatype(lua_State* L, int index);
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

        struct state_tracking {
            std::string name;
            std::shared_ptr<std::mutex> mutex;
            state_union state;
            bool threaded;
            bool internal;
            bool root;
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
        extern bool should_lock(API::lua_State* target, API::lua_State* source);
        extern std::string get_name(API::lua_State* L);
        extern std::vector<std::pair<std::string, API::lua_State*>> get_states();
        extern std::unique_lock<std::mutex> lock(API::lua_State* L);
        extern std::unique_lock<std::mutex> lock(void* L);
        extern std::unique_lock<std::mutex> lock(uintptr_t L);
        extern std::unique_lock<std::mutex> lock(std::string name);
        extern void cross_lock(API::lua_State* target, API::lua_State* source);
        extern void cross_unlock(API::lua_State* target, API::lua_State* source);
        extern void listen(API::lua_State* L, std::string name, bool internal = false);
        extern void listen(API::lua_State* L, std::string name, std::shared_ptr<std::mutex> guard, bool internal = false);
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
        extern API::lua_State* open(std::string name, bool internal = false, bool threaded = false);

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