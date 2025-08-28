#include <string.h>

#include "interstellar_memory.hpp"
#include "interstellar_os.hpp"

#if defined(_WIN32)
#include <psapi.h>
#include <iostream>
#include <windows.h>
#elif defined(__linux)
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <link.h>
#include <cstddef>
#include <stdint.h>
#endif

#include <string>
#include <array>
#include <map>
#include <unordered_set>

#include <string_view>
#include <sstream>
#include <fstream>
#include <iomanip>

#if defined(_MSC_VER)
#define BEGIN_NOOPT __pragma(optimize("", off))
#define END_NOOPT   __pragma(optimize("", on))
#elif defined(__GNUC__) || defined(__clang__)
#define BEGIN_NOOPT _Pragma("GCC push_options") \
                            _Pragma("GCC optimize(\"O0\")")
#define END_NOOPT   _Pragma("GCC pop_options")
#else
#define BEGIN_NOOPT
#define END_NOOPT
#endif

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

namespace INTERSTELLAR_NAMESPACE::Memory {
    using namespace API;
    
    #ifdef __linux
    #define UMODULE void*
    #else
    #define UMODULE HMODULE
    #endif

    static auto _wc(std::string_view pattern) noexcept
    {
        std::array<std::size_t, 256> table;

        auto lastWildcard = pattern.rfind('?');
        if (lastWildcard == std::string_view::npos)
            lastWildcard = 0;

        const auto defaultShift = (std::max)(std::size_t(1), pattern.length() - 1 - lastWildcard);
        table.fill(defaultShift);

        for (auto i = lastWildcard; i < pattern.length() - 1; ++i)
            table[static_cast<std::uint8_t>(pattern[i])] = pattern.length() - 1 - i;

        return table;
    }

    void* scanner_locate(void* hndle, std::size_t& module_size) noexcept
    {
        void* module_base = nullptr;
        module_size = 0;
        
        #if defined(__linux__)
        std::ifstream maps("/proc/self/maps");
        std::unordered_set<std::string> seen;
        std::string line;

        while (std::getline(maps, line)) {
            std::istringstream iss(line);
            std::string addr_range, perms, offset, dev, inode, pathname;
            if (!(iss >> addr_range >> perms >> offset >> dev >> inode)) continue;
            if (iss >> pathname && pathname[0] != '/' || seen.count(pathname)) continue;

            seen.insert(pathname);
            void* module = dlopen(pathname.c_str(), RTLD_LAZY);
            if (!module) continue;
            dlclose(module);
            if (module != hndle) continue;

            size_t dash = addr_range.find('-');
            if (dash == std::string::npos) continue;

            void* base;
            size_t size;
            base = (void*)std::stoul(addr_range.substr(0, dash), nullptr, 16);
            void* end = (void*)std::stoul(addr_range.substr(dash + 1), nullptr, 16);
            size = (size_t)end - (size_t)base;

            module_base = base;
            module_size = size;
        }
        #elif defined(_WIN32)
        if (MODULEINFO moduleInfo; GetModuleInformation(GetCurrentProcess(), (HMODULE)hndle, &moduleInfo, sizeof(moduleInfo))) {
            module_base = moduleInfo.lpBaseOfDll;
            module_size = moduleInfo.SizeOfImage;
        }
        #endif

        if (!module_base || !module_size) return nullptr;

        return (void*)module_base;
    }

    char* scan_hex(void* hndle, std::string pattern) noexcept
    {
        std::size_t module_size = 0;
        void* module_base = scanner_locate(hndle, module_size);
        if (!module_base || !module_size) return nullptr;

        if (module_base && module_size) {
            int lastIdx = pattern.length() - 1;
            const auto Wildcards = _wc(pattern);

            auto start = static_cast<const char*>(module_base);
            const auto end = start + module_size - pattern.length();

            while (start <= end) {
                int i = lastIdx;
                while (i >= 0 && (pattern[i] == '?' || start[i] == pattern[i]))
                    --i;

                if (i < 0) {
                    return (char*)start;
                }

                start += Wildcards[static_cast<std::uint8_t>(start[lastIdx])];
            }
        }

        return nullptr;
    }

    char* scan_ida(void* hndle, const std::string& pattern) noexcept
    {
        std::string hex_string_no_spaces;
        for (char ch : pattern) {
            if (!std::isspace(static_cast<unsigned char>(ch))) {
                hex_string_no_spaces += ch;
            }
        }

        std::string hex_pattern;
        for (size_t i = 0; i < hex_string_no_spaces.size(); ++i) {
            if (hex_string_no_spaces[i] == '?') {
                hex_pattern.push_back('?');
                continue;
            }
            if (i + 1 >= hex_string_no_spaces.size()) break;
            std::string byte_str = hex_string_no_spaces.substr(i, 2);
            unsigned char byte_val = static_cast<unsigned char>(std::stoul(byte_str, nullptr, 16));
            hex_pattern.push_back(byte_val);
            ++i;
        }

        return scan_hex(hndle, hex_pattern);
    }

    #ifdef _WIN32
        #include <Windows.h>
        #include <winternl.h>
        #include <cstddef>
    
        typedef struct T_LDR_DATA_TABLE_ENTRY {
            LIST_ENTRY InLoadOrderLinks;
            LIST_ENTRY InMemoryOrderLinks;
            LIST_ENTRY InInitializationOrderLinks;
            PVOID      DllBase;
            PVOID      EntryPoint;
            ULONG      SizeOfImage;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
        } T_LDR_DATA_TABLE_ENTRY, *P_LDR_DATA_TABLE_ENTRY;

        std::string UnicodeStringToString(const UNICODE_STRING& unicodeStr) {
            if (!unicodeStr.Buffer || unicodeStr.Length == 0) {
                return "";
            }

            int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, unicodeStr.Buffer, unicodeStr.Length / sizeof(wchar_t), nullptr, 0, nullptr, nullptr);
            if (sizeNeeded == 0) {
                return "";
            }

            std::string utf8String(sizeNeeded, '\0');
            WideCharToMultiByte(CP_UTF8, 0, unicodeStr.Buffer, unicodeStr.Length / sizeof(wchar_t), &utf8String[0], sizeNeeded, nullptr, nullptr);

            return utf8String;
        }
    #else
        struct ModuleInfo {
            std::string name;
            void* base;
            size_t size;
        };
    #endif

    int address__tostring(lua_State* L)
    {
        char* address = (char*)Class::check(L, 1, "address");
        std::stringstream ss;
        ss << "address: 0x" << std::hex << reinterpret_cast<uintptr_t>(address);
        lua::pushcstring(L, ss.str());
        return 1;
    }

    void push_address(lua_State* L, void* addr);

    int address__add(lua_State* L) {
        char* a = (char*)Class::check(L, 1, "address");
        char* b = (char*)Class::check(L, 2, "address");
        push_address(L, (void*)((uintptr_t)a + (uintptr_t)b));
        return 1;
    }

    int address__sub(lua_State* L) {
        char* a = (char*)Class::check(L, 1, "address");
        char* b = (char*)Class::check(L, 2, "address");
        push_address(L, (void*)((uintptr_t)a - (uintptr_t)b));
        return 1;
    }

    int address__index(lua_State* L)
    {
        char* address = (char*)Class::check(L, 1, "address");
        std::string index = luaL::checkcstring(L, 2);

        if (index == "raw") {
            lua::pushinteger(L, (uintptr_t)address);
            return 1;
        }

        return 0;
    }

    void push_address(lua_State* L, void* addr)
    {
        if (!Class::existsbyname(L, "address")) {
            Class::create(L, "address");

            lua::pushcfunction(L, address__index);
            lua::setfield(L, -2, "__index");

            lua::pushcfunction(L, address__tostring);
            lua::setfield(L, -2, "__tostring");

            lua::pushcfunction(L, address__add);
            lua::setfield(L, -2, "__add");

            lua::pushcfunction(L, address__sub);
            lua::setfield(L, -2, "__sub");

            lua::pop(L);
        }

        Class::spawn(L, addr, "address");
    }

    struct memory_module {
        std::string name;
        uintptr_t address;
        uintptr_t base;
        size_t size;
    };

    int module__tostring(lua_State* L)
    {
        memory_module* _module = (memory_module*)Class::check(L, 1, "module");
        lua::pushcstring(L, "module: " + _module->name);
        return 1;
    }

    int module__index(lua_State* L)
    {
        memory_module* _module = (memory_module*)Class::check(L, 1, "module");
        std::string index = luaL::checkcstring(L, 2);

        if (index == "name") {
            lua::pushcstring(L, _module->name);
            return 1;
        } else if (index == "address") {
            push_address(L, (void*)_module->address);
            return 1;
        } else if (index == "base") {
            push_address(L, (void*)_module->base);
            return 1;
        } else if (index == "size") {
            lua::pushnumber(L, _module->size);
            return 1;
        }

        return 0;
    }

    int module__gc(lua_State* L)
    {
        if (Class::is(L, 1, "module")) {
            delete (memory_module*)Class::to(L, 1);
        }
        return 0;
    }

    #ifdef _WIN32
        void push_module(lua_State* L, std::string name, HMODULE& hModule, MODULEINFO& moduleInfo)
        {
            memory_module* mem_module = new memory_module({name, (uintptr_t)hModule, (uintptr_t)moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage});

            if (!Class::existsbyname(L, "module")) {
                Class::create(L, "module");

                lua::pushcfunction(L, module__tostring);
                lua::setfield(L, -2, "__tostring");

                lua::pushcfunction(L, module__index);
                lua::setfield(L, -2, "__index");

                lua::pushcfunction(L, module__gc);
                lua::setfield(L, -2, "__gc");

                lua::pop(L);
            }

            Class::spawn(L, mem_module, "module");
        }
    #else
        void push_module(lua_State* L, std::string name, void* module, void* base, size_t size)
        {
            memory_module* mem_module = new memory_module({name, (uintptr_t)module, (uintptr_t)base, size});

            if (!Class::existsbyname(L, "module")) {
                Class::create(L, "module");

                lua::pushcfunction(L, module__tostring);
                lua::setfield(L, -2, "__tostring");

                lua::pushcfunction(L, module__index);
                lua::setfield(L, -2, "__index");

                lua::pushcfunction(L, module__gc);
                lua::setfield(L, -2, "__gc");

                lua::pop(L);
            }

            Class::spawn(L, mem_module, "module");
        }
    #endif

    void* check_module(lua_State* L, int index) {
        memory_module* mem_module = (memory_module*)Class::check(L, index, "module");
        return (void*)mem_module->address;
    }

    bool is_valid_read(void* address, size_t size) {
        #ifdef _WIN32
            return address != nullptr && !IsBadReadPtr(address, size);
        #else
            return address != nullptr;
        #endif
    }

    bool is_valid_write(void* address, size_t size) {
        #ifdef _WIN32
            return address != nullptr && !IsBadWritePtr(address, size);
        #else
            return address != nullptr;
        #endif
    }

    #if defined(__linux__)
        static bool get_page_permissions(void* addr, int& out_prot) {
            std::ifstream maps("/proc/self/maps");
            if (!maps.is_open()) return false;

            std::string line;
            uintptr_t target = reinterpret_cast<uintptr_t>(addr);

            while (std::getline(maps, line)) {
                uintptr_t start, end;
                char perms[5] = {0};

                std::istringstream iss(line);
                iss >> std::hex >> start;
                iss.ignore(1);
                iss >> std::hex >> end;
                iss >> perms;

                if (target >= start && target < end) {
                    int prot = 0;
                    if (perms[0] == 'r') prot |= PROT_READ;
                    if (perms[1] == 'w') prot |= PROT_WRITE;
                    if (perms[2] == 'x') prot |= PROT_EXEC;

                    out_prot = prot;
                    return true;
                }
            }

            return false;
        }
    #endif

    bool is_writable(void* addr) {
        #if defined(__linux__)
            int current_prot;
            if (!get_page_permissions(addr, current_prot)) return false;
            return (current_prot & PROT_WRITE) == PROT_WRITE;
        #elif defined(_WIN32)
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;

            DWORD protect = mbi.Protect;
            if (protect & PAGE_GUARD || protect & PAGE_NOACCESS) return false;

            return (protect & PAGE_READWRITE) || (protect & PAGE_EXECUTE_READWRITE) || (protect & PAGE_WRITECOPY) || (protect & PAGE_EXECUTE_WRITECOPY);
        #endif
    }

    bool is_readable(void* addr) {
        #if defined(__linux__)
            int current_prot;
            if (!get_page_permissions(addr, current_prot)) return false;
            return (current_prot & PROT_READ) == PROT_READ;
        #elif defined(_WIN32)
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;

            DWORD protect = mbi.Protect;
            if (protect & PAGE_GUARD || protect & PAGE_NOACCESS) return false;

            return (protect & PAGE_READONLY) || (protect & PAGE_READWRITE) || (protect & PAGE_EXECUTE_READ) || (protect & PAGE_EXECUTE_READWRITE);
        #endif
    }

    bool make_writeable(void* addr, bool writeable) {
        #if defined(__linux__)
            uintptr_t page_size = sysconf(_SC_PAGESIZE);
            uintptr_t page_start = (uintptr_t)addr & ~(page_size - 1);

            int current_prot;
            if (!get_page_permissions(addr, current_prot)) return false;

            if (writeable)
                current_prot |= PROT_WRITE;
            else
                current_prot &= ~PROT_WRITE;

            return mprotect((void*)page_start, page_size, current_prot) == 0;
        #elif defined(_WIN32)
            DWORD oldProtect;
            MEMORY_BASIC_INFORMATION mbi;

            if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;

            DWORD newProtect = mbi.Protect;

            if (writeable) {
                if (newProtect & PAGE_EXECUTE_READ) newProtect = PAGE_EXECUTE_READWRITE;
                else if (newProtect & PAGE_READONLY) newProtect = PAGE_READWRITE;
                else if (newProtect & PAGE_EXECUTE) newProtect = PAGE_EXECUTE_READWRITE;
                else newProtect = PAGE_READWRITE;
            } else {
                if (newProtect & PAGE_EXECUTE_READWRITE) newProtect = PAGE_EXECUTE_READ;
                else if (newProtect & PAGE_READWRITE) newProtect = PAGE_READONLY;
                else if (newProtect & PAGE_EXECUTE_READWRITE) newProtect = PAGE_EXECUTE_READ;
                else newProtect = PAGE_READONLY;
            }

            return VirtualProtect(addr, 1, newProtect, &oldProtect) != 0;
        #endif
    }

    bool make_readable(void* addr, bool readable) {
        #if defined(__linux__)
            uintptr_t page_size = sysconf(_SC_PAGESIZE);
            uintptr_t page_start = (uintptr_t)addr & ~(page_size - 1);

            int current_prot;
            if (!get_page_permissions(addr, current_prot)) return false;

            if (readable)
                current_prot |= PROT_READ;
            else
                current_prot &= ~PROT_READ;

            return mprotect((void*)page_start, page_size, current_prot) == 0;
        #elif defined(_WIN32)
            DWORD oldProtect;
            MEMORY_BASIC_INFORMATION mbi;

            if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;

            DWORD newProtect = mbi.Protect;

            if (readable) {
                if (newProtect & PAGE_EXECUTE) newProtect = PAGE_EXECUTE_READ;
                else if (newProtect == PAGE_NOACCESS) newProtect = PAGE_READONLY;
                else if (newProtect & PAGE_READWRITE) newProtect = PAGE_READWRITE; // already readable
                else if (newProtect & PAGE_EXECUTE_READWRITE) newProtect = PAGE_EXECUTE_READWRITE;
                else newProtect = PAGE_READONLY;
            } else {
                if (newProtect & PAGE_READWRITE) newProtect = PAGE_NOACCESS;
                else if (newProtect & PAGE_READONLY) newProtect = PAGE_NOACCESS;
                else if (newProtect & PAGE_EXECUTE_READWRITE) newProtect = PAGE_EXECUTE;
                else if (newProtect & PAGE_EXECUTE_READ) newProtect = PAGE_EXECUTE;
                else return false; // unsupported
            }

            return VirtualProtect(addr, 1, newProtect, &oldProtect) != 0;
        #endif
    }

    int address(lua_State* L) {
        if (lua::isstring(L, 1)) {
            std::string addr = luaL::checkcstring(L, 1);
            char* end;
            uintptr_t value = strtoull(addr.c_str(), &end, 16);
            if (*end != '\0') return 0;
            push_address(L, (void*)value);
            return 1;
        }
        else if (lua::iscfunction(L, 1)) {
            using namespace Engine;
            TValue* value = lua::toraw(L, 1);
            GCfunc* func = funcV(value);
            push_address(L, (void*)func->c.f);
            return 1;
        }
        else if (lua::islfunction(L, 1)) {
            using namespace Engine;
            TValue* value = lua::toraw(L, 1);
            GCproto* func = funcproto(funcV(value));
            push_address(L, (void*)func);
            return 1;
        }
        else if (lua::isuserdata(L, 1)) {
            using namespace Engine;
            void* udata = lua::touserdata(L, 1);
            push_address(L, (void*)udata);
            return 1;
        }
        else if (lua::iscdata(L, 1))
        {
            using namespace Engine;
            void* cdata = lua::tocdataptr(L, 1);
            push_address(L, (void*)cdata);
            return 1;
        }
        uintptr_t addr = luaL::checknumber(L, 1);
        push_address(L, (void*)addr);
        return 1;
    }

    int allocate(lua_State* L) {
        size_t size = luaL::checknumber(L, 1);
        push_address(L, malloc(sizeof(unsigned char) * size));
        return 1;
    }

    int modules(lua_State* L) {
        lua::newtable(L);

        int i = 1;
        #if defined(_WIN32)
            #ifdef _M_X64
                PPEB Peb = (PPEB)__readgsqword(0x60);
            #else
                PPEB Peb = (PPEB)__readfsdword(0x30);
            #endif
        
            PLIST_ENTRY ModuleListHead = &Peb->Ldr->InMemoryOrderModuleList;
            PLIST_ENTRY CurrentEntry = ModuleListHead->Flink;

            while (CurrentEntry != ModuleListHead) {
                T_LDR_DATA_TABLE_ENTRY* ModuleEntry = (T_LDR_DATA_TABLE_ENTRY*)((char*)CurrentEntry - offsetof(T_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks));
                std::string DllName = UnicodeStringToString(ModuleEntry->FullDllName);
                HMODULE hModule = GetModuleHandleA(DllName.c_str());

                if (hModule != 0 && hModule != nullptr) {
                    if (MODULEINFO moduleInfo; GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) {
                        lua::pushnumber(L, i++);
                        push_module(L, DllName, hModule, moduleInfo);
                        lua::settable(L, -3);
                    }
                }

                CurrentEntry = CurrentEntry->Flink;
            }
        #elif defined(__linux)
            std::ifstream maps("/proc/self/maps");
            std::unordered_set<std::string> seen;
            std::string line;

            while (std::getline(maps, line)) {
                std::istringstream iss(line);
                std::string addr_range, perms, offset, dev, inode, pathname;
                if (!(iss >> addr_range >> perms >> offset >> dev >> inode)) continue;
                if (iss >> pathname && pathname[0] != '/' || seen.count(pathname)) continue;

                seen.insert(pathname);
                void* module = dlopen(pathname.c_str(), RTLD_LAZY);
                if (!module) continue;
                dlclose(module);

                size_t dash = addr_range.find('-');
                if (dash == std::string::npos) continue;

                void* base;
                size_t size;
                base = (void*)std::stoul(addr_range.substr(0, dash), nullptr, 16);
                void* end = (void*)std::stoul(addr_range.substr(dash + 1), nullptr, 16);
                size = (size_t)end - (size_t)base;

                lua::pushnumber(L, i++);
                push_module(L, pathname, module, base, size);
                lua::settable(L, -3);
            }
        #endif

        return 1;
    }
    
    #ifdef _WIN32
        struct memory_region {
            uintptr_t base;
            size_t size;
            DWORD state;
            DWORD type;
            DWORD protect;
        };
    #else
        struct memory_region {
            uintptr_t base;
            size_t size;
            bool r, w, x, p;
            std::string path;
        };
    #endif

    int region__tostring(lua_State* L)
    {
        memory_region* _region = (memory_region*)Class::check(L, 1, "region");
        std::stringstream ss;
        ss << "region: 0x" << std::hex << _region->base;
        ss << " - 0x" << std::hex << (_region->base + _region->size);
        lua::pushcstring(L, ss.str());
        return 1;
    }

    #ifdef _WIN32
        int region__index(lua_State* L)
        {
            memory_region* _region = (memory_region*)Class::check(L, 1, "region");
            std::string index = luaL::checkcstring(L, 2);

            if (index == "base") {
                push_address(L, (void*)_region->base);
                return 1;
            }
            else if (index == "size") {
                lua::pushnumber(L, _region->size);
                return 1;
            }
            else if (index == "state") {
                if (_region->state & MEM_COMMIT) {
                    lua::pushstring(L, "commit");
                } else if (_region->state & MEM_FREE) {
                    lua::pushstring(L, "free");
                } else if (_region->state & MEM_RESERVE) {
                    lua::pushstring(L, "reserve");
                } else {
                    lua::pushnumber(L, _region->state);
                }
                return 1;
            }
            else if (index == "type") {
                if (_region->type == 0) {
                    lua::pushstring(L, "none");
                } else if (_region->type & MEM_IMAGE) {
                    lua::pushstring(L, "image");
                } else if (_region->type & MEM_MAPPED) {
                    lua::pushstring(L, "mapped");
                } else if (_region->type & MEM_PRIVATE) {
                    lua::pushstring(L, "private");
                } else {
                    lua::pushnumber(L, _region->type);
                }
                return 1;
            }
            else if (index == "protect") {
                int i = 1;
                lua::newtable(L);

                #define PUSH_PROT(flag, name)       \
                    if (_region->protect & flag) {  \
                        lua::pushnumber(L, i++);    \
                        lua::pushstring(L, name);   \
                        lua::settable(L, -3);       \
                                                    \
                        lua::pushstring(L, name);   \
                        lua::pushboolean(L, true);  \
                        lua::settable(L, -3);       \
                    }

                PUSH_PROT(PAGE_NOACCESS, "noaccess");
                PUSH_PROT(PAGE_READONLY, "readonly");
                PUSH_PROT(PAGE_READWRITE, "readwrite");
                PUSH_PROT(PAGE_WRITECOPY, "writecopy");
                PUSH_PROT(PAGE_EXECUTE, "execute");
                PUSH_PROT(PAGE_EXECUTE_READ, "execute_read");
                PUSH_PROT(PAGE_EXECUTE_READWRITE, "execute_readwrite");
                PUSH_PROT(PAGE_EXECUTE_WRITECOPY, "execute_writecopy");

                PUSH_PROT(PAGE_GUARD, "guard");
                PUSH_PROT(PAGE_NOCACHE, "nocache");
                PUSH_PROT(PAGE_WRITECOMBINE, "writecombine");
                return 1;
            }

            return 0;
        }
    #else
        int region__index(lua_State* L)
        {
            memory_region* _region = (memory_region*)Class::check(L, 1, "region");
            std::string index = luaL::checkcstring(L, 2);

            if (index == "base") {
                push_address(L, (void*)_region->base);
                return 1;
            }
            else if (index == "size") {
                lua::pushnumber(L, _region->size);
                return 1;
            }
            else if (index == "state") {
                lua::pushstring(L, "commit");
                return 1;
            }
            else if (index == "type") {
                if (_region->p) {
                    lua::pushstring(L, "private");
                } else {
                    lua::pushstring(L, "shared");
                }
                return 1;
            }
            else if (index == "protect") {
                int i = 1;
                lua::newtable(L);

                #define PUSH_PROT(flag, name)        \
                    if (flag) {                      \
                        lua::pushnumber(L, i++);     \
                        lua::pushstring(L, name);    \
                        lua::settable(L, -3);        \
                                                     \
                        lua::pushstring(L, name);    \
                        lua::pushboolean(L, true);   \
                        lua::settable(L, -3);        \
                    }
                
                PUSH_PROT(_region->r, "read");
                PUSH_PROT(_region->w, "write");
                PUSH_PROT(_region->x, "execute");
                return 1;
            }

            return 0;
        }
    #endif

    int region__gc(lua_State* L)
    {
        if (Class::is(L, 1, "region")) {
            delete (memory_region*)Class::to(L, 1);
        }
        return 0;
    }

    #ifdef _WIN32
        void push_region(lua_State* L, MEMORY_BASIC_INFORMATION& mbi)
        {
            memory_region* mem_region = new memory_region({
                (uintptr_t)mbi.BaseAddress,
                mbi.RegionSize,
                mbi.State,
                mbi.Type,
                mbi.Protect
            });

            if (!Class::existsbyname(L, "region")) {
                Class::create(L, "region");

                lua::pushcfunction(L, region__tostring);
                lua::setfield(L, -2, "__tostring");

                lua::pushcfunction(L, region__index);
                lua::setfield(L, -2, "__index");

                lua::pushcfunction(L, region__gc);
                lua::setfield(L, -2, "__gc");

                lua::pop(L);
            }

            Class::spawn(L, mem_region, "region");
        }
    #else
        void push_region(lua_State* L, memory_region& mbi)
        {
            memory_region* mem_region = new memory_region(mbi);

            if (!Class::existsbyname(L, "region")) {
                Class::create(L, "region");

                lua::pushcfunction(L, region__tostring);
                lua::setfield(L, -2, "__tostring");

                lua::pushcfunction(L, region__index);
                lua::setfield(L, -2, "__index");

                lua::pushcfunction(L, region__gc);
                lua::setfield(L, -2, "__gc");

                lua::pop(L);
            }

            Class::spawn(L, mem_region, "region");
        }
    #endif

    int regions(lua_State* L) {
        lua::newtable(L);
        int i = 1;

        #ifdef _WIN32
            MEMORY_BASIC_INFORMATION mbi;
            LPVOID addr = 0;
            HANDLE hProcess = GetCurrentProcess();
            while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                addr = (LPBYTE)addr + mbi.RegionSize;
                lua::pushnumber(L, i++);
                push_region(L, mbi);
                lua::settable(L, -3);
            }
        #else
            std::ifstream maps("/proc/self/maps");
            std::string line;

            while (std::getline(maps, line)) {
                std::istringstream iss(line);
                std::string addr, perms, offset, dev, inode, pathname;

                iss >> addr >> perms >> offset >> dev >> inode;
                std::getline(iss, pathname);
                if (!pathname.empty() && pathname[0] == ' ')
                    pathname.erase(0, 1);

                memory_region region{};

                uintptr_t start, end;
                sscanf(addr.c_str(), "%lx-%lx", &start, &end);
                region.base = start;
                region.size = end - start;
                region.r = perms[0] == 'r';
                region.w = perms[1] == 'w';
                region.x = perms[2] == 'x';
                region.p = perms[3] == 'p';
                region.path = pathname;

                lua::pushnumber(L, i++);
                push_region(L, region);
                lua::settable(L, -3);
            }
        #endif

        return 1;
    }

    int region(lua_State* L) {
        uintptr_t address = (uintptr_t)Class::check(L, 1, "address");

        #ifdef _WIN32
            MEMORY_BASIC_INFORMATION mbi;
            LPVOID addr = 0;
            HANDLE hProcess = GetCurrentProcess();
            while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                addr = (LPBYTE)addr + mbi.RegionSize;
                
                if ((uintptr_t)mbi.BaseAddress <= address && (uintptr_t)addr >= address) {
                    push_region(L, mbi);
                    return 1;
                }
            }
        #else
            std::ifstream maps("/proc/self/maps");
            std::string line;

            while (std::getline(maps, line)) {
                std::istringstream iss(line);
                std::string addr, perms, offset, dev, inode, pathname;

                iss >> addr >> perms >> offset >> dev >> inode;
                std::getline(iss, pathname);
                if (!pathname.empty() && pathname[0] == ' ')
                    pathname.erase(0, 1);

                uintptr_t start, end;
                sscanf(addr.c_str(), "%lx-%lx", &start, &end);

                if (start <= address && end >= address) {
                    memory_region region{};
                    region.base = start;
                    region.size = end - start;
                    region.r = perms[0] == 'r';
                    region.w = perms[1] == 'w';
                    region.x = perms[2] == 'x';
                    region.p = perms[3] == 'p';
                    region.path = pathname;
                    push_region(L, region);
                    return 1;
                }
            }
        #endif

        return 0;
    }

    bool ends_with(const std::string& str, const std::string& suffix) {
        if (str.length() < suffix.length()) return false;
        return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
    }
    
    int module(lua_State* L) {
        if (!lua::isstring(L, 1)) {
            #if defined(_WIN32)
                #ifdef _M_X64
                    PPEB Peb = (PPEB)__readgsqword(0x60);
                #else
                    PPEB Peb = (PPEB)__readfsdword(0x30);
                #endif
        
                PLIST_ENTRY ModuleListHead = &Peb->Ldr->InMemoryOrderModuleList;
                PLIST_ENTRY CurrentEntry = ModuleListHead->Flink;

                while (CurrentEntry != ModuleListHead) {
                    T_LDR_DATA_TABLE_ENTRY* ModuleEntry = (T_LDR_DATA_TABLE_ENTRY*)((char*)CurrentEntry - offsetof(T_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks));
                    std::string DllName = UnicodeStringToString(ModuleEntry->FullDllName);
                    HMODULE hModule = GetModuleHandleA(DllName.c_str());

                    if (hModule != 0 && hModule != nullptr) {
                        if (MODULEINFO moduleInfo; GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) {
                            push_module(L, DllName, hModule, moduleInfo);
                            return 1;
                        }
                    }

                    CurrentEntry = CurrentEntry->Flink;
                }
            #elif defined(__linux)
                std::ifstream maps("/proc/self/maps");
                std::unordered_set<std::string> seen;
                std::string line;

                while (std::getline(maps, line)) {
                    std::istringstream iss(line);
                    std::string addr_range, perms, offset, dev, inode, pathname;
                    if (!(iss >> addr_range >> perms >> offset >> dev >> inode)) continue;
                    if (iss >> pathname && pathname[0] != '/' || seen.count(pathname)) continue;

                    seen.insert(pathname);
                    void* hmodule = dlopen(pathname.c_str(), RTLD_LAZY);
                    if (!hmodule) continue;
                    dlclose(hmodule);

                    size_t dash = addr_range.find('-');
                    if (dash == std::string::npos) continue;

                    void* base;
                    size_t size;
                    base = (void*)std::stoul(addr_range.substr(0, dash), nullptr, 16);
                    void* end = (void*)std::stoul(addr_range.substr(dash + 1), nullptr, 16);
                    size = (size_t)end - (size_t)base;

                    push_module(L, pathname, hmodule, base, size);
                    return 1;
                }
            #endif
            return 0;
        }

        std::string module = lua::tocstring(L, 1);

        #if defined(_WIN32)
            HMODULE hModule = GetModuleHandleA(module.c_str());
            if (!hModule) return 0;

            MODULEINFO moduleInfo;
            if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) return 0;

            push_module(L, module, hModule, moduleInfo);

            return 1;
        #elif defined(__linux)
            std::ifstream maps("/proc/self/maps");
            std::unordered_set<std::string> seen;
            std::string line;

            while (std::getline(maps, line)) {
                std::istringstream iss(line);
                std::string addr_range, perms, offset, dev, inode, pathname;
                if (!(iss >> addr_range >> perms >> offset >> dev >> inode)) continue;
                if (iss >> pathname && pathname[0] != '/' || seen.count(pathname)) continue;

                seen.insert(pathname);

                if (!ends_with(pathname, module)) continue;

                void* hmodule = dlopen(pathname.c_str(), RTLD_LAZY);
                if (!hmodule) continue;
                dlclose(hmodule);

                size_t dash = addr_range.find('-');
                if (dash == std::string::npos) continue;

                void* base;
                size_t size;
                base = (void*)std::stoul(addr_range.substr(0, dash), nullptr, 16);
                void* end = (void*)std::stoul(addr_range.substr(dash + 1), nullptr, 16);
                size = (size_t)end - (size_t)base;

                push_module(L, pathname, hmodule, base, size);
                return 1;
            }
        #endif

        return 0;
    }

    int base(lua_State* L) {
        void* address = Class::check(L, 1, "address");

        #if defined(_WIN32)
            #ifdef _M_X64
                PPEB Peb = (PPEB)__readgsqword(0x60);
            #else
                PPEB Peb = (PPEB)__readfsdword(0x30);
            #endif
        
            PLIST_ENTRY ModuleListHead = &Peb->Ldr->InMemoryOrderModuleList;
            PLIST_ENTRY CurrentEntry = ModuleListHead->Flink;

            while (CurrentEntry != ModuleListHead) {
                T_LDR_DATA_TABLE_ENTRY* ModuleEntry = (T_LDR_DATA_TABLE_ENTRY*)((char*)CurrentEntry - offsetof(T_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks));
                std::string DllName = UnicodeStringToString(ModuleEntry->FullDllName);
                HMODULE hModule = GetModuleHandleA(DllName.c_str());

                if (hModule != 0 && hModule != nullptr) {
                    if (MODULEINFO moduleInfo; GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) {
                        if (address >= moduleInfo.lpBaseOfDll && address < (PBYTE)moduleInfo.lpBaseOfDll + moduleInfo.SizeOfImage) {
                            push_module(L, DllName, hModule, moduleInfo);
                            return 1;
                        }
                    }
                }

                CurrentEntry = CurrentEntry->Flink;
            }
        #elif defined(__linux)
            std::ifstream maps("/proc/self/maps");
            std::unordered_set<std::string> seen;
            std::string line;

            while (std::getline(maps, line)) {
                std::istringstream iss(line);
                std::string addr_range, perms, offset, dev, inode, pathname;
                if (!(iss >> addr_range >> perms >> offset >> dev >> inode)) continue;
                if (iss >> pathname && pathname[0] != '/' || seen.count(pathname)) continue;

                seen.insert(pathname);

                void* hmodule = dlopen(pathname.c_str(), RTLD_LAZY);
                if (!hmodule) continue;
                dlclose(hmodule);

                size_t dash = addr_range.find('-');
                if (dash == std::string::npos) continue;

                void* base;
                size_t size;
                base = (void*)std::stoul(addr_range.substr(0, dash), nullptr, 16);
                void* end = (void*)std::stoul(addr_range.substr(dash + 1), nullptr, 16);
                size = (size_t)end - (size_t)base;

                if ((uintptr_t)address >= (uintptr_t)base && (uintptr_t)address < (uintptr_t)base + size) {
                    push_module(L, pathname, hmodule, base, size);
                    return 1;
                }
            }
        #endif

        return 0;
    }

    int fetch(lua_State* L) {
        void* address = check_module(L, 1);
        if (address == nullptr) return 0;

        #if defined(_WIN32)
            HMODULE handle = (HMODULE)address;
            std::string proc_ = luaL::checkcstring(L, 2);
            void* addr_ = (void*)GetProcAddress(handle, proc_.c_str());
            if (!addr_)
                return 0;
        #elif defined(__linux)
            void* handle = (void*)address;
            std::string proc_ = luaL::checkcstring(L, 2);
            void* addr_ = (void*)dlsym(handle, proc_.c_str());
            if (!addr_) {
                dlclose(handle);
                return 0;
            }
            dlclose(handle);
        #endif

        push_address(L, addr_);

        return 1;
    }

    int vtable(lua_State* L) {
        void* address = Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(void*))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        void** vtable_ptr = *reinterpret_cast<void***>(address);

        if (!is_valid_read(vtable_ptr, sizeof(void*))) {
            return luaL::error(L, "invalid vtable pointer at address %p", vtable_ptr);
        }

        push_address(L, vtable_ptr);
        return 1;
    }

    int index(lua_State* L) {
        void* address = Class::check(L, 1, "address");
        uintptr_t index = luaL::checknumber(L, 2);

        if (!is_valid_read(address, sizeof(void*))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        push_address(L, reinterpret_cast<void**>(address)[index]);
        return 1;
    }

    typedef void* (*CreateInterface_fn)(const char* name, int* returncode);
    int _interface(lua_State* L) {
        void* address = check_module(L, 1);
        if (address == nullptr) return 0;
        std::string name = luaL::checkcstring(L, 2);

        #if defined(_WIN32)
            HMODULE handle = (HMODULE)address;
            static CreateInterface_fn CreateInterface = (CreateInterface_fn)GetProcAddress(handle, "CreateInterface");

            if (!CreateInterface)
                return 0;

            void* object = CreateInterface(name.c_str(), 0);
        #elif defined(__linux)
            void* handle = (void*)address;

            CreateInterface_fn CreateInterface = (CreateInterface_fn)dlsym(handle, "CreateInterface");
            if (!CreateInterface) {
                dlclose(handle);
                return 0;
            }

            void* object = CreateInterface(name.c_str(), 0);

            dlclose(handle);
        #endif

        push_address(L, object);

        return 1;
    }

    int offset(lua_State* L) {
        char* handle = (char*)Class::check(L, 1, "address");
        int offset = luaL::checknumber(L, 2);
        push_address(L, (void*)(handle + offset));
        return 1;
    }

    int relative(lua_State* L) {
        char* address = (char*)Class::check(L, 1, "address");
        int offset = luaL::checknumber(L, 2);
        int instruction_size = luaL::checknumber(L, 3);
        char* instruction = address + offset;
        int relative_address = *(int*)(instruction);
        char* solved_address = address + instruction_size + relative_address;
        push_address(L, (void*)(solved_address));
        return 1;
    }

    int aob_hex(lua_State* L) {
        void* address = check_module(L, 1);
        if (address == nullptr) return 0;
        std::string pattern = luaL::checkcstring(L, 2);
        char* result = scan_hex(address, pattern);
        if (result == nullptr) {
            return 0;
        }
        push_address(L, (void*)result);
        return 1;
    }

    int aob_ida(lua_State* L) {
        void* address = check_module(L, 1);
        if (address == nullptr) return 0;
        std::string pattern = luaL::checkcstring(L, 2);
        char* result = scan_ida(address, pattern);
        if (result == nullptr) {
            return 0;
        }
        push_address(L, (void*)result);
        return 1;
    }

    inline void scan_get_size(lua_State* L, uintptr_t& base, size_t& size)
    {
        if (Class::is(L, 2, "region")) {
            memory_region* region = (memory_region*)Class::to(L, 2);
            base = region->base;
            size = region->size;
        }
        else if (Class::is(L, 2, "module")) {
            memory_module* module = (memory_module*)Class::to(L, 2);
            base = module->base;
            size = module->size;
        }
        else if (Class::is(L, 2, "address")) {
            base = (uintptr_t)Class::to(L, 2);
            uintptr_t end = (uintptr_t)Class::check(L, 3, "address");
            if (end < base) {
                luaL::argerror(L, 3, "address is smaller than the base address.");
            }
            size = end - base;
        }
        else {
            base = 0;
            size = 0;
        }
    }

    template<typename T>
    inline void scan_process(lua_State* L, uintptr_t base, size_t size, T value) {
        lua::newtable(L);
        int idx = 1;

        if (base == 0 && size == 0) {
            #ifdef _WIN32
                MEMORY_BASIC_INFORMATION mbi;
                LPVOID addr = 0;
                HANDLE hProcess = GetCurrentProcess();
                while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                    addr = (LPBYTE)addr + mbi.RegionSize;
                       
                    DWORD protect = mbi.Protect;
                    bool can_read = (protect & PAGE_READONLY) || (protect & PAGE_READWRITE) || (protect & PAGE_EXECUTE_READ) || (protect & PAGE_EXECUTE_READWRITE);
                    bool can_access = !(protect & PAGE_GUARD || protect & PAGE_NOACCESS);

                    uintptr_t base = (uintptr_t)mbi.BaseAddress;
                    size_t size = mbi.RegionSize;

                    if (can_access && can_read) {
                        for (uintptr_t i = 0; i < size; i = i + sizeof(T)) {
                            char* address = (char*)(base + i);
                            if (*(T*)address == value) {
                                lua::pushnumber(L, idx++);
                                push_address(L, address);
                                lua::settable(L, -3);
                            }
                        }
                    };
                }
            #else
                std::ifstream maps("/proc/self/maps");
                std::string line;

                while (std::getline(maps, line)) {
                    std::istringstream iss(line);
                    std::string addr, perms, offset, dev, inode, pathname;

                    iss >> addr >> perms >> offset >> dev >> inode;
                    std::getline(iss, pathname);
                    if (!pathname.empty() && pathname[0] == ' ')
                        pathname.erase(0, 1);

                    memory_region region{};

                    uintptr_t start, end;
                    sscanf(addr.c_str(), "%lx-%lx", &start, &end);
                    
                    if (perms[0] == 'r') {
                        for (uintptr_t address = start; address < end; address = address + sizeof(T)) {
                            if (*(T*)address == value) {
                                lua::pushnumber(L, idx++);
                                push_address(L, (void*)address);
                                lua::settable(L, -3);
                            }
                        }
                    }
                }
            #endif
        }
        else {
            for (uintptr_t i = 0; i < size; i = i + sizeof(T)) {
                char* address = (char*)(base + i);
                if (!is_valid_read(address, sizeof(T))) {
                    continue;
                }
                if (*(T*)address == value) {
                    lua::pushnumber(L, idx++);
                    push_address(L, address);
                    lua::settable(L, -3);
                }
            }
        }
    }

    int scan_bool(lua_State* L) {
        bool value = luaL::checkboolean(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_char(lua_State* L) {
        char value = luaL::checknumber(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_uchar(lua_State* L) {
        unsigned char value = luaL::checknumber(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_short(lua_State* L) {
        short value = luaL::checknumber(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_ushort(lua_State* L) {
        unsigned short value = luaL::checknumber(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_int(lua_State* L) {
        int value = luaL::checknumber(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_uint(lua_State* L) {
        unsigned int value = luaL::checknumber(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_long(lua_State* L) {
        long value = luaL::checknumber(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_ulong(lua_State* L) {
        unsigned long value = luaL::checknumber(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_float(lua_State* L) {
        float value = luaL::checknumber(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_double(lua_State* L) {
        double value = luaL::checknumber(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_address(lua_State* L) {
        char* value = (char*)Class::check(L, 1, "address");
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, (uintptr_t)value);
        return 1;
    }

    int read_bool(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(bool))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushboolean(L, *(bool*)address);
        return 1;
    }

    int read_char(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(char))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(char*)address);
        return 1;
    }

    int read_uchar(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(unsigned char))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(unsigned char*)address);
        return 1;
    }

    int read_short(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(short))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(short*)address);
        return 1;
    }

    int read_ushort(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(unsigned short))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(unsigned short*)address);
        return 1;
    }

    int read_int(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(int))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(int*)address);
        return 1;
    }

    int read_uint(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(unsigned int))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(unsigned int*)address);
        return 1;
    }

    int read_long(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(long))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(long*)address);
        return 1;
    }

    int read_ulong(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(unsigned long))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(unsigned long*)address);
        return 1;
    }

    int read_float(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(float))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(float*)address);
        return 1;
    }

    int read_double(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(double))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(double*)address);
        return 1;
    }

    int read_sequence(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");
        unsigned int size = luaL::checknumber(L, 2);

        if (!is_valid_read(address, sizeof(unsigned char) * size)) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        char* buffer = new char[size];
        memcpy(buffer, address, size);

        std::stringstream hexStream;
        for (unsigned int i = 0; i < size; ++i) {
            hexStream << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(static_cast<unsigned char>(buffer[i]))
                << " ";
        }

        std::string hex_string = hexStream.str();
        lua::pushcstring(L, hex_string);
        delete[] buffer;

        return 1;
    }

    int read_address(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(void*))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        push_address(L, *(void**)address);
        return 1;
    }

    int write_bool(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(bool))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        *(bool*)address = luaL::checkboolean(L, 2);
        return 0;
    }

    int write_char(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(char))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        bool writeable = is_writable(address);

        if (!writeable) {
            if (!make_writeable(address, true)) {
                return luaL::error(L, "failed to change page protection rules on %p", (void*)address);
            }
        }

        *(char*)address = luaL::checknumber(L, 2);

        if (!writeable) {
            if (!make_writeable(address, false)) {
                return luaL::error(L, "failed to restore page protection rules on %p", (void*)address);
            }
        }
        
        return 0;
    }

    int write_uchar(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(unsigned char))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        bool writeable = is_writable(address);

        if (!writeable) {
            if (!make_writeable(address, true)) {
                return luaL::error(L, "failed to change page protection rules on %p", (void*)address);
            }
        }

        *(unsigned char*)address = (unsigned char)luaL::checknumber(L, 2);

        if (!writeable) {
            if (!make_writeable(address, false)) {
                return luaL::error(L, "failed to restore page protection rules on %p", (void*)address);
            }
        }
        
        return 0;
    }

    int write_short(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(short))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        bool writeable = is_writable(address);

        if (!writeable) {
            if (!make_writeable(address, true)) {
                return luaL::error(L, "failed to change page protection rules on %p", (void*)address);
            }
        }

        *(short*)address = luaL::checknumber(L, 2);

        if (!writeable) {
            if (!make_writeable(address, false)) {
                return luaL::error(L, "failed to restore page protection rules on %p", (void*)address);
            }
        }

        return 0;
    }

    int write_ushort(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(unsigned short))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        bool writeable = is_writable(address);

        if (!writeable) {
            if (!make_writeable(address, true)) {
                return luaL::error(L, "failed to change page protection rules on %p", (void*)address);
            }
        }

        *(unsigned short*)address = (unsigned short)luaL::checknumber(L, 2);

        if (!writeable) {
            if (!make_writeable(address, false)) {
                return luaL::error(L, "failed to restore page protection rules on %p", (void*)address);
            }
        }

        return 0;
    }

    int write_int(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(int))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        bool writeable = is_writable(address);

        if (!writeable) {
            if (!make_writeable(address, true)) {
                return luaL::error(L, "failed to change page protection rules on %p", (void*)address);
            }
        }

        *(int*)address = luaL::checknumber(L, 2);

        if (!writeable) {
            if (!make_writeable(address, false)) {
                return luaL::error(L, "failed to restore page protection rules on %p", (void*)address);
            }
        }

        return 0;
    }

    int write_uint(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(unsigned int))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        bool writeable = is_writable(address);

        if (!writeable) {
            if (!make_writeable(address, true)) {
                return luaL::error(L, "failed to change page protection rules on %p", (void*)address);
            }
        }

        *(unsigned int*)address = luaL::checknumber(L, 2);

        if (!writeable) {
            if (!make_writeable(address, false)) {
                return luaL::error(L, "failed to restore page protection rules on %p", (void*)address);
            }
        }

        return 0;
    }

    int write_long(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(long))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        bool writeable = is_writable(address);

        if (!writeable) {
            if (!make_writeable(address, true)) {
                return luaL::error(L, "failed to change page protection rules on %p", (void*)address);
            }
        }

        *(long*)address = luaL::checknumber(L, 2);

        if (!writeable) {
            if (!make_writeable(address, false)) {
                return luaL::error(L, "failed to restore page protection rules on %p", (void*)address);
            }
        }

        return 0;
    }

    int write_ulong(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(unsigned long))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        bool writeable = is_writable(address);

        if (!writeable) {
            if (!make_writeable(address, true)) {
                return luaL::error(L, "failed to change page protection rules on %p", (void*)address);
            }
        }

        *(unsigned long*)address = (unsigned long)luaL::checknumber(L, 2);

        if (!writeable) {
            if (!make_writeable(address, false)) {
                return luaL::error(L, "failed to restore page protection rules on %p", (void*)address);
            }
        }

        return 0;
    }

    int write_float(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(float))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        bool writeable = is_writable(address);

        if (!writeable) {
            if (!make_writeable(address, true)) {
                return luaL::error(L, "failed to change page protection rules on %p", (void*)address);
            }
        }

        *(float*)address = luaL::checknumber(L, 2);

        if (!writeable) {
            if (!make_writeable(address, false)) {
                return luaL::error(L, "failed to restore page protection rules on %p", (void*)address);
            }
        }

        return 0;
    }

    int write_double(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(double))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        bool writeable = is_writable(address);

        if (!writeable) {
            if (!make_writeable(address, true)) {
                return luaL::error(L, "failed to change page protection rules on %p", (void*)address);
            }
        }

        *(double*)address = luaL::checknumber(L, 2);

        if (!writeable) {
            if (!make_writeable(address, false)) {
                return luaL::error(L, "failed to restore page protection rules on %p", (void*)address);
            }
        }

        return 0;
    }

    int write_sequence(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");
        std::string hex_string = luaL::checkcstring(L, 2);

        std::string filtered;
        for (char ch : std::string(hex_string)) {
            if (!std::isspace(static_cast<unsigned char>(ch))) {
                filtered += ch;
            }
        }

        if (filtered.size() % 2 != 0) {
            return luaL::error(L, "invalid hex string: odd number of digits");
        }

        for (char ch : filtered) {
            if (!std::isxdigit(static_cast<unsigned char>(ch))) {
                return luaL::error(L, "invalid hex string: '%s'", filtered.c_str());
            }
        }

        if (!is_valid_write(address, sizeof(unsigned char) * (filtered.size() / 2))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        bool writeable = is_writable(address);

        if (!writeable) {
            if (!make_writeable(address, true)) {
                return luaL::error(L, "failed to change page protection rules on %p", (void*)address);
            }
        }

        for (unsigned int i = 0; i < (filtered.size() / 2); ++i) {
            std::string byte_str = filtered.substr(i * 2, 2);
            unsigned char byte_val = static_cast<unsigned char>(std::stoul(byte_str, nullptr, 16));
            address[i] = byte_val;
        }

        if (!writeable) {
            if (!make_writeable(address, false)) {
                return luaL::error(L, "failed to restore page protection rules on %p", (void*)address);
            }
        }

        return 0;
    }

    int write_address(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(void*))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        bool writeable = is_writable(address);

        if (!writeable) {
            if (!make_writeable(address, true)) {
                return luaL::error(L, "failed to change page protection rules on %p", (void*)address);
            }
        }

        char* data = (char*)Class::check(L, 2, "address");
        *(char**)address = data;

        if (!writeable) {
            if (!make_writeable(address, false)) {
                return luaL::error(L, "failed to restore page protection rules on %p", (void*)address);
            }
        }

        return 0;
    }

    inline void* subroutine_boundary(lua_State* L, uintptr_t a, uintptr_t b, size_t& actual_size) {
        uintptr_t start_addr = a < b ? a : b;
        uintptr_t end_addr = a < b ? b : a;
        size_t full_size = end_addr - start_addr;

        unsigned char* raw = (unsigned char*)start_addr;

        size_t offset_start = 0;
        while (offset_start < full_size && raw[offset_start] == 0x00) {
            offset_start++;
        }

        size_t offset_end = full_size;
        while (offset_end > offset_start && raw[offset_end - 1] == 0x00) {
            offset_end--;
        }

        actual_size = offset_end - offset_start;
        void* clone = malloc(actual_size);
        if (!clone) {
            luaL::error(L, "out of memory");
            return nullptr;
        }

        #if defined(__linux__)
            uintptr_t page_size = sysconf(_SC_PAGESIZE);
            uintptr_t page_start = (uintptr_t)clone & ~(page_size - 1);

            int current_prot;
            if (!get_page_permissions(clone, current_prot)) {
                luaL::error(L, "failed to assign execution permissions");
                return nullptr;
            };

            current_prot |= PROT_EXEC;
            current_prot |= PROT_READ;
            current_prot |= PROT_WRITE;

            if (mprotect((void*)page_start, page_size, current_prot) != 0) {
                luaL::error(L, "failed to assign execution permissions");
                return nullptr;
            }
        #elif defined(_WIN32)
            DWORD oldProt;
            if (!VirtualProtect(clone, actual_size, PAGE_EXECUTE_READWRITE, &oldProt)) {
                luaL::error(L, "failed to assign execution permissions");
                return nullptr;
            }
        #endif

        memcpy(clone, raw + offset_start, actual_size);
        
        #if defined(__linux__) && (defined(__i386__) || defined(_M_IX86))
            // x86 specific: remove stopid PIC thunk E8 ?? ?? ?? ?? 05 ?? ?? ?? ??
            unsigned char* buffer = (unsigned char*)clone;
            for (size_t i = 0; i + 9 < actual_size;) {
                if (buffer[i] == 0xE8 && buffer[i + 5] == 0x05) {
                    memmove(buffer + i, buffer + i + 10, actual_size - (i + 10));
                    actual_size -= 10;
                    break;
                } else {
                    i++;
                }
            }
        #endif

        return clone;
    }
    
    BEGIN_NOOPT // blank
    #pragma section(".subroutine_blank_routine$a", read, execute)
    #pragma section(".subroutine_blank_routine$b", read, execute)
    #pragma section(".subroutine_blank_routine$c", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(allocate(".subroutine_blank_routine$a")) unsigned char subroutine_blank_start_marker = 0;
            __declspec(code_seg(".subroutine_blank_routine$b"), noinline) void subroutine_blank_routine() {}
            __declspec(allocate(".subroutine_blank_routine$c")) unsigned char subroutine_blank_end_marker = 0;
        #else
            __attribute__((section(".subroutine_blank_routine$a"), noinline, used)) void subroutine_blank_start_marker() {}
            __attribute__((section(".subroutine_blank_routine$b"), noinline, used)) void subroutine_blank_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_blank(lua_State* L) {
        size_t size;
        char* ptr = (char*)subroutine_boundary(L, (uintptr_t)&subroutine_blank_start_marker, (uintptr_t)&subroutine_blank_end_marker, size);
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    BEGIN_NOOPT // bool
    #pragma section(".subroutine_bool_routine$a", read, execute)
    #pragma section(".subroutine_bool_routine$b", read, execute)
    #pragma section(".subroutine_bool_routine$c", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(allocate(".subroutine_bool_routine$a")) unsigned char subroutine_bool_start_marker = 0;
            __declspec(code_seg(".subroutine_bool_routine$b"), noinline) bool subroutine_bool_routine() { return true; }
            __declspec(allocate(".subroutine_bool_routine$c")) unsigned char subroutine_bool_end_marker = 0;
        #else
            __attribute__((section(".subroutine_bool_routine$a"), noinline, used)) bool subroutine_bool_start_marker() { return true; }
            __attribute__((section(".subroutine_bool_routine$b"), noinline, used)) void subroutine_bool_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_bool(lua_State* L) {
        bool value = luaL::checkboolean(L, 1);
        size_t size;
        char* ptr = (char*)subroutine_boundary(L, (uintptr_t)&subroutine_bool_start_marker, (uintptr_t)&subroutine_bool_end_marker, size);
        for (size_t i = 0; i < size; i++) {
            if (ptr[i] == 0x01) {
                *reinterpret_cast<bool*>(ptr + i) = value;
                break;
            }
        }
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    BEGIN_NOOPT // char
    #pragma section(".subroutine_char_routine$a", read, execute)
    #pragma section(".subroutine_char_routine$b", read, execute)
    #pragma section(".subroutine_char_routine$c", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(allocate(".subroutine_char_routine$a")) unsigned char subroutine_char_start_marker = 0;
            __declspec(code_seg(".subroutine_char_routine$b"), noinline) char subroutine_char_routine() { return 0xFF; }
            __declspec(allocate(".subroutine_char_routine$c")) unsigned char subroutine_char_end_marker = 0;
        #else
            __attribute__((section(".subroutine_char_routine$a"), noinline, used)) char subroutine_char_start_marker() { return 0xFF; }
            __attribute__((section(".subroutine_char_routine$b"), noinline, used)) void subroutine_char_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_char(lua_State* L) {
        char value = luaL::checkinteger(L, 1);
        size_t size;
        char* ptr = (char*)subroutine_boundary(L, (uintptr_t)&subroutine_char_start_marker, (uintptr_t)&subroutine_char_end_marker, size);
        for (size_t i = 0; i < size; i++) {
            if (ptr[i] == 0xFF) {
                *reinterpret_cast<char*>(ptr + i) = value;
                break;
            }
        }
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    BEGIN_NOOPT // unsigned char
    #pragma section(".subroutine_uchar_routine$a", read, execute)
    #pragma section(".subroutine_uchar_routine$b", read, execute)
    #pragma section(".subroutine_uchar_routine$c", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(allocate(".subroutine_uchar_routine$a")) unsigned char subroutine_uchar_start_marker = 0;
            __declspec(code_seg(".subroutine_uchar_routine$b"), noinline) unsigned char subroutine_uchar_routine() { return 0xFF; }
            __declspec(allocate(".subroutine_uchar_routine$c")) unsigned char subroutine_uchar_end_marker = 0;
        #else
            __attribute__((section(".subroutine_uchar_routine$a"), noinline, used)) unsigned char subroutine_uchar_start_marker() { return 0xFF; }
            __attribute__((section(".subroutine_uchar_routine$b"), noinline, used)) void subroutine_uchar_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_uchar(lua_State* L) {
        unsigned char value = luaL::checkinteger(L, 1);
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_uchar_start_marker, (uintptr_t)&subroutine_uchar_end_marker, size);
        for (size_t i = 0; i < size; i++) {
            if (ptr[i] == 0xFF) {
                *reinterpret_cast<unsigned char*>(ptr + i) = value;
                break;
            }
        }
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    BEGIN_NOOPT // short
    #pragma section(".subroutine_short_routine$a", read, execute)
    #pragma section(".subroutine_short_routine$b", read, execute)
    #pragma section(".subroutine_short_routine$c", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(allocate(".subroutine_short_routine$a")) unsigned char subroutine_short_start_marker = 0;
            __declspec(code_seg(".subroutine_short_routine$b"), noinline) short subroutine_short_routine() { return 0xFFFF; }
            __declspec(allocate(".subroutine_short_routine$c")) unsigned char subroutine_short_end_marker = 0;
        #else
            __attribute__((section(".subroutine_short_routine$a"), noinline, used)) short subroutine_short_start_marker() { return 0xFFFF; }
            __attribute__((section(".subroutine_short_routine$b"), noinline, used)) void subroutine_short_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_short(lua_State* L) {
        short value = luaL::checkinteger(L, 1);
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_short_start_marker, (uintptr_t)&subroutine_short_end_marker, size);
        for (size_t i = 0; i+1 < size; i++) {
            if (ptr[i + 1] == 0xFF && ptr[i] == 0xFF) {
                *reinterpret_cast<short*>(ptr + i) = value;
                break;
            }
        }
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    BEGIN_NOOPT // unsigned short
    #pragma section(".subroutine_ushort_routine$a", read, execute)
    #pragma section(".subroutine_ushort_routine$b", read, execute)
    #pragma section(".subroutine_ushort_routine$c", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(allocate(".subroutine_ushort_routine$a")) unsigned char subroutine_ushort_start_marker = 0;
            __declspec(code_seg(".subroutine_ushort_routine$b"), noinline) unsigned short subroutine_ushort_routine() { return 0xFFFF; }
            __declspec(allocate(".subroutine_ushort_routine$c")) unsigned char subroutine_ushort_end_marker = 0;
        #else
            __attribute__((section(".subroutine_ushort_routine$a"), noinline, used)) unsigned short subroutine_ushort_start_marker() { return 0xFFFF; }
            __attribute__((section(".subroutine_ushort_routine$b"), noinline, used)) void subroutine_ushort_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_ushort(lua_State* L) {
        unsigned short value = luaL::checkinteger(L, 1);
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_ushort_start_marker, (uintptr_t)&subroutine_ushort_end_marker, size);
        for (size_t i = 0; i + 1 < size; i++) {
            if (ptr[i + 1] == 0xFF && ptr[i] == 0xFF) {
                *reinterpret_cast<unsigned short*>(ptr + i) = value;
                break;
            }
        }
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    BEGIN_NOOPT // int
    #pragma section(".subroutine_int_routine$a", read, execute)
    #pragma section(".subroutine_int_routine$b", read, execute)
    #pragma section(".subroutine_int_routine$c", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(allocate(".subroutine_int_routine$a")) unsigned char subroutine_int_start_marker = 0;
            __declspec(code_seg(".subroutine_int_routine$b"), noinline) int subroutine_int_routine() { return 0xA1B2C3D4; }
            __declspec(allocate(".subroutine_int_routine$c")) unsigned char subroutine_int_end_marker = 0;
        #else
            __attribute__((section(".subroutine_int_routine$a"), noinline, used)) int subroutine_int_start_marker() { return 0xA1B2C3D4; }
            __attribute__((section(".subroutine_int_routine$b"), noinline, used)) void subroutine_int_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_int(lua_State* L) {
        int value = luaL::checkinteger(L, 1);
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_int_start_marker, (uintptr_t)&subroutine_int_end_marker, size);
        for (size_t i = 0; i + 3 < size; i++) {
            if (ptr[i + 3] == 0xA1 && ptr[i + 2] == 0xB2 && ptr[i + 1] == 0xC3 && ptr[i] == 0xD4) {
                *reinterpret_cast<int*>(ptr + i) = value;
                break;
            }
        }
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    BEGIN_NOOPT // unsigned int
    #pragma section(".subroutine_uint_routine$a", read, execute)
    #pragma section(".subroutine_uint_routine$b", read, execute)
    #pragma section(".subroutine_uint_routine$c", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(allocate(".subroutine_uint_routine$a")) unsigned char subroutine_uint_start_marker = 0;
            __declspec(code_seg(".subroutine_uint_routine$b"), noinline) unsigned int subroutine_uint_routine() { return 0xA1B2C3D4; }
            __declspec(allocate(".subroutine_uint_routine$c")) unsigned char subroutine_uint_end_marker = 0;
        #else
            __attribute__((section(".subroutine_uint_routine$a"), noinline, used)) unsigned int subroutine_uint_start_marker() { return 0xA1B2C3D4; }
            __attribute__((section(".subroutine_uint_routine$b"), noinline, used)) void subroutine_uint_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_uint(lua_State* L) {
        unsigned int value = luaL::checkinteger(L, 1);
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_uint_start_marker, (uintptr_t)&subroutine_uint_end_marker, size);
        for (size_t i = 0; i + 3 < size; i++) {
            if (ptr[i + 3] == 0xA1 && ptr[i + 2] == 0xB2 && ptr[i + 1] == 0xC3 && ptr[i] == 0xD4) {
                *reinterpret_cast<unsigned int*>(ptr + i) = value;
                break;
            }
        }
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    BEGIN_NOOPT // long
    #pragma section(".subroutine_long_routine$a", read, execute)
    #pragma section(".subroutine_long_routine$b", read, execute)
    #pragma section(".subroutine_long_routine$c", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(allocate(".subroutine_long_routine$a")) unsigned char subroutine_long_start_marker = 0;
            __declspec(code_seg(".subroutine_long_routine$b"), noinline) long subroutine_long_routine() { return 0xA1B2C3D4; }
            __declspec(allocate(".subroutine_long_routine$c")) unsigned char subroutine_long_end_marker = 0;
        #else
            #if defined(__x86_64__) || defined(_M_X64)
                __attribute__((section(".subroutine_long_routine$a"), noinline, used)) long subroutine_long_start_marker() { return 0xA1B2C3D4E5F6; }
            #else
                __attribute__((section(".subroutine_long_routine$a"), noinline, used)) long subroutine_long_start_marker() { return 0xA1B2C3D4; }
            #endif
            __attribute__((section(".subroutine_long_routine$b"), noinline, used)) void subroutine_long_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_long(lua_State* L) {
        long value = luaL::checkinteger(L, 1);
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_long_start_marker, (uintptr_t)&subroutine_long_end_marker, size);
        #if (defined(__x86_64__) || defined(_M_X64)) && !defined(_WIN32)
            for (size_t i = 0; i + 5 < size; i++) {
                if (ptr[i + 5] == 0xA1 && ptr[i + 4] == 0xB2 && ptr[i + 3] == 0xC3 && ptr[i + 2] == 0xD4 && ptr[i + 1] == 0xE5 && ptr[i] == 0xF6) {
                    *reinterpret_cast<long*>(ptr + i) = value;
                    break;
                }
            }
        #else
            for (size_t i = 0; i + 3 < size; i++) {
                if (ptr[i + 3] == 0xA1 && ptr[i + 2] == 0xB2 && ptr[i + 1] == 0xC3 && ptr[i] == 0xD4) {
                    *reinterpret_cast<long*>(ptr + i) = value;
                    break;
                }
            }
        #endif
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    BEGIN_NOOPT // unsigned long
    #pragma section(".subroutine_ulong_routine$a", read, execute)
    #pragma section(".subroutine_ulong_routine$b", read, execute)
    #pragma section(".subroutine_ulong_routine$c", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(allocate(".subroutine_ulong_routine$a")) unsigned char subroutine_ulong_start_marker = 0;
            __declspec(code_seg(".subroutine_ulong_routine$b"), noinline) unsigned long subroutine_ulong_routine() { return 0xA1B2C3D4; }
            __declspec(allocate(".subroutine_ulong_routine$c")) unsigned char subroutine_ulong_end_marker = 0;
        #else
            #if defined(__x86_64__) || defined(_M_X64)
                __attribute__((section(".subroutine_ulong_routine$a"), noinline, used)) unsigned long subroutine_ulong_start_marker() { return 0xA1B2C3D4E5F6; }
            #else
                __attribute__((section(".subroutine_ulong_routine$a"), noinline, used)) unsigned long subroutine_ulong_start_marker() { return 0xA1B2C3D4; }
            #endif
            __attribute__((section(".subroutine_ulong_routine$b"), noinline, used)) void subroutine_ulong_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_ulong(lua_State* L) {
        unsigned long value = luaL::checkinteger(L, 1);
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_ulong_start_marker, (uintptr_t)&subroutine_ulong_end_marker, size);
        #if (defined(__x86_64__) || defined(_M_X64)) && !defined(_WIN32)
            for (size_t i = 0; i + 5 < size; i++) {
                if (ptr[i + 5] == 0xA1 && ptr[i + 4] == 0xB2 && ptr[i + 3] == 0xC3 && ptr[i + 2] == 0xD4 && ptr[i + 1] == 0xE5 && ptr[i] == 0xF6) {
                    *reinterpret_cast<long*>(ptr + i) = value;
                    break;
                }
            }
        #else
            for (size_t i = 0; i + 3 < size; i++) {
                if (ptr[i + 3] == 0xA1 && ptr[i + 2] == 0xB2 && ptr[i + 1] == 0xC3 && ptr[i] == 0xD4) {
                    *reinterpret_cast<long*>(ptr + i) = value;
                    break;
                }
            }
        #endif
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    int subroutine_sequence(lua_State* L) {
        std::string hex_string = luaL::checkcstring(L, 1);

        std::string filtered;
        for (char ch : std::string(hex_string)) {
            if (!std::isspace(static_cast<unsigned char>(ch))) {
                filtered += ch;
            }
        }

        if (filtered.size() % 2 != 0) {
            return luaL::error(L, "invalid hex string: odd number of digits");
        }

        for (char ch : filtered) {
            if (!std::isxdigit(static_cast<unsigned char>(ch))) {
                return luaL::error(L, "invalid hex string: '%s'", filtered.c_str());
            }
        }

        size_t size = sizeof(unsigned char) * filtered.size() / 2;
        unsigned char* address = (unsigned char*)malloc(size);

        if (!address) {
            return luaL::error(L, "out of memory");
        }

        #if defined(__linux__)
            uintptr_t page_size = sysconf(_SC_PAGESIZE);
            uintptr_t page_start = (uintptr_t)address & ~(page_size - 1);

            int current_prot;
            if (!get_page_permissions(address, current_prot)) {
                return luaL::error(L, "failed to assign execution permissions");
            };

            current_prot |= PROT_EXEC;
            current_prot |= PROT_READ;
            current_prot |= PROT_WRITE;

            if (mprotect((void*)page_start, page_size, current_prot) != 0) {
                return luaL::error(L, "failed to assign execution permissions");
            }
        #elif defined(_WIN32)
            DWORD oldProt;
            if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProt)) {
                return luaL::error(L, "failed to assign execution permissions");
            }
        #endif

        for (unsigned int i = 0; i < (filtered.size() / 2); ++i) {
            std::string byte_str = filtered.substr(i * 2, 2);
            unsigned char byte_val = static_cast<unsigned char>(std::stoul(byte_str, nullptr, 16));
            address[i] = byte_val;
        }

        push_address(L, address);
        lua::pushinteger(L, size);
        return 2;
    }

    typedef void (*pushref__)(lua_State*, int);
    typedef int (*pcall__)(lua_State*, int, int, int);
    BEGIN_NOOPT // invoker
    #pragma section(".subroutine_invoker_routine$a", read, execute)
    #pragma section(".subroutine_invoker_routine$b", read, execute)
    #pragma section(".subroutine_invoker_routine$c", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(allocate(".subroutine_invoker_routine$a")) unsigned char subroutine_invoker_start_marker = 0;
            __declspec(code_seg(".subroutine_invoker_routine$b"), noinline) void subroutine_invoker_routine() {
                int function_id = 0xA1B2C3D4;
                #if defined(__x86_64__) || defined(_M_X64)
                    uintptr_t lua_state = 0x1AA1B2C3D4E5F6;
                    uintptr_t pushref = 0x2AA1B2C3D4E5F6;
                    uintptr_t pcall = 0x3AA1B2C3D4E5F6;
                #else
                    uintptr_t lua_state = 0x1AA1B2C3;
                    uintptr_t pushref = 0x2AA1B2C3;
                    uintptr_t pcall = 0x3AA1B2C3;
                #endif
                ((pushref__)pushref)((lua_State*)lua_state, function_id);
                ((pcall__)pcall)((lua_State*)lua_state, 0, 0, 0);
            }
            __declspec(allocate(".subroutine_invoker_routine$c")) unsigned char subroutine_invoker_end_marker = 0;
        #else
            __attribute__((section(".subroutine_invoker_routine$a"), noinline, used)) void subroutine_invoker_start_marker() {
                int function_id = 0xA1B2C3D4;
                #if defined(__x86_64__) || defined(_M_X64)
                    uintptr_t lua_state = 0x1AA1B2C3D4E5F6;
                    uintptr_t pushref = 0x2AA1B2C3D4E5F6;
                    uintptr_t pcall = 0x3AA1B2C3D4E5F6;
                #else
                    uintptr_t lua_state = 0x1AA1B2C3;
                    uintptr_t pushref = 0x2AA1B2C3;
                    uintptr_t pcall = 0x3AA1B2C3;
                #endif
                ((pushref__)pushref)((lua_State*)lua_state, function_id);
                ((pcall__)pcall)((lua_State*)lua_state, 0, 0, 0);
            }
            __attribute__((section(".subroutine_invoker_routine$b"), noinline, used)) void subroutine_invoker_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_invoker(lua_State* L) {
        luaL::checklfunction(L, 1);
        int id = luaL::newref(L, 1);
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_invoker_start_marker, (uintptr_t)&subroutine_invoker_end_marker, size);

        #if defined(__x86_64__) || defined(_M_X64)
            for (size_t i = 0; i + 3 < size; i++) {
                if (ptr[i + 3] == 0xA1 && ptr[i + 2] == 0xB2 && ptr[i + 1] == 0xC3 && ptr[i] == 0xD4) {
                    *reinterpret_cast<int*>(ptr + i) = id;
                    break;
                }
            }
            for (size_t i = 0; i + 7 < size; i++) {
                if (ptr[i + 7] == 0x00 && ptr[i + 6] == 0x1A && ptr[i + 5] == 0xA1 && ptr[i + 4] == 0xB2 && ptr[i + 3] == 0xC3 && ptr[i + 2] == 0xD4 && ptr[i + 1] == 0xE5 && ptr[i] == 0xF6) {
                    *reinterpret_cast<uintptr_t*>(ptr + i) = (uintptr_t)L;
                    break;
                }
            }
            for (size_t i = 0; i + 7 < size; i++) {
                if (ptr[i + 7] == 0x00 && ptr[i + 6] == 0x2A && ptr[i + 5] == 0xA1 && ptr[i + 4] == 0xB2 && ptr[i + 3] == 0xC3 && ptr[i + 2] == 0xD4 && ptr[i + 1] == 0xE5 && ptr[i] == 0xF6) {
                    *reinterpret_cast<uintptr_t*>(ptr + i) = (uintptr_t)lua::pushref;
                    break;
                }
            }
            for (size_t i = 0; i + 7 < size; i++) {
                if (ptr[i + 7] == 0x00 && ptr[i + 6] == 0x3A && ptr[i + 5] == 0xA1 && ptr[i + 4] == 0xB2 && ptr[i + 3] == 0xC3 && ptr[i + 2] == 0xD4 && ptr[i + 1] == 0xE5 && ptr[i] == 0xF6) {
                    *reinterpret_cast<uintptr_t*>(ptr + i) = (uintptr_t)lua::pcall;
                    break;
                }
            }
        #else
            for (size_t i = 0; i + 3 < size; i++) {
                if (ptr[i + 3] == 0xA1 && ptr[i + 2] == 0xB2 && ptr[i + 1] == 0xC3 && ptr[i] == 0xD4) {
                    *reinterpret_cast<int*>(ptr + i) = id;
                    break;
                }
            }
            for (size_t i = 0; i + 3 < size; i++) {
                if (ptr[i + 3] == 0x1A && ptr[i + 2] == 0xA1 && ptr[i + 1] == 0xB2 && ptr[i] == 0xC3) {
                    *reinterpret_cast<uintptr_t*>(ptr + i) = (uintptr_t)L;
                    break;
                }
            }
            for (size_t i = 0; i + 3 < size; i++) {
                if (ptr[i + 3] == 0x2A && ptr[i + 2] == 0xA1 && ptr[i + 1] == 0xB2 && ptr[i] == 0xC3) {
                    *reinterpret_cast<uintptr_t*>(ptr + i) = (uintptr_t)lua::pushref;
                    break;
                }
            }
            for (size_t i = 0; i + 3 < size; i++) {
                if (ptr[i + 3] == 0x3A && ptr[i + 2] == 0xA1 && ptr[i + 1] == 0xB2 && ptr[i] == 0xC3) {
                    *reinterpret_cast<uintptr_t*>(ptr + i) = (uintptr_t)lua::pcall;
                    break;
                }
            }
        #endif

        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    typedef void*(*blnk)();
    int subroutine_emit(lua_State* L) {
        #if !(defined(__x86_64__) || defined(_M_X64)) && !(defined(__i386__) || defined(_M_IX86))
        return luaL::error(L, "unsupported architecture.");
        #else
        blnk address = (blnk)Class::check(L, 1, "address");
        void* data = address();
        push_address(L, data);
        return 1;
        #endif
    }

    std::unordered_map<uintptr_t, std::vector<char>>& jump_restoration_() {
        static std::unordered_map<uintptr_t, std::vector<char>> jump_restoration = std::unordered_map<uintptr_t, std::vector<char>>();
        return jump_restoration;
    }

    std::unordered_map<uintptr_t, uintptr_t>& jump_mapping_() {
        static std::unordered_map<uintptr_t, uintptr_t> jump_mapping = std::unordered_map<uintptr_t, uintptr_t>();
        return jump_mapping;
    }

    int jump_hook(lua_State* L) {
        char* loc = (char*)Class::check(L, 1, "address");
        char* target = (char*)Class::check(L, 2, "address");

        if (jump_mapping_().find((uintptr_t)loc) != jump_mapping_().end()) {
            lua::pushboolean(L, false);
            return 1;
        }

        bool writeable = is_writable(loc);

        if (!writeable) {
            if (!make_writeable(loc, true)) {
                lua::pushboolean(L, false);
                return 1;
            }
        }

        #if defined(__x86_64__) || defined(_M_X64)
            // SIZE: 12
            // mov rax, imm64 -> 48 B8 XX XX XX XX XX XX XX XX
            // jmp rax -> FF E0
            char* buffer = loc;
            std::vector<char> storage;
            for (unsigned int i = 0; i < 12; ++i) {
                storage.push_back(buffer[i]);
            }
            buffer[0] = 0x48; buffer[1] = 0xB8;
            *(void**)(buffer + 2) = target;
            buffer[10] = 0xFF; buffer[11] = 0xE0;

            jump_restoration_()[(uintptr_t)loc] = storage;
            jump_mapping_()[(uintptr_t)loc] = (uintptr_t)target;
        #elif defined(__i386__) || defined(_M_IX86)
            // SIZE: 5
            // jmp -> E9 XX XX XX XX (offset from PC)
            char* buffer = (char*)loc;
            std::vector<char> storage;
            for (unsigned int i = 0; i < 5; ++i) {
                storage.push_back(buffer[i]);
            }
            buffer[0] = 0xE9;
            intptr_t relative = (intptr_t)(target) - ((intptr_t)buffer + 5);
            *(int32_t*)(buffer + 1) = (int32_t)relative;

            jump_restoration_()[(uintptr_t)loc] = storage;
            jump_mapping_()[(uintptr_t)loc] = (uintptr_t)target;
        #else
            luaL::error(L, "unsupported architecture.");
        #endif

        if (writeable) {
            make_writeable(loc, false);
        }

        lua::pushboolean(L, true);
        return 1;
    }

    int jump_unhook(lua_State* L) {
        char* loc = (char*)Class::check(L, 1, "address");

        if (jump_mapping_().find((uintptr_t)loc) == jump_mapping_().end()) {
            lua::pushboolean(L, false);
            return 1;
        }

        std::vector<char> storage = jump_restoration_()[(uintptr_t)loc];

        bool writeable = is_writable(loc);

        if (!writeable) {
            if (!make_writeable(loc, true)) {
                lua::pushboolean(L, false);
                return 1;
            }
        }

        for (size_t i = 0; i < storage.size(); ++i) {
            ((char*)loc)[i] = storage[i];
        }

        if (writeable) {
            make_writeable(loc, false);
        }

        jump_mapping_().erase((uintptr_t)loc);
        jump_restoration_().erase((uintptr_t)loc);

        lua::pushboolean(L, true);
        return 1;
    }

    int jump_list(lua_State* L) {
        lua::newtable(L);

        int i = 0;
        for (auto& entry : jump_mapping_()) {
            uintptr_t loc = entry.first;
            uintptr_t target = entry.second;

            lua::pushnumber(L, ++i);
            push_address(L, (void*)loc);
            lua::settable(L, -3);

            push_address(L, (void*)loc);
            push_address(L, (void*)target);
            lua::settable(L, -3);
        }

        return 1;
    }

    int jump_get(lua_State* L) {
        char* loc = (char*)Class::check(L, 1, "address");

        if (jump_mapping_().find((uintptr_t)loc) == jump_mapping_().end()) {
            lua::pushboolean(L, false);
            return 1;
        }

        push_address(L, (void*)jump_mapping_()[(uintptr_t)loc]);
        return 1;
    }
    
    void runtime()
    {

    }

    void push(lua_State* L, UMODULE hndle)
    {
        lua::newtable(L);

        lua::pushcfunction(L, address);
        lua::setfield(L, -2, "address");

        lua::pushcfunction(L, allocate);
        lua::setfield(L, -2, "allocate");

        lua::pushcfunction(L, modules);
        lua::setfield(L, -2, "modules");

        lua::pushcfunction(L, module);
        lua::setfield(L, -2, "module");

        lua::pushcfunction(L, regions);
        lua::setfield(L, -2, "regions");

        lua::pushcfunction(L, region);
        lua::setfield(L, -2, "region");

        lua::pushcfunction(L, base);
        lua::setfield(L, -2, "base");

        lua::pushcfunction(L, fetch);
        lua::setfield(L, -2, "fetch");

        lua::pushcfunction(L, vtable);
        lua::setfield(L, -2, "vtable");

        lua::pushcfunction(L, index);
        lua::setfield(L, -2, "index");

        lua::pushcfunction(L, _interface);
        lua::setfield(L, -2, "interface");

        lua::pushcfunction(L, offset);
        lua::setfield(L, -2, "offset");

        lua::pushcfunction(L, relative);
        lua::setfield(L, -2, "relative");

        lua::newtable(L);

        lua::pushcfunction(L, aob_ida);
        lua::setfield(L, -2, "ida");

        lua::pushcfunction(L, aob_hex);
        lua::setfield(L, -2, "hex");

        lua::setfield(L, -2, "aob");

        lua::newtable(L);

        lua::pushcfunction(L, scan_bool);
        lua::setfield(L, -2, "bool");

        lua::pushcfunction(L, scan_char);
        lua::setfield(L, -2, "char");

        lua::pushcfunction(L, scan_uchar);
        lua::setfield(L, -2, "uchar");

        lua::pushcfunction(L, scan_short);
        lua::setfield(L, -2, "short");

        lua::pushcfunction(L, scan_ushort);
        lua::setfield(L, -2, "ushort");

        lua::pushcfunction(L, scan_int);
        lua::setfield(L, -2, "int");

        lua::pushcfunction(L, scan_uint);
        lua::setfield(L, -2, "uint");

        lua::pushcfunction(L, scan_long);
        lua::setfield(L, -2, "long");

        lua::pushcfunction(L, scan_ulong);
        lua::setfield(L, -2, "ulong");

        lua::pushcfunction(L, scan_float);
        lua::setfield(L, -2, "float");

        lua::pushcfunction(L, scan_double);
        lua::setfield(L, -2, "double");

        lua::pushcfunction(L, scan_address);
        lua::setfield(L, -2, "address");

        lua::setfield(L, -2, "scan");

        lua::newtable(L);

        lua::pushcfunction(L, read_bool);
        lua::setfield(L, -2, "bool");

        lua::pushcfunction(L, read_char);
        lua::setfield(L, -2, "char");

        lua::pushcfunction(L, read_uchar);
        lua::setfield(L, -2, "uchar");

        lua::pushcfunction(L, read_short);
        lua::setfield(L, -2, "short");

        lua::pushcfunction(L, read_ushort);
        lua::setfield(L, -2, "ushort");

        lua::pushcfunction(L, read_int);
        lua::setfield(L, -2, "int");

        lua::pushcfunction(L, read_uint);
        lua::setfield(L, -2, "uint");

        lua::pushcfunction(L, read_long);
        lua::setfield(L, -2, "long");

        lua::pushcfunction(L, read_ulong);
        lua::setfield(L, -2, "ulong");

        lua::pushcfunction(L, read_float);
        lua::setfield(L, -2, "float");

        lua::pushcfunction(L, read_double);
        lua::setfield(L, -2, "double");

        lua::pushcfunction(L, read_sequence);
        lua::setfield(L, -2, "sequence");

        lua::pushcfunction(L, read_address);
        lua::setfield(L, -2, "address");

        lua::setfield(L, -2, "read");

        lua::newtable(L);

        lua::pushcfunction(L, write_bool);
        lua::setfield(L, -2, "bool");

        lua::pushcfunction(L, write_char);
        lua::setfield(L, -2, "char");

        lua::pushcfunction(L, write_uchar);
        lua::setfield(L, -2, "uchar");

        lua::pushcfunction(L, write_short);
        lua::setfield(L, -2, "short");

        lua::pushcfunction(L, write_ushort);
        lua::setfield(L, -2, "ushort");

        lua::pushcfunction(L, write_int);
        lua::setfield(L, -2, "int");

        lua::pushcfunction(L, write_uint);
        lua::setfield(L, -2, "uint");

        lua::pushcfunction(L, write_long);
        lua::setfield(L, -2, "long");

        lua::pushcfunction(L, write_ulong);
        lua::setfield(L, -2, "ulong");

        lua::pushcfunction(L, write_float);
        lua::setfield(L, -2, "float");

        lua::pushcfunction(L, write_double);
        lua::setfield(L, -2, "double");

        lua::pushcfunction(L, write_sequence);
        lua::setfield(L, -2, "sequence");

        lua::pushcfunction(L, write_address);
        lua::setfield(L, -2, "address");

        lua::setfield(L, -2, "write");

        lua::newtable(L);

        lua::pushcfunction(L, subroutine_blank);
        lua::setfield(L, -2, "blank");

        lua::pushcfunction(L, subroutine_bool);
        lua::setfield(L, -2, "bool");

        lua::pushcfunction(L, subroutine_char);
        lua::setfield(L, -2, "char");

        lua::pushcfunction(L, subroutine_uchar);
        lua::setfield(L, -2, "uchar");

        lua::pushcfunction(L, subroutine_short);
        lua::setfield(L, -2, "short");

        lua::pushcfunction(L, subroutine_ushort);
        lua::setfield(L, -2, "ushort");

        lua::pushcfunction(L, subroutine_int);
        lua::setfield(L, -2, "int");

        lua::pushcfunction(L, subroutine_uint);
        lua::setfield(L, -2, "uint");

        lua::pushcfunction(L, subroutine_long);
        lua::setfield(L, -2, "long");

        lua::pushcfunction(L, subroutine_ulong);
        lua::setfield(L, -2, "ulong");

        lua::pushcfunction(L, subroutine_sequence);
        lua::setfield(L, -2, "sequence");

        lua::pushcfunction(L, subroutine_invoker);
        lua::setfield(L, -2, "invoker");

        lua::pushcfunction(L, subroutine_emit);
        lua::setfield(L, -2, "emit");

        lua::setfield(L, -2, "subroutine");

        lua::newtable(L);

        lua::pushcfunction(L, jump_hook);
        lua::setfield(L, -2, "hook");

        lua::pushcfunction(L, jump_unhook);
        lua::setfield(L, -2, "unhook");

        lua::pushcfunction(L, jump_list);
        lua::setfield(L, -2, "list");

        lua::pushcfunction(L, jump_get);
        lua::setfield(L, -2, "get");

        lua::setfield(L, -2, "jump");
    }

    void api()
    {
        Reflection::add("memory", push);
    }
}