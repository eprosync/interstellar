#include <string.h>

#include "interstellar_memory.hpp"
#include "interstellar_os.hpp"

#if defined(_WIN32)
#include <psapi.h>
#include <iostream>
#include <windows.h>
#include <intrin.h>
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

    int address__eq(lua_State* L) {
        char* a = (char*)Class::check(L, 1, "address");
        char* b = (char*)Class::check(L, 2, "address");
        lua::pushboolean(L, (uintptr_t)a == (uintptr_t)b);
        return 1;
    }

    int address__index(lua_State* L)
    {
        char* address = (char*)Class::check(L, 1, "address");
        std::string index = luaL::checkcstring(L, 2);

        if (index == "raw") {
            lua::pushinteger(L, (uintptr_t)address);
            return 1;
        } else if (index == "bool") {
            lua::pushboolean(L, (bool)(uintptr_t)address);
            return 1;
        } else if (index == "char") {
            lua::pushinteger(L, (char)(uintptr_t)address);
            return 1;
        } else if (index == "uchar") {
            lua::pushinteger(L, (unsigned char)(uintptr_t)address);
            return 1;
        } else if (index == "short") {
            lua::pushinteger(L, (short)(uintptr_t)address);
            return 1;
        } else if (index == "ushort") {
            lua::pushinteger(L, (unsigned short)(uintptr_t)address);
            return 1;
        } else if (index == "int") {
            lua::pushinteger(L, (int)(uintptr_t)address);
            return 1;
        } else if (index == "uint") {
            lua::pushinteger(L, (unsigned int)(uintptr_t)address);
            return 1;
        } else if (index == "long") {
            lua::pushinteger(L, (long)(uintptr_t)address);
            return 1;
        } else if (index == "ulong") {
            lua::pushinteger(L, (unsigned long)(uintptr_t)address);
            return 1;
        } else if (index == "float") {
            lua::pushnumber(L, (float)(uintptr_t)address);
            return 1;
        } else if (index == "double") {
            lua::pushnumber(L, (double)(uintptr_t)address);
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

            lua::pushcfunction(L, address__eq);
            lua::setfield(L, -2, "__eq");

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

        if (lua::istype(L, 1, datatype::string)) {
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
        push_address(L, (void*)(uintptr_t)luaL::checkinteger(L, 1));
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

    int scan_int8(lua_State* L) {
        int8_t value = luaL::checkinteger(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_uint8(lua_State* L) {
        uint8_t value = luaL::checkinteger(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_int16(lua_State* L) {
        int16_t value = luaL::checkinteger(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_uint16(lua_State* L) {
        uint16_t value = luaL::checkinteger(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_int32(lua_State* L) {
        int32_t value = luaL::checkinteger(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_uint32(lua_State* L) {
        uint32_t value = luaL::checkinteger(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_int64(lua_State* L) {
        int64_t value = luaL::checkinteger(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_uint64(lua_State* L) {
        uint64_t value = luaL::checkinteger(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
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
        char value = luaL::checkinteger(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_uchar(lua_State* L) {
        unsigned char value = luaL::checkinteger(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_short(lua_State* L) {
        short value = luaL::checkinteger(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_ushort(lua_State* L) {
        unsigned short value = luaL::checkinteger(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_int(lua_State* L) {
        int value = luaL::checkinteger(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_uint(lua_State* L) {
        unsigned int value = luaL::checkinteger(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_long(lua_State* L) {
        long value = luaL::checkinteger(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_ulong(lua_State* L) {
        unsigned long value = luaL::checkinteger(L, 1);
        uintptr_t base;
        size_t size;
        scan_get_size(L, base, size);
        scan_process(L, base, size, value);
        return 1;
    }

    int scan_address(lua_State* L) {
        void* value = Class::check(L, 1, "address");
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

    int read_int8(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(int8_t))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushinteger(L, *(int8_t*)address);
        return 1;
    }

    int read_uint8(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(uint8_t))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushinteger(L, *(uint8_t*)address);
        return 1;
    }

    int read_int16(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(int16_t))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushinteger(L, *(int16_t*)address);
        return 1;
    }

    int read_uint16(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(uint16_t))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushinteger(L, *(uint16_t*)address);
        return 1;
    }

    int read_int32(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(int32_t))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushinteger(L, *(int32_t*)address);
        return 1;
    }

    int read_uint32(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(uint32_t))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushinteger(L, *(uint32_t*)address);
        return 1;
    }

    int read_int64(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(int64_t))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushinteger(L, *(int64_t*)address);
        return 1;
    }

    int read_uint64(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(uint64_t))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushinteger(L, *(uint64_t*)address);
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

    int read_string(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");
        int size = 0;

        if (lua::gettop(L) >= 2 && lua::isnumber(L, 2)) {
            size = (int)luaL::checkinteger(L, 2);
        }

        std::string result;
        if (size > 0) {
            if (!is_valid_read(address, size)) {
                return luaL::error(L, "invalid read access at address %p", address);
            }

            const char* p = (const char*)address;
            for (int i = 0; i < size; ++i) {
                if (p[i] == '\0') break;
                result.push_back(p[i]);
            }
        }
        else {
            const char* p = (const char*)address;
            while (is_valid_read((void*)p, 1) && *p != '\0') {
                result.push_back(*p++);
            }
        }

        lua::pushcstring(L, result);
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

    int write_int8(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(int8_t))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        *(int8_t*)address = luaL::checkinteger(L, 2);
        return 0;
    }

    int write_uint8(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(uint8_t))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        *(uint8_t*)address = luaL::checkinteger(L, 2);
        return 0;
    }

    int write_int16(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(int16_t))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        *(int16_t*)address = luaL::checkinteger(L, 2);
        return 0;
    }

    int write_uint16(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(uint16_t))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        *(uint16_t*)address = luaL::checkinteger(L, 2);
        return 0;
    }

    int write_int32(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(int32_t))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        *(int32_t*)address = luaL::checkinteger(L, 2);
        return 0;
    }

    int write_uint32(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(uint32_t))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        *(uint32_t*)address = luaL::checkinteger(L, 2);
        return 0;
    }

    int write_int64(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(int64_t))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        *(int64_t*)address = luaL::checkinteger(L, 2);
        return 0;
    }

    int write_uint64(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(uint64_t))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        *(uint64_t*)address = luaL::checkinteger(L, 2);
        return 0;
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

    int write_string(lua_State* L) {
        unsigned char* address = (unsigned char*)Class::check(L, 1, "address");
        size_t len;
        const char* str = luaL::checklstring(L, 2, &len);

        if (!is_valid_write(address, len)) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        bool writeable = is_writable(address);

        if (!writeable) {
            if (!make_writeable(address, true)) {
                return luaL::error(L, "failed to change page protection rules on %p", (void*)address);
            }
        }

        memcpy(address, str, len + 1);
        address[len + 1] = '\0';

        if (!writeable) {
            if (!make_writeable(address, false)) {
                return luaL::error(L, "failed to restore page protection rules on %p", address);
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
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_blank_routine$a"), noinline) static void subroutine_blank_start_marker() {}
            __declspec(allocate(".subroutine_blank_routine$b")) static unsigned char subroutine_blank_end_marker = 0;
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

    BEGIN_NOOPT // int8
    #pragma section(".subroutine_int8_routine$a", read, execute)
    #pragma section(".subroutine_int8_routine$b", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_int8_routine$a"), noinline) static int8_t subroutine_int8_start_marker() { return 0xFF; }
            __declspec(allocate(".subroutine_int8_routine$b")) static unsigned char subroutine_int8_end_marker = 0;
        #else
            __attribute__((section(".subroutine_int8_routine$a"), noinline, used)) int8_t subroutine_int8_start_marker() { return 0xFF; }
            __attribute__((section(".subroutine_int8_routine$b"), noinline, used)) void subroutine_int8_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_int8(lua_State* L) {
        int8_t value = luaL::checkinteger(L, 1);
        size_t size;
        char* ptr = (char*)subroutine_boundary(L, (uintptr_t)&subroutine_int8_start_marker, (uintptr_t)&subroutine_int8_end_marker, size);
        for (size_t i = 0; i < size; i++) {
            if (ptr[i] == 0xFF) {
                *reinterpret_cast<int8_t*>(ptr + i) = value;
                break;
            }
        }
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    BEGIN_NOOPT // uint8
    #pragma section(".subroutine_uint8_routine$a", read, execute)
    #pragma section(".subroutine_uint8_routine$b", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_uint8_routine$a"), noinline) static uint8_t subroutine_uint8_start_marker() { return 0xFF; }
            __declspec(allocate(".subroutine_uint8_routine$b")) static unsigned char subroutine_uint8_end_marker = 0;
        #else
            __attribute__((section(".subroutine_uint8_routine$a"), noinline, used)) uint8_t subroutine_uint8_start_marker() { return 0xFF; }
            __attribute__((section(".subroutine_uint8_routine$b"), noinline, used)) void subroutine_uint8_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_uint8(lua_State* L) {
        uint8_t value = luaL::checkinteger(L, 1);
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_uint8_start_marker, (uintptr_t)&subroutine_uint8_end_marker, size);
        for (size_t i = 0; i < size; i++) {
            if (ptr[i] == 0xFF) {
                *reinterpret_cast<uint8_t*>(ptr + i) = value;
                break;
            }
        }
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }
    
    BEGIN_NOOPT // int16
    #pragma section(".subroutine_int16_routine$a", read, execute)
    #pragma section(".subroutine_int16_routine$b", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_int16_routine$a"), noinline) static int16_t subroutine_int16_start_marker() { return 0xFFFF; }
            __declspec(allocate(".subroutine_int16_routine$b")) static unsigned char subroutine_int16_end_marker = 0;
        #else
            __attribute__((section(".subroutine_int16_routine$a"), noinline, used)) int16_t subroutine_int16_start_marker() { return 0xFFFF; }
            __attribute__((section(".subroutine_int16_routine$b"), noinline, used)) void subroutine_int16_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_int16(lua_State* L) {
        int16_t value = luaL::checkinteger(L, 1);
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_int16_start_marker, (uintptr_t)&subroutine_int16_end_marker, size);
        for (size_t i = 0; i + 1 < size; i++) {
            if (ptr[i+1] == 0xFF && ptr[i] == 0xFF) {
                *reinterpret_cast<int16_t*>(ptr + i) = value;
                break;
            }
        }
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    BEGIN_NOOPT // uint16
    #pragma section(".subroutine_uint16_routine$a", read, execute)
    #pragma section(".subroutine_uint16_routine$b", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_uint16_routine$a"), noinline) static uint16_t subroutine_uint16_start_marker() { return 0xFFFF; }
            __declspec(allocate(".subroutine_uint16_routine$b")) static unsigned char subroutine_uint16_end_marker = 0;
        #else
            __attribute__((section(".subroutine_uint16_routine$a"), noinline, used)) uint16_t subroutine_uint16_start_marker() { return 0xFFFF; }
            __attribute__((section(".subroutine_uint16_routine$b"), noinline, used)) void subroutine_uint16_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_uint16(lua_State* L) {
        uint16_t value = luaL::checkinteger(L, 1);
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_uint16_start_marker, (uintptr_t)&subroutine_uint16_end_marker, size);
        for (size_t i = 0; i < size; i++) {
            if (ptr[i+1] == 0xFF && ptr[i] == 0xFF) {
                *reinterpret_cast<uint16_t*>(ptr + i) = value;
                break;
            }
        }
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    BEGIN_NOOPT // int32
    #pragma section(".subroutine_int32_routine$a", read, execute)
    #pragma section(".subroutine_int32_routine$b", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_int32_routine$a"), noinline) static int32_t subroutine_int32_start_marker() { return 0xA1B2C3D4; }
            __declspec(allocate(".subroutine_int32_routine$b")) static unsigned char subroutine_int32_end_marker = 0;
        #else
            __attribute__((section(".subroutine_int32_routine$a"), noinline, used)) int32_t subroutine_int32_start_marker() { return 0xA1B2C3D4; }
            __attribute__((section(".subroutine_int32_routine$b"), noinline, used)) void subroutine_int32_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_int32(lua_State* L) {
        int32_t value = luaL::checkinteger(L, 1);
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_int32_start_marker, (uintptr_t)&subroutine_int32_end_marker, size);
        for (size_t i = 0; i + 1 < size; i++) {
            if (ptr[i + 3] == 0xA1 && ptr[i + 2] == 0xB2 && ptr[i + 1] == 0xC3 && ptr[i] == 0xD4) {
                *reinterpret_cast<int32_t*>(ptr + i) = value;
                break;
            }
        }
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    BEGIN_NOOPT // uint32
    #pragma section(".subroutine_uint32_routine$a", read, execute)
    #pragma section(".subroutine_uint32_routine$b", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_uint32_routine$a"), noinline) static uint32_t subroutine_uint32_start_marker() { return 0xA1B2C3D4; }
            __declspec(allocate(".subroutine_uint32_routine$b")) static unsigned char subroutine_uint32_end_marker = 0;
        #else
            __attribute__((section(".subroutine_uint32_routine$a"), noinline, used)) uint32_t subroutine_uint32_start_marker() { return 0xA1B2C3D4; }
            __attribute__((section(".subroutine_uint32_routine$b"), noinline, used)) void subroutine_uint32_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_uint32(lua_State* L) {
        uint32_t value = luaL::checkinteger(L, 1);
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_uint32_start_marker, (uintptr_t)&subroutine_uint32_end_marker, size);
        for (size_t i = 0; i < size; i++) {
            if (ptr[i + 3] == 0xA1 && ptr[i + 2] == 0xB2 && ptr[i + 1] == 0xC3 && ptr[i] == 0xD4) {
                *reinterpret_cast<uint32_t*>(ptr + i) = value;
                break;
            }
        }
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    BEGIN_NOOPT // int64
    #pragma section(".subroutine_int64_routine$a", read, execute)
    #pragma section(".subroutine_int64_routine$b", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_int64_routine$a"), noinline) static int64_t subroutine_int64_start_marker() { return 0xA1B2C3D4E5F6; }
            __declspec(allocate(".subroutine_int64_routine$b")) static unsigned char subroutine_int64_end_marker = 0;
        #else
            __attribute__((section(".subroutine_int64_routine$a"), noinline, used)) int64_t subroutine_int64_start_marker() { return 0xA1B2C3D4E5F6; }
            __attribute__((section(".subroutine_int64_routine$b"), noinline, used)) void subroutine_int64_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_int64(lua_State* L) {
        int64_t value = luaL::checkinteger(L, 1);
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_int64_start_marker, (uintptr_t)&subroutine_int64_end_marker, size);
        for (size_t i = 0; i + 1 < size; i++) {
            if (ptr[i + 5] == 0xA1 && ptr[i + 4] == 0xB2 && ptr[i + 3] == 0xC3 && ptr[i + 2] == 0xD4 && ptr[i + 1] == 0xE5 && ptr[i] == 0xF6) {
                *reinterpret_cast<int64_t*>(ptr + i) = value;
                break;
            }
        }
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    BEGIN_NOOPT // uint64
    #pragma section(".subroutine_uint64_routine$a", read, execute)
    #pragma section(".subroutine_uint64_routine$b", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_uint64_routine$a"), noinline) static uint64_t subroutine_uint64_start_marker() { return 0xA1B2C3D4E5F6; }
            __declspec(allocate(".subroutine_uint64_routine$b")) static unsigned char subroutine_uint64_end_marker = 0;
        #else
            __attribute__((section(".subroutine_uint64_routine$a"), noinline, used)) uint64_t subroutine_uint64_start_marker() { return 0xA1B2C3D4E5F6; }
            __attribute__((section(".subroutine_uint64_routine$b"), noinline, used)) void subroutine_uint64_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_uint64(lua_State* L) {
        uint64_t value = luaL::checkinteger(L, 1);
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_uint64_start_marker, (uintptr_t)&subroutine_uint64_end_marker, size);
        for (size_t i = 0; i < size; i++) {
            if (ptr[i + 5] == 0xA1 && ptr[i + 4] == 0xB2 && ptr[i + 3] == 0xC3 && ptr[i + 2] == 0xD4 && ptr[i + 1] == 0xE5 && ptr[i] == 0xF6) {
                *reinterpret_cast<uint64_t*>(ptr + i) = value;
                break;
            }
        }
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
    }

    BEGIN_NOOPT // bool
    #pragma section(".subroutine_bool_routine$a", read, execute)
    #pragma section(".subroutine_bool_routine$b", read, execute)
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_bool_routine$a"), noinline) static bool subroutine_bool_start_marker() { return true; }
            __declspec(allocate(".subroutine_bool_routine$b")) static unsigned char subroutine_bool_end_marker = 0;
        #else
            __attribute__((section(".subroutine_bool_routine$a"), noinline, used)) bool subroutine_bool_start_marker() { return true; }
            __attribute__((section(".subroutine_bool_routine$b"), noinline, used)) void subroutine_bool_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_bool(lua_State* L) {
        bool value = luaL::checkboolean(L, 1);
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_bool_start_marker, (uintptr_t)&subroutine_bool_end_marker, size);
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
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_char_routine$a"), noinline) static char subroutine_char_start_marker() { return 0xFF; }
            __declspec(allocate(".subroutine_char_routine$b")) static unsigned char subroutine_char_end_marker = 0;
        #else
            __attribute__((section(".subroutine_char_routine$a"), noinline, used)) char subroutine_char_start_marker() { return 0xFF; }
            __attribute__((section(".subroutine_char_routine$b"), noinline, used)) void subroutine_char_end_marker() {}
        #endif
    }
    END_NOOPT
    int subroutine_char(lua_State* L) {
        char value = luaL::checkinteger(L, 1);
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_char_start_marker, (uintptr_t)&subroutine_char_end_marker, size);
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
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_uchar_routine$a"), noinline) static unsigned char subroutine_uchar_start_marker() { return 0xFF; }
            __declspec(allocate(".subroutine_uchar_routine$b")) static unsigned char subroutine_uchar_end_marker = 0;
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
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_short_routine$a"), noinline) static short subroutine_short_start_marker() { return 0xFFFF; }
            __declspec(allocate(".subroutine_short_routine$b")) static unsigned char subroutine_short_end_marker = 0;
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
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_ushort_routine$a"), noinline) static unsigned short subroutine_ushort_start_marker() { return 0xFFFF; }
            __declspec(allocate(".subroutine_ushort_routine$b")) static unsigned char subroutine_ushort_end_marker = 0;
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
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_int_routine$a"), noinline) static int subroutine_int_start_marker() { return 0xA1B2C3D4; }
            __declspec(allocate(".subroutine_int_routine$b")) static unsigned char subroutine_int_end_marker = 0;
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
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_uint_routine$a"), noinline) static unsigned int subroutine_uint_start_marker() { return 0xA1B2C3D4; }
            __declspec(allocate(".subroutine_uint_routine$b")) static unsigned char subroutine_uint_end_marker = 0;
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
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_long_routine$a"), noinline) static long subroutine_long_start_marker() { return 0xA1B2C3D4; }
            __declspec(allocate(".subroutine_long_routine$b")) static unsigned char subroutine_long_end_marker = 0;
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
    extern "C" {
        #ifdef _WIN32
            __declspec(code_seg(".subroutine_ulong_routine$a"), noinline) static unsigned long subroutine_ulong_start_marker() { return 0xA1B2C3D4; }
            __declspec(allocate(".subroutine_ulong_routine$b")) static unsigned char subroutine_ulong_end_marker = 0;
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

    // pain.
    typedef void (*pushref__)(lua_State*, int);
    typedef void (*pop__)(lua_State*, int);
    typedef int (*pcall__)(lua_State*, int, int, int);
    typedef void (*push_address__)(lua_State*, void*);
    typedef bool (*class_is__)(lua_State*, int, unsigned char);
    typedef void* (*class_to__)(lua_State*, int);
    BEGIN_NOOPT // invoker
    #pragma section(".subroutine_invoker_routine$a", read, execute)
    #pragma section(".subroutine_invoker_routine$b", read, execute)
    extern "C" {
        #ifdef _WIN32
            #if defined(__x86_64__) || defined(_M_X64)
            __declspec(code_seg(".subroutine_invoker_routine$a"), noinline) static void* subroutine_invoker_start_marker(void* a, void* b, void* c, void* d) {
            #else
            __declspec(code_seg(".subroutine_invoker_routine$a"), noinline) static void* subroutine_invoker_start_marker() {
            #endif
                int function_id = 0xA1B2C3D4;
                unsigned int class_id = 0xB1B2C3D4;
                #if defined(__x86_64__) || defined(_M_X64)
                    void* sp = (void*)((uintptr_t)_AddressOfReturnAddress() + 0x8);
                    uintptr_t lua_state = 0x1AA1B2C3D4E5F6;
                    uintptr_t pushref = 0x2AA1B2C3D4E5F6;
                    uintptr_t pcall = 0x3AA1B2C3D4E5F6;
                    uintptr_t push_address = 0x4AA1B2C3D4E5F6;
                    uintptr_t class_is = 0x5AA1B2C3D4E5F6;
                    uintptr_t class_to = 0x6AA1B2C3D4E5F6;
                    uintptr_t pop = 0x7AA1B2C3D4E5F6;
                    ((pushref__)pushref)((lua_State*)lua_state, function_id);
                    ((push_address__)push_address)((lua_State*)lua_state, sp);
                    ((pcall__)pcall)((lua_State*)lua_state, 1, 1, 0);
                    void* address = 0;
                    if (((class_is__)class_is)((lua_State*)lua_state, -1, (unsigned char)class_id)) {
                        address = ((class_to__)class_to)((lua_State*)lua_state, -1);
                    }
                    ((pop__)pop)((lua_State*)lua_state, 1);
                    return address;
                #else
                    void* sp = (void*)((uintptr_t)_AddressOfReturnAddress() + 0x4);
                    uintptr_t lua_state = 0x1AA1B2C3;
                    uintptr_t pushref = 0x2AA1B2C3;
                    uintptr_t pcall = 0x3AA1B2C3;
                    uintptr_t push_address = 0x4AA1B2C3;
                    uintptr_t class_is = 0x5AA1B2C3;
                    uintptr_t class_to = 0x6AA1B2C3;
                    uintptr_t pop = 0x7AA1B2C3;
                    ((pushref__)pushref)((lua_State*)lua_state, function_id);
                    ((push_address__)push_address)((lua_State*)lua_state, sp);
                    ((pcall__)pcall)((lua_State*)lua_state, 1, 1, 0);
                    void* address = (void*)0x100;
                    if (((class_is__)class_is)((lua_State*)lua_state, -1, (unsigned char)class_id)) {
                        address = ((class_to__)class_to)((lua_State*)lua_state, -1);
                    }
                    ((pop__)pop)((lua_State*)lua_state, 1);
                    return address;
                #endif
            }
            __declspec(allocate(".subroutine_invoker_routine$b")) static unsigned char subroutine_invoker_end_marker = 0;
        #else
            #if defined(__x86_64__) || defined(_M_X64)
                __attribute__((section(".subroutine_invoker_routine$a"), noinline, used)) void* subroutine_invoker_start_marker(void* a, void* b, void* c, void* d) {
            #else
                __attribute__((section(".subroutine_invoker_routine$a"), noinline, used)) void* subroutine_invoker_start_marker() {
            #endif
                int function_id = 0xA1B2C3D4;
                unsigned int class_id = 0xB1B2C3D4;
                #if defined(__x86_64__) || defined(_M_X64)
                    void* sp = (void*)((uintptr_t)__builtin_frame_address(0) + 0x8);
                    uintptr_t lua_state = 0x1AA1B2C3D4E5F6;
                    uintptr_t pushref = 0x2AA1B2C3D4E5F6;
                    uintptr_t pcall = 0x3AA1B2C3D4E5F6;
                    uintptr_t push_address = 0x4AA1B2C3D4E5F6;
                    uintptr_t class_is = 0x5AA1B2C3D4E5F6;
                    uintptr_t class_to = 0x6AA1B2C3D4E5F6;
                    uintptr_t pop = 0x7AA1B2C3D4E5F6;
                    ((pushref__)pushref)((lua_State*)lua_state, function_id);
                    ((push_address__)push_address)((lua_State*)lua_state, sp);
                    ((push_address__)push_address)((lua_State*)lua_state, a);
                    ((push_address__)push_address)((lua_State*)lua_state, b);
                    ((push_address__)push_address)((lua_State*)lua_state, c);
                    ((push_address__)push_address)((lua_State*)lua_state, d);
                    ((pcall__)pcall)((lua_State*)lua_state, 5, 1, 0);
                    void* address = 0;
                    if (((class_is__)class_is)((lua_State*)lua_state, -1, (unsigned char)class_id)) {
                        address = ((class_to__)class_to)((lua_State*)lua_state, -1);
                    }
                    ((pop__)pop)((lua_State*)lua_state, 1);
                    return address;
                #else
                    void* sp = (void*)((uintptr_t)__builtin_frame_address(0) + 0x8);
                    uintptr_t lua_state = 0x1AA1B2C3;
                    uintptr_t pushref = 0x2AA1B2C3;
                    uintptr_t pcall = 0x3AA1B2C3;
                    uintptr_t push_address = 0x4AA1B2C3;
                    uintptr_t class_is = 0x5AA1B2C3;
                    uintptr_t class_to = 0x6AA1B2C3;
                    uintptr_t pop = 0x7AA1B2C3;
                    ((pushref__)pushref)((lua_State*)lua_state, function_id);
                    ((push_address__)push_address)((lua_State*)lua_state, sp);
                    ((pcall__)pcall)((lua_State*)lua_state, 1, 1, 0);
                    void* address = 0;
                    if (((class_is__)class_is)((lua_State*)lua_state, -1, (unsigned char)class_id)) {
                        address = ((class_to__)class_to)((lua_State*)lua_state, -1);
                    }
                    ((pop__)pop)((lua_State*)lua_state, 1);
                    return address;
                #endif
            }
            __attribute__((section(".subroutine_invoker_routine$b"), noinline, used)) void subroutine_invoker_end_marker() {}
        #endif
    }
    END_NOOPT

    int subroutine_invoker(lua_State* L) {
        #if !(defined(__x86_64__) || defined(_M_X64)) && !(defined(__i386__) || defined(_M_IX86))
        return luaL::error(L, "unsupported architecture.");
        #else
        luaL::checklfunction(L, 1);
        int id = luaL::newref(L, 1);
        Class::class_store store = Class::getbyname(L, "address");
        size_t size;
        unsigned char* ptr = (unsigned char*)subroutine_boundary(L, (uintptr_t)&subroutine_invoker_start_marker, (uintptr_t)&subroutine_invoker_end_marker, size);
        
        for (size_t i = 0; i + 3 < size; i++) {
            if (ptr[i + 3] == 0xA1 && ptr[i + 2] == 0xB2 && ptr[i + 1] == 0xC3 && ptr[i] == 0xD4) {
                *reinterpret_cast<int*>(ptr + i) = id;
                break;
            }
        }
        for (size_t i = 0; i + 3 < size; i++) {
            if (ptr[i + 3] == 0xB1 && ptr[i + 2] == 0xB2 && ptr[i + 1] == 0xC3 && ptr[i] == 0xD4) {
                *reinterpret_cast<unsigned int*>(ptr + i) = (unsigned int)store.type;
                break;
            }
        }

        #if defined(__x86_64__) || defined(_M_X64)
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
            for (size_t i = 0; i + 7 < size; i++) {
                if (ptr[i + 7] == 0x00 && ptr[i + 6] == 0x4A && ptr[i + 5] == 0xA1 && ptr[i + 4] == 0xB2 && ptr[i + 3] == 0xC3 && ptr[i + 2] == 0xD4 && ptr[i + 1] == 0xE5 && ptr[i] == 0xF6) {
                    *reinterpret_cast<uintptr_t*>(ptr + i) = (uintptr_t)push_address;
                    break;
                }
            }
            for (size_t i = 0; i + 7 < size; i++) {
                if (ptr[i + 7] == 0x00 && ptr[i + 6] == 0x5A && ptr[i + 5] == 0xA1 && ptr[i + 4] == 0xB2 && ptr[i + 3] == 0xC3 && ptr[i + 2] == 0xD4 && ptr[i + 1] == 0xE5 && ptr[i] == 0xF6) {
                    *reinterpret_cast<uintptr_t*>(ptr + i) = (uintptr_t)(class_is__)Class::is;
                    break;
                }
            }
            for (size_t i = 0; i + 7 < size; i++) {
                if (ptr[i + 7] == 0x00 && ptr[i + 6] == 0x6A && ptr[i + 5] == 0xA1 && ptr[i + 4] == 0xB2 && ptr[i + 3] == 0xC3 && ptr[i + 2] == 0xD4 && ptr[i + 1] == 0xE5 && ptr[i] == 0xF6) {
                    *reinterpret_cast<uintptr_t*>(ptr + i) = (uintptr_t)Class::to;
                    break;
                }
            }
            for (size_t i = 0; i + 7 < size; i++) {
                if (ptr[i + 7] == 0x00 && ptr[i + 6] == 0x7A && ptr[i + 5] == 0xA1 && ptr[i + 4] == 0xB2 && ptr[i + 3] == 0xC3 && ptr[i + 2] == 0xD4 && ptr[i + 1] == 0xE5 && ptr[i] == 0xF6) {
                    *reinterpret_cast<uintptr_t*>(ptr + i) = (uintptr_t)lua::pop;
                    break;
                }
            }
        #else
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
            for (size_t i = 0; i + 3 < size; i++) {
                if (ptr[i + 3] == 0x4A && ptr[i + 2] == 0xA1 && ptr[i + 1] == 0xB2 && ptr[i] == 0xC3) {
                    *reinterpret_cast<uintptr_t*>(ptr + i) = (uintptr_t)push_address;
                    break;
                }
            }
            for (size_t i = 0; i + 3 < size; i++) {
                if (ptr[i + 3] == 0x5A && ptr[i + 2] == 0xA1 && ptr[i + 1] == 0xB2 && ptr[i] == 0xC3) {
                    *reinterpret_cast<uintptr_t*>(ptr + i) = (uintptr_t)(class_is__)Class::is;
                    break;
                }
            }
            for (size_t i = 0; i + 3 < size; i++) {
                if (ptr[i + 3] == 0x6A && ptr[i + 2] == 0xA1 && ptr[i + 1] == 0xB2 && ptr[i] == 0xC3) {
                    *reinterpret_cast<uintptr_t*>(ptr + i) = (uintptr_t)Class::to;
                    break;
                }
            }
            for (size_t i = 0; i + 3 < size; i++) {
                if (ptr[i + 3] == 0x7A && ptr[i + 2] == 0xA1 && ptr[i + 1] == 0xB2 && ptr[i] == 0xC3) {
                    *reinterpret_cast<uintptr_t*>(ptr + i) = (uintptr_t)lua::pop;
                    break;
                }
            }
        #endif
        push_address(L, (void*)ptr);
        lua::pushinteger(L, size);
        return 2;
        #endif
    }

    typedef void* (*blnk)(...);
    template <size_t... I>
    void* call_n_impl(blnk f, const std::vector<void*>& args, std::index_sequence<I...>) {
        return f(args[I]...);
    }

    template <size_t N>
    void* call_n(blnk f, const std::vector<void*>& args) {
        return call_n_impl(f, args, std::make_index_sequence<N>{});
    }

    int subroutine_emit(lua_State* L) {
        #if !(defined(__aarch64__) || defined(__x86_64__) || defined(_M_X64)) && !(defined(__arm__) || defined(__i386__) || defined(_M_IX86))
        return luaL::error(L, "unsupported architecture.");
        #else
        blnk address = (blnk)Class::check(L, 1, "address");

        int nargs = lua::gettop(L) - 1;
        std::vector<void*> args;
        args.reserve(nargs);

        for (int i = 0; i < nargs; i++) {
            void* arg = Class::check(L, i + 2, "address");
            args.push_back(arg);
        }

        void* result = nullptr;

        // why can't I just generate these like in rust?
        try {
            switch (nargs) {
                case 0: result = call_n<0>(address, args); break;
                case 1: result = call_n<1>(address, args); break;
                case 2: result = call_n<2>(address, args); break;
                case 3: result = call_n<3>(address, args); break;
                case 4: result = call_n<4>(address, args); break;
                case 5: result = call_n<5>(address, args); break;
                case 6: result = call_n<6>(address, args); break;
                case 7: result = call_n<7>(address, args); break;
                case 8: result = call_n<8>(address, args); break;
                case 9: result = call_n<9>(address, args); break;
                case 10: result = call_n<10>(address, args); break;
                case 11: result = call_n<11>(address, args); break;
                case 12: result = call_n<12>(address, args); break;
                case 13: result = call_n<13>(address, args); break;
                case 14: result = call_n<14>(address, args); break;
                case 15: result = call_n<15>(address, args); break;
                case 16: result = call_n<16>(address, args); break;
                case 17: result = call_n<17>(address, args); break;
                case 18: result = call_n<18>(address, args); break;
                case 19: result = call_n<19>(address, args); break;
                case 20: result = call_n<20>(address, args); break;
                case 21: result = call_n<21>(address, args); break;
                case 22: result = call_n<22>(address, args); break;
                case 23: result = call_n<23>(address, args); break;
                case 24: result = call_n<24>(address, args); break;
                case 25: result = call_n<25>(address, args); break;
                case 26: result = call_n<26>(address, args); break;
                case 27: result = call_n<27>(address, args); break;
                case 28: result = call_n<28>(address, args); break;
                case 29: result = call_n<29>(address, args); break;
                case 30: result = call_n<30>(address, args); break;
                case 31: result = call_n<31>(address, args); break;
                case 32: result = call_n<32>(address, args); break;
                case 33: result = call_n<33>(address, args); break;
                case 34: result = call_n<34>(address, args); break;
                case 35: result = call_n<35>(address, args); break;
                case 36: result = call_n<36>(address, args); break;
                case 37: result = call_n<37>(address, args); break;
                case 38: result = call_n<38>(address, args); break;
                case 39: result = call_n<39>(address, args); break;
                case 40: result = call_n<40>(address, args); break;
                case 41: result = call_n<41>(address, args); break;
                case 42: result = call_n<42>(address, args); break;
                case 43: result = call_n<43>(address, args); break;
                case 44: result = call_n<44>(address, args); break;
                case 45: result = call_n<45>(address, args); break;
                case 46: result = call_n<46>(address, args); break;
                case 47: result = call_n<47>(address, args); break;
                case 48: result = call_n<48>(address, args); break;
                case 49: result = call_n<49>(address, args); break;
                case 50: result = call_n<50>(address, args); break;
                case 51: result = call_n<51>(address, args); break;
                case 52: result = call_n<52>(address, args); break;
                case 53: result = call_n<53>(address, args); break;
                case 54: result = call_n<54>(address, args); break;
                case 55: result = call_n<55>(address, args); break;
                case 56: result = call_n<56>(address, args); break;
                case 57: result = call_n<57>(address, args); break;
                case 58: result = call_n<58>(address, args); break;
                case 59: result = call_n<59>(address, args); break;
                case 60: result = call_n<60>(address, args); break;
                case 61: result = call_n<61>(address, args); break;
                case 62: result = call_n<62>(address, args); break;
                case 63: result = call_n<63>(address, args); break;
                case 64: result = call_n<64>(address, args); break;
                case 65: result = call_n<65>(address, args); break;
                case 66: result = call_n<66>(address, args); break;
                case 67: result = call_n<67>(address, args); break;
                case 68: result = call_n<68>(address, args); break;
                case 69: result = call_n<69>(address, args); break;
                case 70: result = call_n<70>(address, args); break;
                case 71: result = call_n<71>(address, args); break;
                case 72: result = call_n<72>(address, args); break;
                case 73: result = call_n<73>(address, args); break;
                case 74: result = call_n<74>(address, args); break;
                case 75: result = call_n<75>(address, args); break;
                case 76: result = call_n<76>(address, args); break;
                case 77: result = call_n<77>(address, args); break;
                case 78: result = call_n<78>(address, args); break;
                case 79: result = call_n<79>(address, args); break;
                case 80: result = call_n<80>(address, args); break;
                case 81: result = call_n<81>(address, args); break;
                case 82: result = call_n<82>(address, args); break;
                case 83: result = call_n<83>(address, args); break;
                case 84: result = call_n<84>(address, args); break;
                case 85: result = call_n<85>(address, args); break;
                case 86: result = call_n<86>(address, args); break;
                case 87: result = call_n<87>(address, args); break;
                case 88: result = call_n<88>(address, args); break;
                case 89: result = call_n<89>(address, args); break;
                case 90: result = call_n<90>(address, args); break;
                case 91: result = call_n<91>(address, args); break;
                case 92: result = call_n<92>(address, args); break;
                case 93: result = call_n<93>(address, args); break;
                case 94: result = call_n<94>(address, args); break;
                case 95: result = call_n<95>(address, args); break;
                case 96: result = call_n<96>(address, args); break;
                case 97: result = call_n<97>(address, args); break;
                case 98: result = call_n<98>(address, args); break;
                case 99: result = call_n<99>(address, args); break;
                case 100: result = call_n<100>(address, args); break;
                case 101: result = call_n<101>(address, args); break;
                case 102: result = call_n<102>(address, args); break;
                case 103: result = call_n<103>(address, args); break;
                case 104: result = call_n<104>(address, args); break;
                case 105: result = call_n<105>(address, args); break;
                case 106: result = call_n<106>(address, args); break;
                case 107: result = call_n<107>(address, args); break;
                case 108: result = call_n<108>(address, args); break;
                case 109: result = call_n<109>(address, args); break;
                case 110: result = call_n<110>(address, args); break;
                case 111: result = call_n<111>(address, args); break;
                case 112: result = call_n<112>(address, args); break;
                case 113: result = call_n<113>(address, args); break;
                case 114: result = call_n<114>(address, args); break;
                case 115: result = call_n<115>(address, args); break;
                case 116: result = call_n<116>(address, args); break;
                case 117: result = call_n<117>(address, args); break;
                case 118: result = call_n<118>(address, args); break;
                case 119: result = call_n<119>(address, args); break;
                case 120: result = call_n<120>(address, args); break;
                case 121: result = call_n<121>(address, args); break;
                case 122: result = call_n<122>(address, args); break;
                case 123: result = call_n<123>(address, args); break;
                case 124: result = call_n<124>(address, args); break;
                case 125: result = call_n<125>(address, args); break;
                case 126: result = call_n<126>(address, args); break;
                case 127: result = call_n<127>(address, args); break;
                case 128: result = call_n<128>(address, args); break;
                case 129: result = call_n<129>(address, args); break;
                case 130: result = call_n<130>(address, args); break;
                case 131: result = call_n<131>(address, args); break;
                case 132: result = call_n<132>(address, args); break;
                case 133: result = call_n<133>(address, args); break;
                case 134: result = call_n<134>(address, args); break;
                case 135: result = call_n<135>(address, args); break;
                case 136: result = call_n<136>(address, args); break;
                case 137: result = call_n<137>(address, args); break;
                case 138: result = call_n<138>(address, args); break;
                case 139: result = call_n<139>(address, args); break;
                case 140: result = call_n<140>(address, args); break;
                case 141: result = call_n<141>(address, args); break;
                case 142: result = call_n<142>(address, args); break;
                case 143: result = call_n<143>(address, args); break;
                case 144: result = call_n<144>(address, args); break;
                case 145: result = call_n<145>(address, args); break;
                case 146: result = call_n<146>(address, args); break;
                case 147: result = call_n<147>(address, args); break;
                case 148: result = call_n<148>(address, args); break;
                case 149: result = call_n<149>(address, args); break;
                case 150: result = call_n<150>(address, args); break;
                case 151: result = call_n<151>(address, args); break;
                case 152: result = call_n<152>(address, args); break;
                case 153: result = call_n<153>(address, args); break;
                case 154: result = call_n<154>(address, args); break;
                case 155: result = call_n<155>(address, args); break;
                case 156: result = call_n<156>(address, args); break;
                case 157: result = call_n<157>(address, args); break;
                case 158: result = call_n<158>(address, args); break;
                case 159: result = call_n<159>(address, args); break;
                case 160: result = call_n<160>(address, args); break;
                case 161: result = call_n<161>(address, args); break;
                case 162: result = call_n<162>(address, args); break;
                case 163: result = call_n<163>(address, args); break;
                case 164: result = call_n<164>(address, args); break;
                case 165: result = call_n<165>(address, args); break;
                case 166: result = call_n<166>(address, args); break;
                case 167: result = call_n<167>(address, args); break;
                case 168: result = call_n<168>(address, args); break;
                case 169: result = call_n<169>(address, args); break;
                case 170: result = call_n<170>(address, args); break;
                case 171: result = call_n<171>(address, args); break;
                case 172: result = call_n<172>(address, args); break;
                case 173: result = call_n<173>(address, args); break;
                case 174: result = call_n<174>(address, args); break;
                case 175: result = call_n<175>(address, args); break;
                case 176: result = call_n<176>(address, args); break;
                case 177: result = call_n<177>(address, args); break;
                case 178: result = call_n<178>(address, args); break;
                case 179: result = call_n<179>(address, args); break;
                case 180: result = call_n<180>(address, args); break;
                case 181: result = call_n<181>(address, args); break;
                case 182: result = call_n<182>(address, args); break;
                case 183: result = call_n<183>(address, args); break;
                case 184: result = call_n<184>(address, args); break;
                case 185: result = call_n<185>(address, args); break;
                case 186: result = call_n<186>(address, args); break;
                case 187: result = call_n<187>(address, args); break;
                case 188: result = call_n<188>(address, args); break;
                case 189: result = call_n<189>(address, args); break;
                case 190: result = call_n<190>(address, args); break;
                case 191: result = call_n<191>(address, args); break;
                case 192: result = call_n<192>(address, args); break;
                case 193: result = call_n<193>(address, args); break;
                case 194: result = call_n<194>(address, args); break;
                case 195: result = call_n<195>(address, args); break;
                case 196: result = call_n<196>(address, args); break;
                case 197: result = call_n<197>(address, args); break;
                case 198: result = call_n<198>(address, args); break;
                case 199: result = call_n<199>(address, args); break;
                case 200: result = call_n<200>(address, args); break;
                case 201: result = call_n<201>(address, args); break;
                case 202: result = call_n<202>(address, args); break;
                case 203: result = call_n<203>(address, args); break;
                case 204: result = call_n<204>(address, args); break;
                case 205: result = call_n<205>(address, args); break;
                case 206: result = call_n<206>(address, args); break;
                case 207: result = call_n<207>(address, args); break;
                case 208: result = call_n<208>(address, args); break;
                case 209: result = call_n<209>(address, args); break;
                case 210: result = call_n<210>(address, args); break;
                case 211: result = call_n<211>(address, args); break;
                case 212: result = call_n<212>(address, args); break;
                case 213: result = call_n<213>(address, args); break;
                case 214: result = call_n<214>(address, args); break;
                case 215: result = call_n<215>(address, args); break;
                case 216: result = call_n<216>(address, args); break;
                case 217: result = call_n<217>(address, args); break;
                case 218: result = call_n<218>(address, args); break;
                case 219: result = call_n<219>(address, args); break;
                case 220: result = call_n<220>(address, args); break;
                case 221: result = call_n<221>(address, args); break;
                case 222: result = call_n<222>(address, args); break;
                case 223: result = call_n<223>(address, args); break;
                case 224: result = call_n<224>(address, args); break;
                case 225: result = call_n<225>(address, args); break;
                case 226: result = call_n<226>(address, args); break;
                case 227: result = call_n<227>(address, args); break;
                case 228: result = call_n<228>(address, args); break;
                case 229: result = call_n<229>(address, args); break;
                case 230: result = call_n<230>(address, args); break;
                case 231: result = call_n<231>(address, args); break;
                case 232: result = call_n<232>(address, args); break;
                case 233: result = call_n<233>(address, args); break;
                case 234: result = call_n<234>(address, args); break;
                case 235: result = call_n<235>(address, args); break;
                case 236: result = call_n<236>(address, args); break;
                case 237: result = call_n<237>(address, args); break;
                case 238: result = call_n<238>(address, args); break;
                case 239: result = call_n<239>(address, args); break;
                case 240: result = call_n<240>(address, args); break;
                case 241: result = call_n<241>(address, args); break;
                case 242: result = call_n<242>(address, args); break;
                case 243: result = call_n<243>(address, args); break;
                case 244: result = call_n<244>(address, args); break;
                case 245: result = call_n<245>(address, args); break;
                case 246: result = call_n<246>(address, args); break;
                case 247: result = call_n<247>(address, args); break;
                case 248: result = call_n<248>(address, args); break;
                case 249: result = call_n<249>(address, args); break;
                case 250: result = call_n<250>(address, args); break;
                case 251: result = call_n<251>(address, args); break;
                case 252: result = call_n<252>(address, args); break;
                case 253: result = call_n<253>(address, args); break;
                case 254: result = call_n<254>(address, args); break;
                case 255: result = call_n<255>(address, args); break;
                default: return 0;
            }
        }
        catch (const std::exception& e) {
            return luaL::error(L, "subroutine exception: %s", e.what());
        }
        catch (...) {
            return luaL::error(L, "subroutine unknown exception");
        }

        push_address(L, result);
        return 1;
        #endif
    }

    typedef int (*blnk_cfunc)(lua_State*);
    int subroutine_cfunc(lua_State* L) {
        blnk_cfunc address = (blnk_cfunc)Class::check(L, 1, "address");
        lua::pushcfunction(L, address);
        return 1;
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
            // ARCH: x64, SIZE: 12
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
            // ARCH: x86, SIZE: 5
            // jmp -> E9 XX XX XX XX (offset from PC)
            char* buffer = loc;
            std::vector<char> storage;
            for (unsigned int i = 0; i < 5; ++i) {
                storage.push_back(buffer[i]);
            }
            buffer[0] = 0xE9;
            intptr_t relative = (intptr_t)(target) - ((intptr_t)buffer + 5);
            *(int32_t*)(buffer + 1) = (int32_t)relative;

            jump_restoration_()[(uintptr_t)loc] = storage;
            jump_mapping_()[(uintptr_t)loc] = (uintptr_t)target;
        #elif defined(__arm__)
            // ARCH: ARM32, SIZE: 12
            // movw r12, #imm16 (lower)
            // movt r12, #imm16 (upper)
            // bx r12 -> 0xE12FFF10
            char* buffer = loc;
            std::vector<char> storage;
            for (unsigned int i = 0; i < 12; ++i) {
                storage.push_back(buffer[i]);
            }

            uint32_t i0 = ((uintptr_t)target >>  0) & 0xFFFF;  // lower 16 bits
            uint32_t i1 = ((uintptr_t)target >> 16) & 0xFFFF;  // upper 16 bits

            uint32_t* instr = (uint32_t*)buffer;

            // r12 seems like the best for a sratch procedure call, don't see any other being available...
            // ISA MOVW -> cond (31–28) | op (27–23) | fixed:0 (22) | IMM4 (19-16) | Rd (15-12) | IMM12 (11-0)
            instr[0] = 0xE3000000 | (12 << 12) | ((i0 & 0xF000) << 4) | ((i0 & 0x0FFF));
            // ISA MOVT -> cond (31–28) | op (27–23) | fixed:1 (22) | IMM4 (19-16) | Rd (15-12) | IMM12 (11-0)
            instr[1] = 0xE3400000 | (12 << 12) | ((i1 & 0xF000) << 4) | ((i1 & 0x0FFF));
            // ISA BX -> cond (31-28) | op:000100101111111111110001 (27-4) | Rm (3-0)
            instr[2] = 0xE12FFF10 | (12);

            jump_restoration_()[(uintptr_t)loc] = storage;
            jump_mapping_()[(uintptr_t)loc] = (uintptr_t)target;
        #elif defined(__aarch64__)
            // ARCH: AARCH64 (ARMv8-A A64), SIZE: 20
            // movz x16, i0 -> 0X XX X9 D2
            // movk x16, i1, lsl #16 -> 0X XX XB F2
            // movk x16, i2, lsl #32 -> 0X XX XD F2
            // movk x16, i3, lsl #48 -> 0X XX XF F2
            // br x16 -> 00 02 D6 1F
            char* buffer = loc;

            std::vector<char> storage;
            for (unsigned int i = 0; i < 20; ++i) {
                storage.push_back(buffer[i]);
            }

            uint16_t i0 = ((uintptr_t)target >>  0) & 0xFFFF;
            uint16_t i1 = ((uintptr_t)target >> 16) & 0xFFFF;
            uint16_t i2 = ((uintptr_t)target >> 32) & 0xFFFF;
            uint16_t i3 = ((uintptr_t)target >> 48) & 0xFFFF;

            uint32_t* instr = (uint32_t*)buffer;

            // x16 seems to be the best register here, since its a procedure call standard for a scratch trampoline call usually...
            // ISA MOVZ -> sf:1 (64-bit R) | opc:10 | fixed:100101 | HW (22–21) | IMM16 (20–5) | Rd (4–0)
            instr[0] = 0xD2800000 | (i0 << 5) | 16;
            // ISA MOVK -> sf:1 (64-bit R) | opc:11 | fixed:100101 | HW (22–21) | IMM16 (20–5) | Rd (4–0)
            instr[1] = 0xF2800000 | (1 << 21) | (i1 << 5) | 16;
            instr[2] = 0xF2800000 | (2 << 21) | (i2 << 5) | 16;
            instr[3] = 0xF2800000 | (3 << 21) | (i3 << 5) | 16;
            // ISA BR -> fixed (31–10): 1101011000011111000000 | Rn (9–5) | 00000
            instr[4] = 0xD61F0000 | (16 << 5);

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

        lua::pushcfunction(L, scan_int8);
        lua::setfield(L, -2, "int8");

        lua::pushcfunction(L, scan_uint8);
        lua::setfield(L, -2, "uint8");

        lua::pushcfunction(L, scan_int16);
        lua::setfield(L, -2, "int16");

        lua::pushcfunction(L, scan_uint16);
        lua::setfield(L, -2, "uint16");

        lua::pushcfunction(L, scan_int32);
        lua::setfield(L, -2, "int32");

        lua::pushcfunction(L, scan_uint32);
        lua::setfield(L, -2, "uint32");

        lua::pushcfunction(L, scan_int64);
        lua::setfield(L, -2, "int64");

        lua::pushcfunction(L, scan_uint64);
        lua::setfield(L, -2, "uint64");

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

        lua::pushcfunction(L, read_int8);
        lua::setfield(L, -2, "int8");

        lua::pushcfunction(L, read_uint8);
        lua::setfield(L, -2, "uint8");

        lua::pushcfunction(L, read_int16);
        lua::setfield(L, -2, "int16");

        lua::pushcfunction(L, read_uint16);
        lua::setfield(L, -2, "uint16");

        lua::pushcfunction(L, read_int32);
        lua::setfield(L, -2, "int32");

        lua::pushcfunction(L, read_uint32);
        lua::setfield(L, -2, "uint32");

        lua::pushcfunction(L, read_int64);
        lua::setfield(L, -2, "int64");

        lua::pushcfunction(L, read_uint64);
        lua::setfield(L, -2, "uint64");

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

        lua::pushcfunction(L, read_string);
        lua::setfield(L, -2, "string");

        lua::pushcfunction(L, read_address);
        lua::setfield(L, -2, "address");

        lua::setfield(L, -2, "read");

        lua::newtable(L);

        lua::pushcfunction(L, write_int8);
        lua::setfield(L, -2, "int8");

        lua::pushcfunction(L, write_uint8);
        lua::setfield(L, -2, "uint8");

        lua::pushcfunction(L, write_int16);
        lua::setfield(L, -2, "int16");

        lua::pushcfunction(L, write_uint16);
        lua::setfield(L, -2, "uint16");

        lua::pushcfunction(L, write_int32);
        lua::setfield(L, -2, "int32");

        lua::pushcfunction(L, write_uint32);
        lua::setfield(L, -2, "uint32");

        lua::pushcfunction(L, write_int64);
        lua::setfield(L, -2, "int64");

        lua::pushcfunction(L, write_uint64);
        lua::setfield(L, -2, "uint64");

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

        lua::pushcfunction(L, write_string);
        lua::setfield(L, -2, "string");

        lua::pushcfunction(L, write_address);
        lua::setfield(L, -2, "address");

        lua::setfield(L, -2, "write");

        lua::newtable(L);

        lua::pushcfunction(L, subroutine_blank);
        lua::setfield(L, -2, "blank");

        lua::pushcfunction(L, subroutine_int8);
        lua::setfield(L, -2, "int8");

        lua::pushcfunction(L, subroutine_uint8);
        lua::setfield(L, -2, "uint8");

        lua::pushcfunction(L, subroutine_int16);
        lua::setfield(L, -2, "int16");

        lua::pushcfunction(L, subroutine_uint16);
        lua::setfield(L, -2, "uint16");

        lua::pushcfunction(L, subroutine_int32);
        lua::setfield(L, -2, "int32");

        lua::pushcfunction(L, subroutine_uint32);
        lua::setfield(L, -2, "uint32");

        lua::pushcfunction(L, subroutine_int64);
        lua::setfield(L, -2, "int64");

        lua::pushcfunction(L, subroutine_uint64);
        lua::setfield(L, -2, "uint64");

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

        lua::pushcfunction(L, subroutine_cfunc);
        lua::setfield(L, -2, "cfunc");

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

        lua::newtable(L);

        lua::pushinteger(L, sizeof(int8_t));
        lua::setfield(L, -2, "int8");

        lua::pushinteger(L, sizeof(uint8_t));
        lua::setfield(L, -2, "uint8");

        lua::pushinteger(L, sizeof(int16_t));
        lua::setfield(L, -2, "int16");

        lua::pushinteger(L, sizeof(uint16_t));
        lua::setfield(L, -2, "uint16");

        lua::pushinteger(L, sizeof(int32_t));
        lua::setfield(L, -2, "int32");

        lua::pushinteger(L, sizeof(uint32_t));
        lua::setfield(L, -2, "uint32");

        lua::pushinteger(L, sizeof(int64_t));
        lua::setfield(L, -2, "int64");

        lua::pushinteger(L, sizeof(uint64_t));
        lua::setfield(L, -2, "uint64");

        lua::pushinteger(L, sizeof(void*));
        lua::setfield(L, -2, "address");

        lua::pushinteger(L, sizeof(void*));
        lua::setfield(L, -2, "pointer");

        lua::pushinteger(L, sizeof(bool));
        lua::setfield(L, -2, "bool");

        lua::pushinteger(L, sizeof(char));
        lua::setfield(L, -2, "char");

        lua::pushinteger(L, sizeof(unsigned char));
        lua::setfield(L, -2, "uchar");

        lua::pushinteger(L, sizeof(short));
        lua::setfield(L, -2, "short");

        lua::pushinteger(L, sizeof(unsigned short));
        lua::setfield(L, -2, "ushort");

        lua::pushinteger(L, sizeof(int));
        lua::setfield(L, -2, "int");

        lua::pushinteger(L, sizeof(unsigned int));
        lua::setfield(L, -2, "uint");

        lua::pushinteger(L, sizeof(long));
        lua::setfield(L, -2, "long");

        lua::pushinteger(L, sizeof(unsigned long));
        lua::setfield(L, -2, "ulong");

        lua::pushinteger(L, sizeof(long long));
        lua::setfield(L, -2, "longlong");

        lua::pushinteger(L, sizeof(unsigned long long));
        lua::setfield(L, -2, "ulonglong");

        lua::pushinteger(L, sizeof(float));
        lua::setfield(L, -2, "float");

        lua::pushinteger(L, sizeof(double));
        lua::setfield(L, -2, "double");

        lua::setfield(L, -2, "size");
    }

    void api()
    {
        Reflection::add("memory", push);
    }
}