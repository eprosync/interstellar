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
#include <iostream>
#include <iomanip>

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

    void push_address(lua_State* L, void* addr)
    {
        if (!Class::existsbyname(L, "address")) {
            Class::create(L, "address");

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

    int scanner_hex(lua_State* L) {
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

    int scanner_ida(lua_State* L) {
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

    int read_bool(lua_State* L) {
        char* address = (char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(bool))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushboolean(L, *(bool*)address);
        return 1;
    }

    int read_char(lua_State* L) {
        char* address = (char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(char))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(char*)address);
        return 1;
    }

    int read_uchar(lua_State* L) {
        char* address = (char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(unsigned char))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(unsigned char*)address);
        return 1;
    }

    int read_short(lua_State* L) {
        char* address = (char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(short))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(short*)address);
        return 1;
    }

    int read_ushort(lua_State* L) {
        char* address = (char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(unsigned short))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(unsigned short*)address);
        return 1;
    }

    int read_int(lua_State* L) {
        char* address = (char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(int))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(int*)address);
        return 1;
    }

    int read_uint(lua_State* L) {
        char* address = (char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(unsigned int))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(unsigned int*)address);
        return 1;
    }

    int read_long(lua_State* L) {
        char* address = (char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(long))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(long*)address);
        return 1;
    }

    int read_ulong(lua_State* L) {
        char* address = (char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(unsigned long))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(unsigned long*)address);
        return 1;
    }

    int read_float(lua_State* L) {
        char* address = (char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(float))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(float*)address);
        return 1;
    }

    int read_double(lua_State* L) {
        char* address = (char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(double))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        lua::pushnumber(L, *(double*)address);
        return 1;
    }

    int read_sequence(lua_State* L) {
        char* address = (char*)Class::check(L, 1, "address");
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
        char* address = (char*)Class::check(L, 1, "address");

        if (!is_valid_read(address, sizeof(void*))) {
            return luaL::error(L, "invalid read access at address %p", address);
        }

        push_address(L, *(void**)address);
        return 1;
    }

    int write_bool(lua_State* L) {
        char* address = (char*)Class::check(L, 1, "address");

        if (!is_valid_write(address, sizeof(bool))) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        *(bool*)address = luaL::checkboolean(L, 2);
        return 0;
    }

    int write_char(lua_State* L) {
        char* address = (char*)Class::check(L, 1, "address");

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
        char* address = (char*)Class::check(L, 1, "address");

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
        char* address = (char*)Class::check(L, 1, "address");

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
        char* address = (char*)Class::check(L, 1, "address");

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
        char* address = (char*)Class::check(L, 1, "address");

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
        char* address = (char*)Class::check(L, 1, "address");

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
        char* address = (char*)Class::check(L, 1, "address");

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
        char* address = (char*)Class::check(L, 1, "address");

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
        char* address = (char*)Class::check(L, 1, "address");

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
        char* address = (char*)Class::check(L, 1, "address");

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
        char* address = (char*)Class::check(L, 1, "address");
        std::string hex_string = luaL::checkcstring(L, 2);
        unsigned int size = luaL::checknumber(L, 3);

        if (!is_valid_write(address, sizeof(unsigned char) * size)) {
            return luaL::error(L, "invalid write access at address %p", address);
        }

        std::string hex_string_no_spaces;
        for (char ch : std::string(hex_string)) {
            if (!std::isspace(static_cast<unsigned char>(ch))) {
                hex_string_no_spaces += ch;
            }
        }

        if (hex_string_no_spaces.length() != static_cast<size_t>(size * 2)) {
            return luaL::error(L, "expected %u characters, got %zu", size * 2, hex_string_no_spaces.length());
        }


        for (char ch : hex_string_no_spaces) {
            if (!std::isspace(static_cast<unsigned char>(ch)) && !std::isxdigit(static_cast<unsigned char>(ch))) {
                return luaL::error(L, "invalid hex string: '%s'", hex_string_no_spaces.c_str());
            }
        }

        bool writeable = is_writable(address);

        if (!writeable) {
            if (!make_writeable(address, true)) {
                return luaL::error(L, "failed to change page protection rules on %p", (void*)address);
            }
        }

        for (unsigned int i = 0; i < size; ++i) {
            std::string byte_str = hex_string_no_spaces.substr(i * 2, 2);
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
        char* address = (char*)Class::check(L, 1, "address");

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
    
    void runtime()
    {

    }

    void push(lua_State* L, UMODULE hndle)
    {
        lua::newtable(L);

        lua::pushcfunction(L, address);
        lua::setfield(L, -2, "address");

        lua::pushcfunction(L, modules);
        lua::setfield(L, -2, "modules");

        lua::pushcfunction(L, module);
        lua::setfield(L, -2, "module");

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

        lua::newtable(L);

        lua::pushcfunction(L, scanner_ida);
        lua::setfield(L, -2, "ida");

        lua::pushcfunction(L, scanner_hex);
        lua::setfield(L, -2, "hex");

        lua::setfield(L, -2, "aob");

        lua::pushcfunction(L, offset);
        lua::setfield(L, -2, "offset");

        lua::pushcfunction(L, relative);
        lua::setfield(L, -2, "relative");

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
    }

    void api()
    {
        Reflection::add("memory", push);
    }
}