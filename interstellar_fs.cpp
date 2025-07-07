#include <string.h>

#include "interstellar_fs.hpp"
#include "interstellar.hpp"
#include "interstellar_buffer.hpp"

#include <unordered_set>
#include <unordered_map>
#include <map>
#include <sstream>
#include <ostream>
#include <fstream>
#include <string>
#include <regex>
#include <mutex>
#include <thread>

#include <iostream>
#include <vector>

#if defined(_WIN32)
    #include <windows.h>
#elif defined(__linux__)
    #include <unistd.h>
    #include <limits.h>
    #include <stdlib.h> 
#endif

const char* path_extension(const char* path) {
    const char* last_dot = strrchr(path, '.');
    const char* last_slash_unix = strrchr(path, '/');
    const char* last_slash_win = strrchr(path, '\\');

    const char* last_slash = last_slash_unix;
    if (!last_slash || (last_slash_win && last_slash_win > last_slash)) {
        last_slash = last_slash_win;
    }

    if (last_dot && (!last_slash || last_dot > last_slash)) {
        return last_dot;
    }

    return "";
}

// TODO: We need async FS operations...
namespace INTERSTELLAR_NAMESPACE::FS {
    using namespace API;
    std::mutex async_lock;

    std::unordered_map<std::string, lua_FS_Error>& get_on_error()
    {
        static std::unordered_map<std::string, lua_FS_Error> m;
        return m;
    }

    void add_error(std::string name, lua_FS_Error callback)
    {
        auto& on_error = get_on_error();
        on_error.emplace(name, callback);
    }

    void remove_error(std::string name)
    {
        auto& on_error = get_on_error();
        on_error.erase(name);
    }

    std::string pwd() {
        return std::filesystem::current_path().string();
    }

    std::string where() {
        #if defined(_WIN32)
            std::vector<char> buffer(MAX_PATH);
            DWORD length = 0;

            while (true) {
                length = GetModuleFileNameA(NULL, buffer.data(), static_cast<DWORD>(buffer.size()));
                if (length == 0) {
                    return "";
                }
                else if (length < buffer.size()) {
                    break;
                }
                else {
                    // Buffer was too small; grow it
                    buffer.resize(buffer.size() * 2);
                }
            }

            std::string fullPath(buffer.data(), length);
            size_t pos = fullPath.find_last_of("\\/");
            return (pos != std::string::npos) ? fullPath.substr(0, pos) : "";

        #elif defined(__linux__)
            ssize_t length = 0;
            std::vector<char> buffer(1024);

            while (true) {
                length = readlink("/proc/self/exe", buffer.data(), buffer.size() - 1);
                if (length == -1) {
                    return "";
                }
                else if (length < buffer.size() - 1) {
                    buffer[length] = '\0'; // Null-terminate
                    break;
                }
                else {
                    // Buffer was too small; grow it
                    buffer.resize(buffer.size() * 2);
                }
            }

            std::string fullPath(buffer.data(), length);
            size_t pos = fullPath.find_last_of('/');
            return (pos != std::string::npos) ? fullPath.substr(0, pos) : "";

        #else
            return ""; // Unsupported platform
        #endif
    }

    std::string root_path = ""; // This is to prevent some common isolation escape
    std::vector<std::string> disallowedExtensions = {
        ".exe", ".scr", ".bat", ".com", ".csh", ".msi", ".vb", ".vbs", ".vbe", ".ws", ".wsf", ".wsh", ".ps1"
    };

    std::filesystem::path canonical_bounded(const std::string file_path) {
        std::filesystem::path root = std::filesystem::path(root_path);
        std::filesystem::path combined = root / file_path;
        std::filesystem::path normalized = combined.lexically_normal();

        if (std::mismatch(root.begin(), root.end(), normalized.begin()).first != root.end()) {
            return std::filesystem::path("");
        }

        return std::filesystem::relative(normalized, root);
    }

    int canonical(lua_State* L) {
        std::string file_path = luaL::checkcstring(L, 1);
        lua::pushcstring(L, canonical_bounded(file_path).string());
        return 1;
    }

    bool within(const std::string& root_path, const std::string& file_path) {
        std::filesystem::path weak_path = std::filesystem::path(root_path) / std::filesystem::path(file_path);
        std::filesystem::path full_path = std::filesystem::weakly_canonical(weak_path);
        return full_path.string().rfind(root_path) == 0;
    }

    bool within_bounded(const std::string& root_path, const std::string& file_path) {
        std::filesystem::path weak_path = std::filesystem::path(root_path) / std::filesystem::path(file_path);
        std::filesystem::path full_path = canonical_bounded(weak_path.string());
        return full_path.string().rfind(root_path) == 0;
    }

    int within(lua_State* L) {
        std::string root_path = luaL::checkcstring(L, 1);
        std::string file_path = luaL::checkcstring(L, 2);
        lua::pushboolean(L, within_bounded(root_path, file_path));
        return 1;
    }

    std::string localize(const std::string& root_path, const std::string& file_path) {
        std::filesystem::path weak_path = std::filesystem::path(root_path) / std::filesystem::path(file_path);
        std::filesystem::path full_path = std::filesystem::weakly_canonical(weak_path);

        if (full_path.string().rfind(root_path) != 0) {
            return "";
        }

        return full_path.string();
    }

    int join(lua_State* L) {
        int args = lua::gettop(L);
        std::filesystem::path joined;
        for (int i = 1; i <= args; i++) {
            std::filesystem::path str = luaL::checkcstring(L, i);
            joined = joined / str;
        }
        lua::pushcstring(L, joined.string());
        return 1;
    }

    std::string forward(std::string path) {
        std::replace(path.begin(), path.end(), '\\', '/');
        return path;
    }

    int forward(lua_State* L) {
        lua::pushcstring(L, forward(luaL::checkcstring(L, 1)));
        return 1;
    }

    std::string backward(std::string path) {
        std::replace(path.begin(), path.end(), '/', '\\');
        return path;
    }

    int backward(lua_State* L) {
        lua::pushcstring(L, backward(luaL::checkcstring(L, 1)));
        return 1;
    }

    std::string extname(const std::string& path) {
        std::filesystem::path _path = path;
        return _path.extension().string();
    }

    std::string extname(const std::string& path, const std::string& replace) {
        std::filesystem::path _path = path;
        _path.replace_extension(replace);
        return _path.string();
    }

    int extname(lua_State* L) {
        std::string path = luaL::checkcstring(L, 1);
        if (!lua::isnil(L, 2)) {
            lua::pushcstring(L, extname(path, luaL::checkcstring(L, 2)));
        }
        else {
            lua::pushcstring(L, extname(path));
        }
        return 1;
    }

    std::string filename(const std::string& path) {
        std::filesystem::path _path = path;
        return _path.filename().string();
    }

    std::string filename(const std::string& path, const std::string& replace) {
        std::filesystem::path _path = path;
        _path.replace_filename(replace);
        return _path.string();
    }

    int filename(lua_State* L) {
        std::string path = luaL::checkcstring(L, 1);
        if (!lua::isnil(L, 2)) {
            lua::pushcstring(L, filename(path, luaL::checkcstring(L, 2)));
        }
        else {
            lua::pushcstring(L, filename(path));
        }
        return 1;
    }

    std::string dirname(const std::string& path) {
        std::filesystem::path _path = path;
        return _path.parent_path().string();
    }

    std::string dirname(const std::string& path, const std::string& replace) {
        std::filesystem::path _path = path;
        _path = std::filesystem::path(replace) / _path.filename();
        return _path.string();
    }

    int dirname(lua_State* L) {
        std::string path = luaL::checkcstring(L, 1);
        if (!lua::isnil(L, 2)) {
            lua::pushcstring(L, dirname(path, luaL::checkcstring(L, 2)));
        }
        else {
            lua::pushcstring(L, dirname(path));
        }
        return 1;
    }

    std::string sanitize(const std::string& input) {
        #ifdef _WIN32
        static const std::regex invalid_chars("[<>:\"|?*\n\r\t\b\f\v]");
        std::string sanitized = std::regex_replace(input, invalid_chars, "_");

        sanitized.erase(std::remove_if(sanitized.begin(), sanitized.end(),
            [](unsigned char c) { return c < 32 || c > 126; }),
            sanitized.end());

        while (!sanitized.empty() && (sanitized.back() == ' ' || sanitized.back() == '.')) {
            sanitized.pop_back();
        }

        static const std::unordered_set<std::string> reserved_names = {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
        };

        std::string name = std::filesystem::path(sanitized).stem().string();
        if (reserved_names.count(name)) {
            sanitized += "_safe";
        }
        #else
        static const std::regex invalid_chars("[/\\0\n\r\t\b\f\v]");
        std::string sanitized = std::regex_replace(input, invalid_chars, "_");

        sanitized.erase(std::remove_if(sanitized.begin(), sanitized.end(),
            [](unsigned char c) { return c < 32 || c > 126; }),
            sanitized.end());

        while (!sanitized.empty() && (sanitized.back() == ' ' || sanitized.back() == '.')) {
            sanitized.pop_back();
        }
        #endif

        if (sanitized.empty()) {
            sanitized = "blank";
        }

        return sanitized;
    }

    int sanitize(lua_State* L) {
        lua::pushcstring(L, sanitize(luaL::checkcstring(L, 1)));
        return 1;
    }

    bool isfile(const std::string& file_path) {
        return std::filesystem::is_regular_file(file_path);
    }

    int isfile(lua_State* L) {
        std::string file_path = luaL::checkcstring(L, 1);
        std::filesystem::path weak_path = std::filesystem::path(root_path) / std::filesystem::path(file_path);
        std::filesystem::path full_path = std::filesystem::weakly_canonical(weak_path);

        if (full_path.string().rfind(root_path) != 0) {
            luaL::error(L, "fs.isfile, attempt to escape directory");
            return 0;
        }

        lua::pushboolean(L, std::filesystem::is_regular_file(full_path));

        return 1;
    }

    bool isfolder(const std::string& folder_path) {
        return std::filesystem::is_directory(folder_path);
    }

    int isfolder(lua_State* L) {
        std::string file_path = luaL::checkcstring(L, 1);
        std::filesystem::path weak_path = std::filesystem::path(root_path) / std::filesystem::path(file_path);
        std::filesystem::path full_path = std::filesystem::weakly_canonical(weak_path);

        if (full_path.string().rfind(root_path) != 0) {
            luaL::error(L, "fs.isfolder, attempt to escape directory");
            return 0;
        }

        lua::pushboolean(L, std::filesystem::is_directory(full_path));

        return 1;
    }

    bool readable(const std::string& file_path)
    {
        std::error_code ec;
        auto perms = std::filesystem::status(file_path, ec).permissions();
        if ((perms & std::filesystem::perms::owner_read) != std::filesystem::perms::none &&
            (perms & std::filesystem::perms::group_read) != std::filesystem::perms::none &&
            (perms & std::filesystem::perms::others_read) != std::filesystem::perms::none) {
            return true;
        }
        return false;
    }

    int readable(lua_State* L) {
        std::string file_path = luaL::checkcstring(L, 1);
        std::filesystem::path weak_path = std::filesystem::path(root_path) / std::filesystem::path(file_path);
        std::filesystem::path full_path = std::filesystem::weakly_canonical(weak_path);

        if (full_path.string().rfind(root_path) != 0) {
            luaL::error(L, "fs.readable, attempt to escape directory");
            return 0;
        }

        lua::pushboolean(L, readable(full_path.string()));

        return 1;
    }

    bool writeable(const std::string& file_path)
    {
        std::error_code ec;
        auto perms = std::filesystem::status(file_path, ec).permissions();
        if ((perms & std::filesystem::perms::owner_write) != std::filesystem::perms::none &&
            (perms & std::filesystem::perms::group_write) != std::filesystem::perms::none &&
            (perms & std::filesystem::perms::others_write) != std::filesystem::perms::none) {
            return true;
        }
        return false;
    }

    int writeable(lua_State* L) {
        std::string file_path = luaL::checkcstring(L, 1);
        std::filesystem::path weak_path = std::filesystem::path(root_path) / std::filesystem::path(file_path);
        std::filesystem::path full_path = std::filesystem::weakly_canonical(weak_path);

        if (full_path.string().rfind(root_path) != 0) {
            luaL::error(L, "fs.writeable, attempt to escape directory");
            return 0;
        }

        lua::pushboolean(L, writeable(full_path.string()));

        return 1;
    }

    int scan(lua_State* L) {
        std::string folder_path = luaL::checkcstring(L, 1);
        std::filesystem::path weak_path = std::filesystem::path(root_path) / std::filesystem::path(folder_path);
        std::filesystem::path full_path = std::filesystem::weakly_canonical(weak_path);

        if (full_path.string().rfind(root_path) != 0) {
            luaL::error(L, "fs.scan, attempt to escape directory");
            return 0;
        }

        if (!std::filesystem::exists(full_path)) {
            return 0;
        }

        lua::newtable(L);

        size_t index = 1;

        for (const auto& entry : std::filesystem::directory_iterator(full_path)) {
            std::string filename = entry.path().filename().string();
            lua::pushnumber(L, index++);
            lua::pushcstring(L, filename);
            lua::settable(L, -3);
        }

        return 1;
    }

    bool mkdir(const std::string& folder_path) {
        return std::filesystem::create_directories(folder_path);
    }

    int mkdir(lua_State* L) {
        std::string folder_path = luaL::checkcstring(L, 1);
        std::filesystem::path weak_path = std::filesystem::path(root_path) / std::filesystem::path(folder_path);
        std::filesystem::path full_path = std::filesystem::weakly_canonical(weak_path);

        if (full_path.string().rfind(root_path) != 0) {
            luaL::error(L, "fs.mkdir, attempt to escape directory");
            return 0;
        }

        lua::pushboolean(L, std::filesystem::create_directories(full_path));

        return 0;
    }

    bool rmdir(const std::string& folder_path) {
        try {
            return std::filesystem::remove_all(folder_path);
        }
        catch (std::exception& e) {
            return false;
        }
    }

    int rmdir(lua_State* L) {
        std::string folder_path = luaL::checkcstring(L, 1);
        std::filesystem::path weak_path = std::filesystem::path(root_path) / std::filesystem::path(folder_path);
        std::filesystem::path full_path = std::filesystem::weakly_canonical(weak_path);

        if (full_path.string().rfind(root_path) != 0) {
            luaL::error(L, "fs.rmdir, attempt to escape directory");
            return 0;
        }

        std::error_code ec;
        std::uintmax_t count = std::filesystem::remove_all(full_path, ec);
        lua::pushboolean(L, !ec && count > 0);
        return 1;
    }

    bool rmfile(const std::string& file_path) {
        return std::filesystem::remove(file_path);
    }

    int rmfile(lua_State* L) {
        std::string file_path = luaL::checkcstring(L, 1);
        std::filesystem::path weak_path = std::filesystem::path(root_path) / std::filesystem::path(file_path);
        std::filesystem::path full_path = std::filesystem::weakly_canonical(weak_path);

        if (full_path.string().rfind(root_path) != 0) {
            luaL::error(L, "fs.rmfile, attempt to escape directory");
            return 0;
        }

        std::error_code ec;
        bool err = std::filesystem::remove(full_path, ec);
        lua::pushboolean(L, !ec && !err);
        return 1;
    }

    bool rm(const std::string& path) {
        std::error_code ec;
        std::uintmax_t count = std::filesystem::remove_all(path, ec);
        return !ec && count > 0;
    }

    int rm(lua_State* L) {
        std::string file_path = luaL::checkcstring(L, 1);
        std::filesystem::path weak_path = std::filesystem::path(root_path) / std::filesystem::path(file_path);
        std::filesystem::path full_path = std::filesystem::weakly_canonical(weak_path);

        if (full_path.string().rfind(root_path) != 0) {
            luaL::error(L, "fs.rm, attempt to escape directory");
            return 0;
        }

        std::error_code ec;
        std::uintmax_t count = std::filesystem::remove_all(full_path, ec);
        lua::pushboolean(L, !ec && count > 0);
        return 1;
    }

    bool mv(const std::string& from, const std::string& to) {
        std::error_code ec;
        std::filesystem::rename(from, to, ec);
        return !ec;
    }

    int mv(lua_State* L) {
        std::string from_path = luaL::checkcstring(L, 1);
        std::string to_path = luaL::checkcstring(L, 2);

        std::filesystem::path from_weak_path = std::filesystem::path(root_path) / std::filesystem::path(from_path);
        std::filesystem::path from_full_path = std::filesystem::weakly_canonical(from_weak_path);

        if (from_full_path.string().rfind(root_path) != 0) {
            luaL::argerror(L, 1, "fs.mv, attempt to escape directory");
            return 0;
        }

        std::filesystem::path to_weak_path = std::filesystem::path(root_path) / std::filesystem::path(to_path);
        std::filesystem::path to_full_path = std::filesystem::weakly_canonical(to_weak_path);

        if (to_full_path.string().rfind(root_path) != 0) {
            luaL::argerror(L, 2, "fs.mv, attempt to escape directory");
            return 0;
        }

        std::error_code ec;
        std::filesystem::rename(from_full_path, to_full_path, ec);
        lua::pushboolean(L, !ec);
        return 1;
    }

    bool cp(const std::string& from, const std::string& to) {
        std::error_code ec;
        std::filesystem::copy(from, to,
            std::filesystem::copy_options::recursive |
            std::filesystem::copy_options::overwrite_existing,
            ec);
        return !ec;
    }

    int cp(lua_State* L) {
        std::string from_path = luaL::checkcstring(L, 1);
        std::string to_path = luaL::checkcstring(L, 2);

        std::filesystem::path from_weak_path = std::filesystem::path(root_path) / std::filesystem::path(from_path);
        std::filesystem::path from_full_path = std::filesystem::weakly_canonical(from_weak_path);

        if (from_full_path.string().rfind(root_path) != 0) {
            luaL::argerror(L, 1, "fs.cp, attempt to escape directory");
            return 0;
        }

        std::filesystem::path to_weak_path = std::filesystem::path(root_path) / std::filesystem::path(to_path);
        std::filesystem::path to_full_path = std::filesystem::weakly_canonical(to_weak_path);

        if (to_full_path.string().rfind(root_path) != 0) {
            luaL::argerror(L, 2, "fs.cp, attempt to escape directory");
            return 0;
        }

        std::error_code ec;
        std::filesystem::copy(from_full_path, to_full_path,
            std::filesystem::copy_options::recursive |
            std::filesystem::copy_options::overwrite_existing,
            ec);
        lua::pushboolean(L, !ec);
        return 1;
    }

    std::string read(const std::string& file_path) {
        if (!std::filesystem::exists(file_path))
            return "";
        std::ifstream stream(file_path, std::ios_base::binary);
        std::string file_content((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        return file_content;
    }

    std::vector<std::tuple<uintptr_t, int, bool, std::string>> queue_read;
    int read(lua_State* L) {
        std::string file_path = luaL::checkcstring(L, 1);
        std::filesystem::path weak_path = std::filesystem::path(root_path) / std::filesystem::path(file_path);
        std::filesystem::path full_path = std::filesystem::weakly_canonical(weak_path);

        if (full_path.string().rfind(root_path) != 0) {
            luaL::error(L, "fs.read, attempt to escape directory");
            return 0;
        }

        if (!std::filesystem::exists(full_path.string().c_str())) {
            luaL::error(L, "fs.read, file does not exist");
            return 0;
        }

        if (lua::isfunction(L, 2)) {
            int reference = luaL::newref(L, 2);
            uintptr_t id = Tracker::id(L);

            // TODO: use luaL::trace for errors
            std::thread([id, reference, full_path]() {
                std::ifstream stream(full_path, std::ios_base::binary);
                std::string file_content((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
                std::unique_lock<std::mutex> guard(async_lock);
                queue_read.push_back(std::tuple(id, reference, true, file_content));
                guard.unlock();
                }).detach();
            return 0;
        }

        std::ifstream stream(full_path, std::ios_base::binary);
        std::string file_content((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        lua::pushcstring(L, file_content);

        return 1;
    }

    bool write(const std::string& file_path, std::string file_content) {
        std::string extension = path_extension(file_path.c_str());

        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

        for (const std::string& disallowedExtension : disallowedExtensions) {
            if (extension == disallowedExtension) {
                return false;
            }
        }

        std::ofstream outfile(file_path, std::ios::out | std::ios::binary);

        if (!outfile.is_open()) {
            return false;
        }

        outfile.write(file_content.c_str(), file_content.size());
        outfile.close();

        return true;
    }

    std::vector<std::tuple<uintptr_t, int, bool>> queue_write;
    int write(lua_State* L) {
        std::string file_path = luaL::checkcstring(L, 1);
        std::filesystem::path weak_path = std::filesystem::path(root_path) / std::filesystem::path(file_path);
        std::filesystem::path full_path = std::filesystem::weakly_canonical(weak_path);

        if (full_path.string().rfind(root_path) != 0) {
            luaL::error(L, "fs.write, attempt to escape directory");
            return 0;
        }

        std::string file_content;
        if (lua::isstring(L, 2)) {
            file_content = lua::tocstring(L, 2);
        }
        else if (Class::is(L, 2, "buffer")) {
            file_content = ((Buffer::Buffer*)Class::to(L, 2))->to_string();
        }
        else {
            luaL::argerror(L, 2, "expected string or buffer");
            return 0;
        }

        std::string extension = path_extension(full_path.string().c_str());

        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

        for (const std::string& disallowedExtension : disallowedExtensions) {
            if (extension == disallowedExtension) {
                luaL::error(L, "fs.write, forbidden extension");
                return 0;
            }
        }

        if (lua::isfunction(L, 3) || (lua::isboolean(L, 3) && lua::toboolean(L, 3))) {
            int reference = (lua::isboolean(L, 3) && lua::toboolean(L, 3)) ? -1 : luaL::newref(L, 3);
            uintptr_t id = Tracker::id(L);

            // TODO: use luaL::trace for errors
            std::thread([id, reference, full_path, file_content]() {
                std::ofstream outfile(full_path, std::ios::out | std::ios::binary);

                if (!outfile.is_open()) {
                    std::unique_lock<std::mutex> guard(async_lock);
                    queue_write.push_back(std::tuple(id, reference, false));
                    guard.unlock();
                    return 0;
                }

                outfile.write(file_content.c_str(), file_content.size());
                outfile.close();

                std::unique_lock<std::mutex> guard(async_lock);
                queue_write.push_back(std::tuple(id, reference, true));
                guard.unlock();
                }).detach();
        }
        else {
            std::ofstream outfile(full_path, std::ios::out | std::ios::binary);

            if (!outfile.is_open()) {
                luaL::error(L, "fs.write, failed to open file for writing");
                return 0;
            }

            outfile.write(file_content.c_str(), file_content.size());
            outfile.close();
        }

        return 0;
    }

    bool append(const std::string& file_path, std::string file_content) {
        std::string extension = path_extension(file_path.c_str());

        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

        for (const std::string& disallowedExtension : disallowedExtensions) {
            if (extension == disallowedExtension) {
                return false;
            }
        }

        if (!std::filesystem::exists(file_path)) {
            return false;
        }

        std::ofstream outfile(file_path, std::ios::app | std::ios::binary);

        if (!outfile.is_open()) {
            return false;
        }

        outfile.write(file_content.c_str(), file_content.size());
        outfile.close();

        return true;
    }

    std::vector<std::tuple<uintptr_t, int, bool>> queue_append;
    int append(lua_State* L) {
        std::string file_path = luaL::checkcstring(L, 1);
        std::filesystem::path weak_path = std::filesystem::path(root_path) / std::filesystem::path(file_path);
        std::filesystem::path full_path = std::filesystem::weakly_canonical(weak_path);

        if (full_path.string().rfind(root_path) != 0) {
            luaL::error(L, "fs.append, attempt to escape directory");
            return 0;
        }

        std::string file_content;
        if (lua::isstring(L, 2)) {
            file_content = lua::tocstring(L, 2);
        }
        else if (Class::is(L, 2, "buffer")) {
            file_content = ((Buffer::Buffer*)Class::to(L, 2))->to_string();
        }
        else {
            luaL::argerror(L, 2, "expected string or buffer");
            return 0;
        }

        std::string extension = path_extension(full_path.string().c_str());
        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

        for (const std::string& disallowedExtension : disallowedExtensions) {
            if (extension == disallowedExtension) {
                luaL::error(L, "fs.append, forbidden extension");
                return 0;
            }
        }

        if (!std::filesystem::exists(full_path)) {
            luaL::error(L, "fs.append, file does not exist");
            return 0;
        }

        if (lua::isfunction(L, 3) || (lua::isboolean(L, 3) && lua::toboolean(L, 3))) {
            int reference = (lua::isboolean(L, 3) && lua::toboolean(L, 3)) ? -1 : luaL::newref(L, 3);
            uintptr_t id = Tracker::id(L);

            // TODO: use luaL::trace for errors
            std::thread([id, reference, full_path, file_content]() {
                std::ofstream outfile;
                outfile.open(full_path, std::ios_base::app | std::ios_base::binary);

                if (!outfile.is_open()) {
                    std::unique_lock<std::mutex> guard(async_lock);
                    queue_append.push_back(std::tuple(id, reference, false));
                    guard.unlock();
                    return 0;
                }

                outfile.write(file_content.c_str(), file_content.size());
                outfile.close();

                std::unique_lock<std::mutex> guard(async_lock);
                queue_append.push_back(std::tuple(id, reference, true));
                guard.unlock();
            }).detach();

            return 0;
        }
        else {
            std::ofstream outfile;
            outfile.open(full_path, std::ios_base::app | std::ios_base::binary);

            if (!outfile.is_open()) {
                lua::pushboolean(L, false);
                return 1;
            }

            outfile.write(file_content.c_str(), file_content.size());
            outfile.close();
        }

        lua::pushboolean(L, true);
        return 1;
    }

    void runtime_threaded(lua_State* T)
    {
        std::unique_lock<std::mutex> guard(async_lock);

        if (queue_read.size() > 0) {
            for (auto it = queue_read.begin(); it != queue_read.end(); ) {
                auto& result = *it;
                uintptr_t id = std::get<0>(result);
                lua_State* L = Tracker::is_state(id);

                if (L != T) {
                    ++it;
                    continue;
                }

                int reference = std::get<1>(result);
                bool success = std::get<2>(result);
                std::string data = std::get<3>(result);

                if (!success) {
                    auto& on_error = get_on_error();
                    for (auto const& handle : on_error) handle.second(L, "fs.read, failed to open file for reading");
                }
                else if (reference > 0) {
                    lua::pushref(L, reference);
                    lua::pushcstring(L, data);

                    if (lua::tcall(L, 1, 0)) {
                        std::string err = lua::tocstring(L, -1);
                        lua::pop(L);
                        auto& on_error = get_on_error();
                        for (auto const& handle : on_error) handle.second(L, err);
                    }
                }

                if (reference > 0) {
                    luaL::rmref(L, reference);
                }

                it = queue_read.erase(it);
            }
        }

        if (queue_write.size() > 0) {
            for (auto it = queue_write.begin(); it != queue_write.end(); ) {
                auto& result = *it;
                uintptr_t id = std::get<0>(result);
                lua_State* L = Tracker::is_state(id);

                if (L != T) {
                    ++it;
                    continue;
                }

                int reference = std::get<1>(result);
                bool success = std::get<2>(result);

                if (!success) {
                    auto& on_error = get_on_error();
                    for (auto const& handle : on_error) handle.second(L, "fs.write, failed to open file for writing");
                }
                else if (reference > 0) {
                    lua::pushref(L, reference);

                    if (lua::tcall(L, 0, 0)) {
                        std::string err = lua::tocstring(L, -1);
                        lua::pop(L);
                        auto& on_error = get_on_error();
                        for (auto const& handle : on_error) handle.second(L, err);
                    }
                }

                if (reference > 0) {
                    luaL::rmref(L, reference);
                }

                it = queue_write.erase(it);
            }
        }

        if (queue_append.size() > 0) {
            for (auto it = queue_append.begin(); it != queue_append.end(); ) {
                auto& result = *it;
                uintptr_t id = std::get<0>(result);
                lua_State* L = Tracker::is_state(id);

                if (L != T) {
                    ++it;
                    continue;
                }

                int reference = std::get<1>(result);
                bool success = std::get<2>(result);

                if (!success) {
                    auto& on_error = get_on_error();
                    for (auto const& handle : on_error) handle.second(L, "fs.append, failed to open file for appending");
                }
                else if (reference > 0) {
                    lua::pushref(L, reference);

                    if (lua::tcall(L, 0, 0)) {
                        std::string err = lua::tocstring(L, -1);
                        lua::pop(L);
                        auto& on_error = get_on_error();
                        for (auto const& handle : on_error) handle.second(L, err);
                    }
                }

                if (reference > 0) {
                    luaL::rmref(L, reference);
                }

                it = queue_append.erase(it);
            }
        }

        guard.unlock();
    }

    void runtime()
    {
        std::unique_lock<std::mutex> guard(async_lock);

        if (queue_read.size() > 0) {
            for (auto it = queue_read.begin(); it != queue_read.end(); ) {
                auto& result = *it;
                uintptr_t id = std::get<0>(result);
                lua_State* L = Tracker::is_state(id);

                if (L == nullptr || Tracker::is_threaded(L)) {
                    ++it;
                    continue;
                }

                int reference = std::get<1>(result);
                bool success = std::get<2>(result);
                std::string data = std::get<3>(result);

                if (!success) {
                    auto& on_error = get_on_error();
                    for (auto const& handle : on_error) handle.second(L, "fs.read, failed to open file for reading");
                }
                else if (reference > 0) {
                    lua::pushref(L, reference);
                    lua::pushcstring(L, data);

                    if (lua::tcall(L, 1, 0)) {
                        std::string err = lua::tocstring(L, -1);
                        lua::pop(L);
                        auto& on_error = get_on_error();
                        for (auto const& handle : on_error) handle.second(L, err);
                    }
                }

                if (reference > 0) {
                    luaL::rmref(L, reference);
                }

                it = queue_read.erase(it);
            }
        }

        if (queue_write.size() > 0) {
            for (auto it = queue_write.begin(); it != queue_write.end(); ) {
                auto& result = *it;
                uintptr_t id = std::get<0>(result);
                lua_State* L = Tracker::is_state(id);

                if (L == nullptr || Tracker::is_threaded(L)) {
                    ++it;
                    continue;
                }

                int reference = std::get<1>(result);
                bool success = std::get<2>(result);

                if (!success) {
                    auto& on_error = get_on_error();
                    for (auto const& handle : on_error) handle.second(L, "fs.write, failed to open file for writing");
                }
                else if (reference > 0) {
                    lua::pushref(L, reference);

                    if (lua::tcall(L, 0, 0)) {
                        std::string err = lua::tocstring(L, -1);
                        lua::pop(L);
                        auto& on_error = get_on_error();
                        for (auto const& handle : on_error) handle.second(L, err);
                    }
                }

                if (reference > 0) {
                    luaL::rmref(L, reference);
                }

                it = queue_write.erase(it);
            }
        }

        if (queue_append.size() > 0) {
            for (auto it = queue_append.begin(); it != queue_append.end(); ) {
                auto& result = *it;
                uintptr_t id = std::get<0>(result);
                lua_State* L = Tracker::is_state(id);

                if (L == nullptr || Tracker::is_threaded(L)) {
                    ++it;
                    continue;
                }

                int reference = std::get<1>(result);
                bool success = std::get<2>(result);

                if (!success) {
                    auto& on_error = get_on_error();
                    for (auto const& handle : on_error) handle.second(L, "fs.append, failed to open file for appending");
                }
                else if (reference > 0) {
                    lua::pushref(L, reference);

                    if (lua::tcall(L, 0, 0)) {
                        std::string err = lua::tocstring(L, -1);
                        lua::pop(L);
                        auto& on_error = get_on_error();
                        for (auto const& handle : on_error) handle.second(L, err);
                    }
                }

                if (reference > 0) {
                    luaL::rmref(L, reference);
                }

                it = queue_append.erase(it);
            }
        }

        guard.unlock();
    }

    void push(lua_State* L, UMODULE handle) {
        lua::newtable(L);

        lua::pushcstring(L, std::string(1, (char)std::filesystem::path::preferred_separator));
        lua::setfield(L, -2, "separator");

        lua::pushcfunction(L, read);
        lua::setfield(L, -2, "read");

        lua::pushcfunction(L, write);
        lua::setfield(L, -2, "write");

        lua::pushcfunction(L, isfile);
        lua::setfield(L, -2, "isfile");

        lua::pushcfunction(L, isfolder);
        lua::setfield(L, -2, "isfolder");

        lua::pushcfunction(L, readable);
        lua::setfield(L, -2, "readable");

        lua::pushcfunction(L, writeable);
        lua::setfield(L, -2, "writeable");

        lua::pushcfunction(L, scan);
        lua::setfield(L, -2, "scan");

        lua::pushcfunction(L, mkdir);
        lua::setfield(L, -2, "mkdir");

        lua::pushcfunction(L, rmdir);
        lua::setfield(L, -2, "rmdir");

        lua::pushcfunction(L, rmfile);
        lua::setfield(L, -2, "rmfile");

        lua::pushcfunction(L, rm);
        lua::setfield(L, -2, "rm");

        lua::pushcfunction(L, mv);
        lua::setfield(L, -2, "mv");

        lua::pushcfunction(L, cp);
        lua::setfield(L, -2, "cp");

        lua::pushcfunction(L, sanitize);
        lua::setfield(L, -2, "sanitize");

        lua::pushcfunction(L, extname);
        lua::setfield(L, -2, "extname");

        lua::pushcfunction(L, filename);
        lua::setfield(L, -2, "filename");

        lua::pushcfunction(L, dirname);
        lua::setfield(L, -2, "dirname");

        lua::pushcfunction(L, join);
        lua::setfield(L, -2, "join");

        lua::pushcfunction(L, forward);
        lua::setfield(L, -2, "forward");

        lua::pushcfunction(L, backward);
        lua::setfield(L, -2, "backward");

        lua::pushcfunction(L, within);
        lua::setfield(L, -2, "within");

        lua::pushcfunction(L, canonical);
        lua::setfield(L, -2, "canonical");
    }

    void api(std::string root) {
        root_path = (root.size() > 0 ? root : where());
        Reflection::on_threaded("fs", runtime_threaded);
        Reflection::on_runtime("fs", runtime);
        Reflection::add("fs", push);
    }
}