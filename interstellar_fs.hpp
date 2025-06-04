#pragma once
#include "interstellar.hpp"
#include <filesystem>

// Interstellar: File System
// Allows for filesystem access (under a certain directory however)
namespace INTERSTELLAR_NAMESPACE::FS {
    typedef void (*lua_FS_Error) (API::lua_State* L, std::string error);
    extern void add_error(std::string name, lua_FS_Error callback);
    extern void remove_error(std::string name);

    template <typename... Args>
    std::string join(Args&&... args) {
        return (std::filesystem::path{} / ... / args).string();
    }

    extern std::string pwd();
    extern std::string where();
    extern bool within(const std::string& root_path, const std::string& file_path);
    extern std::string localize(const std::string& root_path, const std::string& file_path);
    extern std::string forward(std::string path);
    extern std::string backward(std::string path);
    extern std::string extname(const std::string& path);
    extern std::string extname(const std::string& path, const std::string& replace);
    extern std::string filename(const std::string& path);
    extern std::string filename(const std::string& path, const std::string& replace);
    extern std::string dirname(const std::string& path);
    extern std::string dirname(const std::string& path, const std::string& replace);
    extern std::string sanitize(const std::string& input);
    extern bool isfile(const std::string& file_path);
    extern bool isfolder(const std::string& folder_path);
    extern bool mkdir(const std::string& folder_path);
    extern bool rmdir(const std::string& folder_path);
    extern bool rmfile(const std::string& file_path);
    extern bool rm(const std::string& file_path);
    extern bool mv(const std::string& from, const std::string& to);
    extern bool cp(const std::string& from, const std::string& to);
    extern std::string read(const std::string& file_path);
    extern bool write(const std::string& file_path, std::string file_content);
    extern bool append(const std::string& file_path, std::string file_content);

    extern void push(API::lua_State* L, UMODULE hndle);
    extern void api(std::string root_path = "");
}