#pragma once
#include "interstellar.hpp"
#include <filesystem>

// Interstellar: File System
// Allows for filesystem access (under a certain directory however)
namespace INTERSTELLAR_NAMESPACE::FS
{
    template <typename... Args>
    std::string join(Args&&... args) {
        return (std::filesystem::path{} / ... / args).string();
    }

    extern std::string get_root();
    extern bool within(std::string root_path, std::string file_path);
    extern std::string localize(std::string root_path, std::string file_path);
    extern std::string forward(std::string path);
    extern std::string backward(std::string path);
    extern std::string extname(std::string path);
    extern std::string extname(std::string path, std::string replace);
    extern std::string filename(std::string path);
    extern std::string filename(std::string path, std::string replace);
    extern std::string dirname(std::string path);
    extern std::string dirname(std::string path, std::string replace);
    extern std::string sanitize(std::string input);
    extern bool isfile(std::string file_path);
    extern bool isfolder(std::string folder_path);
    extern bool makefolder(std::string folder_path);
    extern bool delfolder(std::string folder_path);
    extern bool delfile(std::string file_path);
    extern std::string read(std::string file_path);
    extern bool write(std::string file_path, std::string file_content);
    extern bool append(std::string file_path, std::string file_content);

    extern void push(API::lua_State* L, UMODULE hndle);
    extern void api(std::string root_path = "");
}