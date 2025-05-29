#include <string.h>
#include "interstellar_lxz.hpp"
#pragma comment (lib, "zlib.Lib")
#pragma comment (lib, "Zstd.Lib")
#pragma comment (lib, "BZ2.Lib")
#pragma comment (lib, "LZMA.Lib")
#include <bxzstr/bxzstr.hpp>
#include <unordered_map>
#include <istream>
#include <ostream>
#include <iostream>
#include <sstream>
#include <streambuf>
#include <thread>
#include <mutex>
#include <queue>
#include <map>

namespace INTERSTELLAR_NAMESPACE::LXZ {
    using namespace Interstellar;
    using namespace Interstellar::API;
    std::vector<std::tuple<uintptr_t, int, std::string>> queue;
    std::mutex dethread_lock;

    std::unordered_map<std::string, lua_LXZ_Error>& get_on_error()
    {
        static std::unordered_map<std::string, lua_LXZ_Error> m;
        return m;
    }

    void add_error(std::string name, lua_LXZ_Error callback)
    {
        auto& on_error = get_on_error();
        on_error.emplace(name, callback);
    }

    void remove_error(std::string name)
    {
        auto& on_error = get_on_error();
        on_error.erase(name);
    }

    void runtime_threaded(lua_State* T)
    {
        std::unique_lock<std::mutex> lock_guard(dethread_lock);

        if (queue.size() > 0) {
            for (auto it = queue.begin(); it != queue.end(); ) {
                auto& result = *it;
                uintptr_t id = std::get<0>(result);
                lua_State* L = Tracker::is_state(id);

                if (L != T) {
                    ++it;
                    continue;
                }

                int reference = std::get<1>(result);
                std::string data = std::get<2>(result);

                lua::pushref(L, reference);
                lua::pushcstring(L, data);

                if (lua::tcall(L, 1, 0)) {
                    std::string err = lua::tocstring(L, -1);
                    lua::pop(L);
                    auto& on_error = get_on_error();
                    for (auto const& handle : on_error) handle.second(L, err);
                }

                luaL::rmref(L, reference);

                it = queue.erase(it);
            }
        }

        lock_guard.unlock();
    }

    void runtime()
    {
        std::unique_lock<std::mutex> lock_guard(dethread_lock);

        if (queue.size() > 0) {
            for (auto it = queue.begin(); it != queue.end(); ) {
                auto& result = *it;
                uintptr_t id = std::get<0>(result);
                lua_State* L = Tracker::is_state(id);

                if (L == nullptr || Tracker::is_threaded(L)) {
                    ++it;
                    continue;
                }

                int reference = std::get<1>(result);
                std::string data = std::get<2>(result);

                lua::pushref(L, reference);
                lua::pushcstring(L, data);

                if (lua::tcall(L, 1, 0)) {
                    std::string err = lua::tocstring(L, -1);
                    lua::pop(L);
                    auto& on_error = get_on_error();
                    for (auto const& handle : on_error) handle.second(L, err);
                }

                luaL::rmref(L, reference);

                it = queue.erase(it);
            }
        }

        lock_guard.unlock();
    }

    int lua_z_compress(lua_State* L) {
        std::string input = lua::tocstring(L, 1);

        if (lua::isfunction(L, 2)) {
            int reference = luaL::newref(L, 2);

            std::thread([L, reference, input]() {
                std::lock_guard<std::mutex> lock(dethread_lock);
                try {
                    std::ostringstream compressed_stream;
                    {
                        bxz::ostream z_out(compressed_stream, bxz::z);
                        z_out << input;
                    }
                    queue.push_back(std::tuple((uintptr_t)L, reference, compressed_stream.str()));
                }
                catch (const std::exception& e) {
                    if (Tracker::is_state(L) != nullptr) {
                        queue.push_back(std::tuple((uintptr_t)L, reference, ""));
                    }
                }
                catch (...) {
                    if (Tracker::is_state(L) != nullptr) {
                        queue.push_back(std::tuple((uintptr_t)L, reference, ""));
                    }
                }
                }).detach();

            return 0;
        }

        try {
            std::ostringstream compressed_stream;
            {
                bxz::ostream z_out(compressed_stream, bxz::z);
                z_out << input;
            }

            lua::pushcstring(L, compressed_stream.str());
            return 1;
        }
        catch (const std::exception& e) {
            return luaL::error(L, "Z compression failed: %s", e.what());
        }
        catch (...) {
            return luaL::error(L, "Z compression failed: Unknown error");
        }
    }

    int lua_zstd_compress(lua_State* L) {
        std::string input = lua::tocstring(L, 1);

        if (lua::isfunction(L, 2)) {
            int reference = luaL::newref(L, 2);

            std::thread([L, reference, input]() {
                std::lock_guard<std::mutex> lock(dethread_lock);
                try {
                    std::ostringstream compressed_stream;
                    {
                        bxz::ostream zstd_out(compressed_stream, bxz::zstd);
                        zstd_out << input;
                    }
                    queue.push_back(std::tuple((uintptr_t)L, reference, compressed_stream.str()));
                }
                catch (const std::exception& e) {
                    if (Tracker::is_state(L) != nullptr) {
                        queue.push_back(std::tuple((uintptr_t)L, reference, ""));
                    }
                }
                catch (...) {
                    if (Tracker::is_state(L) != nullptr) {
                        queue.push_back(std::tuple((uintptr_t)L, reference, ""));
                    }
                }
                }).detach();

            return 0;
        }

        try {
            std::ostringstream compressed_stream;
            {
                bxz::ostream zstd_out(compressed_stream, bxz::zstd);
                zstd_out << input;
            }

            lua::pushcstring(L, compressed_stream.str());
            return 1;
        }
        catch (const std::exception& e) {
            return luaL::error(L, "ZSTD compression failed: %s", e.what());
        }
        catch (...) {
            return luaL::error(L, "ZSTD compression failed: Unknown error");
        }
    }

    int lua_bz2_compress(lua_State* L) {
        std::string input = lua::tocstring(L, 1);

        if (lua::isfunction(L, 2)) {
            int reference = luaL::newref(L, 2);

            std::thread([L, reference, input]() {
                std::lock_guard<std::mutex> lock(dethread_lock);
                try {
                    std::ostringstream compressed_stream;
                    {
                        bxz::ostream bz2_out(compressed_stream, bxz::bz2);
                        bz2_out << input;
                    }
                    queue.push_back(std::tuple((uintptr_t)L, reference, compressed_stream.str()));
                }
                catch (const std::exception& e) {
                    if (Tracker::is_state(L) != nullptr) {
                        queue.push_back(std::tuple((uintptr_t)L, reference, ""));
                    }
                }
                catch (...) {
                    if (Tracker::is_state(L) != nullptr) {
                        queue.push_back(std::tuple((uintptr_t)L, reference, ""));
                    }
                }
                }).detach();

            return 0;
        }

        try {
            std::ostringstream compressed_stream;
            {
                bxz::ostream bz2_out(compressed_stream, bxz::bz2);
                bz2_out << input;
            }

            lua::pushcstring(L, compressed_stream.str());
            return 1;
        }
        catch (const std::exception& e) {
            return luaL::error(L, "BZ2 compression failed: %s", e.what());
        }
        catch (...) {
            return luaL::error(L, "BZ2 compression failed: Unknown error");
        }
    }

    int lua_lzma_compress(lua_State* L) {
        std::string input = lua::tocstring(L, 1);

        if (lua::isfunction(L, 2)) {
            int reference = luaL::newref(L, 2);

            std::thread([L, reference, input]() {
                std::lock_guard<std::mutex> lock(dethread_lock);
                try {
                    std::ostringstream compressed_stream;
                    {
                        bxz::ostream lzma_out(compressed_stream, bxz::lzma);
                        lzma_out << input;
                    }
                    queue.push_back(std::tuple((uintptr_t)L, reference, compressed_stream.str()));
                }
                catch (const std::exception& e) {
                    if (Tracker::is_state(L) != nullptr) {
                        queue.push_back(std::tuple((uintptr_t)L, reference, ""));
                    }
                }
                catch (...) {
                    if (Tracker::is_state(L) != nullptr) {
                        queue.push_back(std::tuple((uintptr_t)L, reference, ""));
                    }
                }
                }).detach();

            return 0;
        }

        try {
            std::ostringstream compressed_stream;
            {
                bxz::ostream lzma_out(compressed_stream, bxz::lzma);
                lzma_out << input;
            }

            lua::pushcstring(L, compressed_stream.str());
            return 1;
        }
        catch (const std::exception& e) {
            return luaL::error(L, "LZMA compression failed: %s", e.what());
        }
        catch (...) {
            return luaL::error(L, "LZMA compression failed: Unknown error");
        }
    }

    int lua_decompress(lua_State* L) {
        std::string input = lua::tocstring(L, 1);

        if (lua::isfunction(L, 2)) {
            int reference = luaL::newref(L, 2);

            std::thread([L, reference, input]() {
                std::lock_guard<std::mutex> lock(dethread_lock);
                try {
                    std::istringstream compressed_input(input);
                    std::ostringstream decompressed_stream;
                    {
                        bxz::istream data_in(compressed_input);
                        decompressed_stream << data_in.rdbuf();
                    }
                    queue.push_back(std::tuple((uintptr_t)L, reference, decompressed_stream.str()));
                }
                catch (const std::exception& e) {
                    if (Tracker::is_state(L) != nullptr) {
                        queue.push_back(std::tuple((uintptr_t)L, reference, ""));
                    }
                }
                catch (...) {
                    if (Tracker::is_state(L) != nullptr) {
                        queue.push_back(std::tuple((uintptr_t)L, reference, ""));
                    }
                }
                }).detach();

            return 0;
        }

        try {
            std::istringstream compressed_input(input);
            std::ostringstream decompressed_stream;
            {
                bxz::istream data_in(compressed_input);
                decompressed_stream << data_in.rdbuf();
            }

            lua::pushcstring(L, decompressed_stream.str());
            return 1;
        }
        catch (const std::exception& e) {
            return luaL::error(L, "Decompression failed: %s", e.what());
        }
        catch (...) {
            return luaL::error(L, "Decompression failed: Unknown error");
        }
    }

    void push(API::lua_State* L, UMODULE hndle) {
        lua::newtable(L);

        lua::newtable(L);

        lua::pushcfunction(L, lua_z_compress);
        lua::setfield(L, -2, "z");

        lua::pushcfunction(L, lua_zstd_compress);
        lua::setfield(L, -2, "zstd");

        lua::pushcfunction(L, lua_bz2_compress);
        lua::setfield(L, -2, "bz2");

        lua::pushcfunction(L, lua_lzma_compress);
        lua::setfield(L, -2, "lzma");

        lua::setfield(L, -2, "encode");

        lua::newtable(L);

        lua::pushcfunction(L, lua_decompress);
        lua::setfield(L, -2, "z");

        lua::pushcfunction(L, lua_decompress);
        lua::setfield(L, -2, "zstd");

        lua::pushcfunction(L, lua_decompress);
        lua::setfield(L, -2, "bz2");

        lua::pushcfunction(L, lua_decompress);
        lua::setfield(L, -2, "lzma");

        lua::setfield(L, -2, "decode");
    }

    void api() {
        Reflection::on_threaded("lxz", runtime_threaded);
        Reflection::on_runtime("lxz", runtime);
        Reflection::add("lxz", push);
    }
}