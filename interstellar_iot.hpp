#pragma once
#include "interstellar.hpp"
#include <ixwebsocket/IXWebSocket.h>
#include <queue>

// Interstellar: IOT
// Create connections to the internet
namespace INTERSTELLAR_NAMESPACE::IOT {
    class CSocket {
    public:
        CSocket(const std::string& url);
        CSocket(const std::string& url, std::map<std::string, std::string> headers_);
        ~CSocket();

        void headers_add(std::string& key, std::string& value);
        void headers_remove(std::string& key);
        std::string headers_get(std::string& key);
        std::map<std::string, std::string> headers_all();

        void connect(int timeout = 15);
        void disconnect(const std::string& reason = "");
        void text(const std::string& payload);
        void utf8(const std::string& payload);
        void binary(const std::string& payload);
        void ping(const std::string& payload = "");
        void ping_interval(int sec);
        void ping_message(const std::string& payload = "");

        bool is_open() const;
        bool is_closing() const;
        bool is_closed() const;
        bool is_connecting() const;
        bool is_tls() const;
        std::string get_host() const;
        std::string get_port() const;
        std::string get_path() const;
        std::string get_url() const;

        void dethreader();
    protected:
        virtual void on_message(const std::string& message, bool is_binary);
        virtual void on_open();
        virtual void on_close(uint16_t code, const std::string& reason);
        virtual void on_error(int status, const std::string& reason);
        virtual void on_ping(const std::string& message);
        virtual void on_pong(const std::string& message);

    private:
        static std::string parse_host(const std::string& url);
        static std::string parse_port(const std::string& url);
        static std::string parse_path(const std::string& url);

        std::string url;
        std::string host;
        std::string port;
        std::string path;

        ix::WebSocketHttpHeaders headers;
        ix::WebSocket socket;

        std::thread ws_thread;
        std::mutex queue_mutex;
        std::queue<std::function<void()>> event_queue;
    };

    typedef void (*lua_IOT_Error) (API::lua_State* L, std::string url, std::string error);
    extern void add_error(std::string name, lua_IOT_Error callback);
    extern void remove_error(std::string name);

    extern void runtime();
    extern void push(API::lua_State* L, UMODULE hndle);
    extern void api();
}