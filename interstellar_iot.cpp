#define FMT_UNICODE 0
#include <restinio/core.hpp>
#include <restinio/websocket/websocket.hpp>
#include "interstellar_iot.hpp"
#include "interstellar_signal.hpp"

#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <map>
#include <unordered_map>
#include <functional>
#include <vector>
#include <algorithm>

#pragma comment (lib, "Ws2_32.Lib")
#pragma comment (lib, "Wldap32.Lib")
#pragma comment (lib, "Crypt32.Lib")
#include <cpr/cpr.h>
#pragma comment (lib, "cpr.Lib")
#pragma comment (lib, "libcurl.Lib")
#pragma comment (lib, "libcrypto.lib")
#pragma comment (lib, "libssl.lib")
#pragma comment (lib, "zlib.Lib")
#pragma comment (lib, "ixwebsocket.lib")
#pragma comment (lib, "mbedtls.lib")
#pragma comment (lib, "mbedx509.lib")
#pragma comment (lib, "mbedcrypto.lib")
#pragma comment (lib, "llhttp.lib")
#pragma comment (lib, "fmt.lib")

namespace INTERSTELLAR_NAMESPACE::IOT {
    using namespace API;
    
    CSocket::CSocket(const std::string& url) : url(url), host(parse_host(url)), port(parse_port(url)), path(parse_path(url)) {
        socket.setUrl(this->url);
        socket.enablePong();
        socket.setPingInterval(30);
        socket.setHandshakeTimeout(15);
        socket.disableAutomaticReconnection();
        socket.setOnMessageCallback([this](const ix::WebSocketMessagePtr& msg) {
            std::lock_guard<std::mutex> lock(this->queue_mutex);
            if (msg->type == ix::WebSocketMessageType::Message) {
                std::string message = msg->str;
                bool is_binary = msg->binary;
                this->event_queue.push([this, message, is_binary]() { on_message(message, is_binary); });
            }
            else if (msg->type == ix::WebSocketMessageType::Open) {
                this->event_queue.push([this]() { on_open(); });
            }
            else if (msg->type == ix::WebSocketMessageType::Close) {
                uint16_t code = msg->closeInfo.code;
                std::string reason = msg->closeInfo.reason;
                this->event_queue.push([this, code, reason]() { on_close(code, reason); });
            }
            else if (msg->type == ix::WebSocketMessageType::Error) {
                int status = msg->errorInfo.http_status;
                std::string reason = msg->errorInfo.reason;
                this->event_queue.push([this, status, reason]() { on_error(status, reason); });
            }
            else if (msg->type == ix::WebSocketMessageType::Ping) {
                std::string message = msg->str;
                this->event_queue.push([this, message]() { on_ping(message); });
            }
            else if (msg->type == ix::WebSocketMessageType::Pong) {
                std::string message = msg->str;
                this->event_queue.push([this, message]() { on_pong(message); });
            }
        });
    }

    CSocket::CSocket(const std::string& url, std::map<std::string, std::string> headers_) : CSocket(url) {
        for (auto& header : headers_) {
            this->headers.emplace(header.first, header.second);
        }
        socket.setExtraHeaders(this->headers);
    }

    CSocket::~CSocket() {
        disconnect();
        socket.stop();
        if (ws_thread.joinable()) ws_thread.join();
    }

    void CSocket::headers_add(std::string& key, std::string& value) {
        headers.emplace(key, value);
        socket.setExtraHeaders(this->headers);
    }

    void CSocket::headers_remove(std::string& key) {
        headers.erase(key);
        socket.setExtraHeaders(this->headers);
    }

    std::string CSocket::headers_get(std::string& key) {
        if (headers.find(key) != headers.end()) {
            return headers[key];
        }
        return "";
    }

    std::map<std::string, std::string> CSocket::headers_all() {
        std::map<std::string, std::string> list;
        for (auto& header : headers) {
            list.emplace(header.first, header.second);
        }
        return list;
    }

    void CSocket::connect(int timeout) {
        if (is_open() || is_connecting() || is_closing()) return;
        std::thread([this, timeout]() {
            socket.connect(timeout);
            ws_thread = std::thread([this]() { socket.run(); });
        }).detach();
    }

    void CSocket::disconnect(const std::string& reason) {
        if (!is_open() && !is_connecting()) return;
        socket.close(ix::WebSocketCloseConstants::kNormalClosureCode, reason);
    }

    void CSocket::text(const std::string& payload) {
        if (!is_open()) return;
        socket.sendText(payload);
    }

    void CSocket::utf8(const std::string& payload) {
        if (!is_open()) return;
        socket.sendUtf8Text(payload);
    }

    void CSocket::binary(const std::string& payload) {
        if (!is_open()) return;
        socket.sendBinary(payload);
    }

    void CSocket::ping(const std::string& payload) {
        if (!is_open()) return;
        socket.ping(payload);
    }

    void CSocket::ping_interval(int sec) {
        socket.setPingInterval(sec);
    }

    void CSocket::ping_message(const std::string& message) {
        socket.setPingMessage(message);
    }

    bool CSocket::is_open() const { return socket.getReadyState() == ix::ReadyState::Open; }
    bool CSocket::is_closing() const { return socket.getReadyState() == ix::ReadyState::Closing; }
    bool CSocket::is_closed() const { return socket.getReadyState() == ix::ReadyState::Closed; }
    bool CSocket::is_connecting() const { return socket.getReadyState() == ix::ReadyState::Connecting; }
    bool CSocket::is_tls() const { return url.find("wss") == 0 ? true : false; }

    std::string CSocket::get_host() const { return host; }
    std::string CSocket::get_port() const { return port; }
    std::string CSocket::get_path() const { return path; }
    std::string CSocket::get_url() const { return url; }

    void CSocket::on_message(const std::string& message, bool is_binary) {}
    void CSocket::on_open() {}
    void CSocket::on_close(uint16_t code, const std::string& reason) {}
    void CSocket::on_error(int status, const std::string& reason) {}
    void CSocket::on_ping(const std::string& message) {}
    void CSocket::on_pong(const std::string& message) {}

    void CSocket::dethreader() {
        std::lock_guard<std::mutex> lock(queue_mutex);
        while (!event_queue.empty()) {
            event_queue.front()();
            event_queue.pop();
        }
    }

    std::string CSocket::parse_host(const std::string& url) {
        auto start = url.find("//") + 2;
        auto end = url.find("/", start);
        auto host_port = url.substr(start, end - start);

        auto colon_pos = host_port.find(":");
        return (colon_pos != std::string::npos) ? host_port.substr(0, colon_pos) : host_port;
    }
    std::string CSocket::parse_port(const std::string& url) {
        auto scheme_end = url.find("://");
        if (scheme_end == std::string::npos) return "";

        std::string scheme = url.substr(0, scheme_end);
        auto start = scheme_end + 3;
        auto end = url.find("/", start);
        std::string host_port = url.substr(start, end - start);

        auto colon_pos = host_port.find(":");
        if (colon_pos != std::string::npos) {
            return host_port.substr(colon_pos + 1);
        }
        else {
            return (scheme == "wss") ? "443" : "80";
        }
    }
    std::string CSocket::parse_path(const std::string& url) {
        auto start = url.find("//") + 2;
        auto path_start = url.find("/", start);
        return path_start != std::string::npos ? url.substr(path_start) : "/";
    }

    std::unordered_map<std::string, lua_IOT_Error>& get_on_error()
    {
        static std::unordered_map<std::string, lua_IOT_Error> m;
        return m;
    }

    void add_error(std::string name, lua_IOT_Error callback)
    {
        auto& on_error = get_on_error();
        on_error.emplace(name, callback);
    }

    void remove_error(std::string name)
    {
        auto& on_error = get_on_error();
        on_error.erase(name);
    }

    std::vector<std::pair<uintptr_t, int>> progress_cancel;
    std::mutex progress_cancel_lock;

    std::vector<std::tuple<uintptr_t, int, std::string, cpr::cpr_off_t, cpr::cpr_off_t, cpr::cpr_off_t, cpr::cpr_off_t>> http_progress;
    std::mutex http_progress_lock;

    std::vector<std::tuple<uintptr_t, int, cpr::Response>> http_responses;
    std::mutex http_response_lock;

    std::queue<std::tuple<uintptr_t, int, int, std::string, std::string, cpr::Body, cpr::Header, cpr::Parameters>> http_queue;
    std::mutex http_queue_lock;
    
    constexpr int http_max_threads = 4;
    std::atomic<unsigned int> http_threads = 0;

    void http_worker()
    {
        while (true) {
            std::unique_lock<std::mutex> lock(http_queue_lock);

            if (http_queue.empty()) {
                http_threads--;
                lock.unlock();
                break;
            }

            auto [id, reference, reference_progress, url, method, body, headers, params] = http_queue.front();
            http_queue.pop();
            lock.unlock();

            cpr::cpr_off_t last_downloadTotal = 0, last_downloadNow = 0, last_uploadTotal = 0, last_uploadNow = 0;

            cpr::ProgressCallback progress = cpr::ProgressCallback([&](cpr::cpr_off_t downloadTotal, cpr::cpr_off_t downloadNow, cpr::cpr_off_t uploadTotal, cpr::cpr_off_t uploadNow, intptr_t) {
                if (reference_progress == 0) return true;
                std::lock_guard<std::mutex> cancel_lock_guard(progress_cancel_lock);
                if (!progress_cancel.empty()) {
                    for (auto& cancel : progress_cancel) {
                        if (cancel.first == id && cancel.second == reference) {
                            return false;
                        }
                    }
                }

                if (last_downloadTotal == downloadTotal && last_downloadNow == downloadNow && last_uploadTotal == uploadTotal && last_uploadNow == uploadNow) {
                    return true;
                }

                last_downloadTotal = downloadTotal;
                last_downloadNow = downloadNow;
                last_uploadTotal = uploadTotal;
                last_uploadNow = uploadNow;

                std::lock_guard<std::mutex> http_lock_guard(http_progress_lock);

                if (Tracker::is_state(id)) {
                    http_progress.emplace_back(std::tuple<uintptr_t, int, std::string, cpr::cpr_off_t, cpr::cpr_off_t, cpr::cpr_off_t, cpr::cpr_off_t>(
                        id, reference_progress, url,
                        downloadTotal,
                        downloadNow,
                        uploadTotal,
                        uploadNow
                    ));
                }

                return true;
            });

            cpr::Response response;
            if (method == "post") {
                response = cpr::Post(cpr::Url{ url }, body, params, headers, progress);
            }
            else if (method == "get") {
                response = cpr::Get(cpr::Url{ url }, params, headers, progress);
            }
            else if (method == "put") {
                response = cpr::Put(cpr::Url{ url }, body, params, headers, progress);
            }
            else if (method == "delete") {
                response = cpr::Delete(cpr::Url{ url }, params, headers, progress);
            }
            else if (method == "patch") {
                response = cpr::Patch(cpr::Url{ url }, body, params, headers, progress);
            }

            if (reference_progress != 0) {
                std::lock_guard<std::mutex> http_lock_guard(http_progress_lock);
                if (Tracker::is_state(id)) {
                    http_progress.emplace_back(std::tuple<uintptr_t, int, std::string, cpr::cpr_off_t, cpr::cpr_off_t, cpr::cpr_off_t, cpr::cpr_off_t>(
                        id, reference_progress, url,
                        -1,
                        -1,
                        -1,
                        -1
                    ));
                }
            }

            std::lock_guard<std::mutex> http_lock_guard(http_response_lock);
            http_responses.emplace_back(id, reference, response);
        }
    }

    int http(lua_State* L)
    {
        uintptr_t id = Tracker::id(L);

        std::string url = luaL::checkcstring(L, 1);
        luaL::checkfunction(L, 2);
        int reference = luaL::newref(L, 2);
        int reference_progress = 0;

        std::string method = "get";
        cpr::Body body = "";
        cpr::Header headers;
        cpr::Parameters params;

        if (lua::istable(L, 3)) {
            lua::getfield(L, 3, "method");
            if (lua::isstring(L, -1)) {
                method = lua::tocstring(L, -1);
            }
            lua::pop(L);

            lua::getfield(L, 3, "headers");
            if (lua::istable(L, -1)) {
                lua::pushnil(L);
                while (lua::next(L, -2) != 0)
                {
                    headers.emplace(luaL::checkcstring(L, -2), luaL::checkcstring(L, -1));
                    lua::pop(L);
                }
            }
            lua::pop(L);

            lua::getfield(L, 3, "parameters");
            if (lua::istable(L, -1)) {
                lua::pushnil(L);
                while (lua::next(L, -2) != 0)
                {
                    params.Add({ luaL::checkcstring(L, -2), luaL::checkcstring(L, -1) });
                    lua::pop(L);
                }
            }
            lua::pop(L);

            lua::getfield(L, 3, "body");
            if (lua::isstring(L, -1)) {
                body = lua::tocstring(L, -1);
            }
            lua::pop(L);

            lua::getfield(L, 3, "progress");
            if (lua::isfunction(L, -1)) {
                reference_progress = luaL::newref(L, -1);
            }
            lua::pop(L);
        }

        std::lock_guard<std::mutex> lock(http_queue_lock);
        http_queue.emplace(id, reference, reference_progress, url, method, body, headers, params);

        if (http_threads < http_max_threads) {
            http_threads++;
            std::thread(http_worker).detach();
        }

        return 0;
    }

    std::vector<std::pair<uintptr_t, int>> stream_cancel;
    std::mutex stream_cancel_lock;

    std::vector<std::tuple<uintptr_t, int, cpr::Response>> stream_responses;
    std::mutex stream_response_lock;

    std::queue<std::tuple<uintptr_t, int, int, std::string, std::string, cpr::Body, cpr::Header, cpr::Parameters>> stream_queue;
    std::mutex stream_queue_lock;

    constexpr int stream_max_threads = 4;
    std::atomic<unsigned int> stream_threads = 0;

    void stream_worker()
    {
        while (true) {
            std::unique_lock<std::mutex> lock(stream_queue_lock);

            if (stream_queue.empty()) {
                stream_threads--;
                lock.unlock();
                break;
            }

            auto [id, reference, reference_progress, url, method, body, headers, params] = stream_queue.front();
            stream_queue.pop();
            lock.unlock();

            cpr::Header response_headers;

            cpr::HeaderCallback header_callback = cpr::HeaderCallback([&](const std::string_view& header, uintptr_t) {
                size_t delimiter = header.find(": ");
                if (delimiter != std::string_view::npos) {
                    std::string key(header.substr(0, delimiter));
                    std::string value(header.substr(delimiter + 2));
                    response_headers[key] = value;
                }
                return true;
            });

            cpr::WriteCallback stream_callback = cpr::WriteCallback(
                [&](const std::string_view& data, intptr_t) {
                    std::lock_guard<std::mutex> cancel_lock_guard(stream_cancel_lock);
                    if (!stream_cancel.empty()) {
                        for (auto& cancel : stream_cancel) {
                            if (cancel.first == id && cancel.second == reference) {
                                return false;
                            }
                        }
                    }

                    if (!data.empty()) {
                        cpr::Response partial;
                        partial.status_code = 100;
                        partial.header = response_headers;
                        partial.text = std::string(data);
                        partial.url = url;
                        partial.reason = "";
                        std::lock_guard<std::mutex> stream_lock_guard(stream_response_lock);
                        if (Tracker::is_state(id)) {
                            stream_responses.emplace_back(id, reference, partial);
                        }
                    }
                    return true;
                }
            );

            cpr::ProgressCallback progress_callback = cpr::ProgressCallback([&](cpr::cpr_off_t downloadTotal, cpr::cpr_off_t downloadNow, cpr::cpr_off_t uploadTotal, cpr::cpr_off_t uploadNow, intptr_t) {
                if (reference_progress == 0) return true;
                std::lock_guard<std::mutex> cancel_lock_guard(progress_cancel_lock);
                if (!progress_cancel.empty()) {
                    for (auto& cancel : progress_cancel) {
                        if (cancel.first == id && cancel.second == reference) {
                            return false;
                        }
                    }
                }

                std::lock_guard<std::mutex> http_lock_guard(http_progress_lock);
                if (Tracker::is_state(id)) {
                    http_progress.emplace_back(std::tuple<uintptr_t, int, std::string, cpr::cpr_off_t, cpr::cpr_off_t, cpr::cpr_off_t, cpr::cpr_off_t>(
                        id, reference_progress, url,
                        downloadTotal,
                        downloadNow,
                        uploadTotal,
                        uploadNow
                    ));
                }
                return true;
            });

            cpr::Response response;
            if (method == "post") {
                response = cpr::Post(cpr::Url{ url }, body, params, headers, header_callback, stream_callback, progress_callback);
            }
            else if (method == "get") {
                response = cpr::Get(cpr::Url{ url }, params, headers, header_callback, stream_callback, progress_callback);
            }
            else if (method == "put") {
                response = cpr::Put(cpr::Url{ url }, body, params, headers, header_callback, stream_callback, progress_callback);
            }
            else if (method == "delete") {
                response = cpr::Delete(cpr::Url{ url }, params, headers, header_callback, stream_callback, progress_callback);
            }
            else if (method == "patch") {
                response = cpr::Patch(cpr::Url{ url }, body, params, headers, header_callback, stream_callback, progress_callback);
            }

            if (reference_progress != 0) {
                std::lock_guard<std::mutex> http_lock_guard(http_progress_lock);
                if (Tracker::is_state(id)) {
                    http_progress.emplace_back(std::tuple<uintptr_t, int, std::string, cpr::cpr_off_t, cpr::cpr_off_t, cpr::cpr_off_t, cpr::cpr_off_t>(
                        id, reference_progress, url,
                        -1,
                        -1,
                        -1,
                        -1
                    ));
                }
            }

            std::lock_guard<std::mutex> stream_lock_guard(stream_response_lock);
            stream_responses.emplace_back(id, reference, response);
        }
    }

    int stream(lua_State* L)
    {
        uintptr_t id = Tracker::id(L);

        std::string url = luaL::checkcstring(L, 1);
        luaL::checkfunction(L, 2);
        int reference = luaL::newref(L, 2);
        int reference_progress = 0;

        std::string method = "get";
        cpr::Body body = "";
        cpr::Header headers;
        cpr::Parameters params;

        if (lua::istable(L, 3)) {
            lua::getfield(L, 3, "method");
            if (lua::isstring(L, -1)) {
                method = lua::tocstring(L, -1);
            }
            lua::pop(L);

            lua::getfield(L, 3, "headers");
            if (lua::istable(L, -1)) {
                lua::pushnil(L);
                while (lua::next(L, -2) != 0)
                {
                    headers.emplace(luaL::checkcstring(L, -2), luaL::checkcstring(L, -1));
                    lua::pop(L);
                }
            }
            lua::pop(L);

            lua::getfield(L, 3, "parameters");
            if (lua::istable(L, -1)) {
                lua::pushnil(L);
                while (lua::next(L, -2) != 0)
                {
                    params.Add({ luaL::checkcstring(L, -2), luaL::checkcstring(L, -1) });
                    lua::pop(L);
                }
            }
            lua::pop(L);

            lua::getfield(L, 3, "body");
            if (lua::isstring(L, -1)) {
                body = lua::tocstring(L, -1);
            }
            lua::pop(L);

            lua::getfield(L, 3, "progress");
            if (lua::isfunction(L, -1)) {
                reference_progress = luaL::newref(L, -1);
            }
            lua::pop(L);
        }

        std::lock_guard<std::mutex> lock(stream_queue_lock);
        stream_queue.emplace(id, reference, reference_progress, url, method, body, headers, params);

        if (stream_threads < stream_max_threads) {
            stream_threads++;
            std::thread(stream_worker).detach();
        }

        return 0;
    }
    
    class LSocket;
    std::unordered_map<uintptr_t, std::vector<LSocket*>> sockets;

    class LSocket : public CSocket {
    public:
        LSocket(lua_State* L, const std::string& url) : CSocket(url), L(L) {
            listener = Signal::create();
            uintptr_t id = Tracker::id(L);
            if (sockets.find(id) == sockets.end()) {
                sockets[id] = std::vector<LSocket*>();
            }
            sockets[id].push_back(this);
        }

        LSocket(lua_State* L, const std::string& url, std::map<std::string, std::string> headers_) : CSocket(url, headers_), L(L) {
            listener = Signal::create();
            uintptr_t id = Tracker::id(L);
            if (sockets.find(id) == sockets.end()) {
                sockets[id] = std::vector<LSocket*>();
            }
            sockets[id].push_back(this);
        }

        ~LSocket() {
            uintptr_t id = Tracker::id(L);
            if (sockets.find(id) != sockets.end()) {
                auto& handlers = sockets[id];
                handlers.erase(std::remove(handlers.begin(), handlers.end(), this), handlers.end());
            }
            delete listener;
            listener = nullptr;
        }

        void on_message(const std::string& message, bool is_binary) {
            if (listener == nullptr) return;
            lua::pushcstring(L, message);
            lua::pushboolean(L, is_binary);
            listener->fire(L, "message", 2);
        }

        void on_open() {
            if (listener == nullptr) return;
            listener->fire(L, "open");
        }

        void on_close(uint16_t code, const std::string& reason) {
            if (listener == nullptr) return;
            lua::pushnumber(L, code);
            lua::pushcstring(L, reason);
            listener->fire(L, "close", 2);
        }

        void on_error(int status, const std::string& reason) {
            if (listener == nullptr) return;
            lua::pushnumber(L, status);
            lua::pushcstring(L, reason);
            listener->fire(L, "error", 2);
        }

        void on_ping(const std::string& message) {
            if (listener == nullptr) return;
            lua::pushcstring(L, message);
            listener->fire(L, "ping", 1);
        }

        void on_pong(const std::string& message) {
            if (listener == nullptr) return;
            lua::pushcstring(L, message);
            listener->fire(L, "pong", 1);
        }

        void addl(std::string name, std::string identity, int index) {
            listener->addl(this->L, name, identity, index);
        }

        void removel(std::string name, std::string identity) {
            listener->removel(this->L, name, identity);
        }

        lua_State* L;
        Signal::Handle* listener;
    };

    bool is_socket(lua_State* L, void* value)
    {
        uintptr_t id = Tracker::id(L);
        if (sockets.find(id) == sockets.end()) {
            return false;
        }
        auto& handlers = sockets[id];
        return std::find(handlers.begin(), handlers.end(), value) != handlers.end();
    }

    int socket_add(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        std::string name = luaL::checkcstring(L, 2);
        std::string identity = luaL::checkcstring(L, 3);
        luaL::checklfunction(L, 4);
        socket->addl(name, identity, 4);
        return 0;
    }

    int socket_remove(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        std::string name = luaL::checkcstring(L, 2);
        std::string identity = luaL::checkcstring(L, 3);
        socket->removel(name, identity);
        return 0;
    }

    int socket_connect(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        socket->connect();
        return 0;
    }

    int socket_disconnect(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");

        if (lua::isstring(L, 2)) {
            socket->disconnect(lua::tocstring(L, 2));
        }
        else {
            socket->disconnect();
        }

        return 0;
    }

    int socket_text(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        socket->text(luaL::checkcstring(L, 2));
        return 0;
    }

    int socket_utf8(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        socket->utf8(luaL::checkcstring(L, 2));
        return 0;
    }

    int socket_binary(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        socket->binary(luaL::checkcstring(L, 2));
        return 0;
    }

    int socket_ping(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");

        if (lua::isstring(L, 2)) {
            socket->ping(lua::tocstring(L, 2));
        }
        else {
            socket->ping();
        }

        return 0;
    }

    int socket_ping_interval(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");

        if (lua::isnumber(L, 2)) {
            socket->ping_interval(lua::tonumber(L, 2));
        }
        else {
            socket->ping_interval(0);
        }

        return 0;
    }

    int socket_ping_message(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");

        if (lua::isstring(L, 2)) {
            socket->ping_message(lua::tocstring(L, 2));
        }
        else {
            socket->ping_message("");
        }

        return 0;
    }

    int socket_headers_add(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        std::string key = luaL::checkcstring(L, 2);
        std::string value = luaL::checkcstring(L, 3);
        socket->headers_add(key, value);
        return 0;
    }

    int socket_headers_remove(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        std::string key = luaL::checkcstring(L, 2);
        socket->headers_remove(key);
        return 0;
    }

    int socket_headers_get(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        std::string key = luaL::checkcstring(L, 2);
        lua::pushcstring(L, socket->headers_get(key));
        return 1;
    }

    int socket_headers_all(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");

        lua::newtable(L);

        for (auto& header : socket->headers_all()) {
            lua::pushcstring(L, header.second);
            lua::setcfield(L, -2, header.first);
        }

        return 1;
    }

    int socket_get_url(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        lua::pushcstring(L, socket->get_url());
        return 1;
    }

    int socket_get_host(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        lua::pushcstring(L, socket->get_host());
        return 1;
    }

    int socket_get_port(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        lua::pushcstring(L, socket->get_port());
        return 1;
    }

    int socket_get_path(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        lua::pushcstring(L, socket->get_path());
        return 1;
    }

    int socket_is_open(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        lua::pushboolean(L, socket->is_open());
        return 1;
    }

    int socket_is_connecting(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        lua::pushboolean(L, socket->is_connecting());
        return 1;
    }

    int socket_is_closing(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        lua::pushboolean(L, socket->is_closing());
        return 1;
    }

    int socket_is_closed(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        lua::pushboolean(L, socket->is_closed());
        return 1;
    }

    int socket_is_tls(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        lua::pushboolean(L, socket->is_tls());
        return 1;
    }

    int socket__tostring(lua_State* L)
    {
        LSocket* socket = (LSocket*)Class::check(L, 1, "socket");
        lua::pushcstring(L, "socket: " + socket->get_url());
        return 1;
    }

    int socket__gc(lua_State* L)
    {
        if (Class::is(L, 1, "socket")) {
            delete (LSocket*)Class::to(L, 1);
        }
        return 0;
    }

    int socket(lua_State* L) {
        std::string url = luaL::checkcstring(L, 1);
        std::map<std::string, std::string> headers;

        if (lua::istable(L, 2)) {
            lua::pushnil(L);
            while (lua::next(L, 2) != 0)
            {
                headers.emplace(luaL::checkcstring(L, -2), luaL::checkcstring(L, -1));
                lua::pop(L);
            }
        }

        if (!Class::existsbyname(L, "socket")) {
            Class::create(L, "socket");

            lua::pushcfunction(L, socket__tostring);
            lua::setfield(L, -2, "__tostring");

            lua::pushcfunction(L, socket__gc);
            lua::setfield(L, -2, "__gc");

            lua::newtable(L);
                lua::pushcfunction(L, socket_add);
                lua::setfield(L, -2, "add");

                lua::pushcfunction(L, socket_remove);
                lua::setfield(L, -2, "remove");

                lua::pushcfunction(L, socket_connect);
                lua::setfield(L, -2, "connect");

                lua::pushcfunction(L, socket_disconnect);
                lua::setfield(L, -2, "disconnect");

                lua::pushcfunction(L, socket_text);
                lua::setfield(L, -2, "text");

                lua::pushcfunction(L, socket_utf8);
                lua::setfield(L, -2, "utf8");

                lua::pushcfunction(L, socket_binary);
                lua::setfield(L, -2, "binary");

                lua::pushcfunction(L, socket_ping);
                lua::setfield(L, -2, "ping");

                lua::pushcfunction(L, socket_ping_interval);
                lua::setfield(L, -2, "ping_interval");

                lua::pushcfunction(L, socket_ping_message);
                lua::setfield(L, -2, "ping_message");

                lua::pushcfunction(L, socket_headers_add);
                lua::setfield(L, -2, "headers_add");

                lua::pushcfunction(L, socket_headers_remove);
                lua::setfield(L, -2, "headers_remove");

                lua::pushcfunction(L, socket_headers_get);
                lua::setfield(L, -2, "headers_get");

                lua::pushcfunction(L, socket_headers_all);
                lua::setfield(L, -2, "headers_all");

                lua::pushcfunction(L, socket_get_url);
                lua::setfield(L, -2, "get_url");

                lua::pushcfunction(L, socket_get_host);
                lua::setfield(L, -2, "get_host");

                lua::pushcfunction(L, socket_get_port);
                lua::setfield(L, -2, "get_port");

                lua::pushcfunction(L, socket_get_path);
                lua::setfield(L, -2, "get_path");

                lua::pushcfunction(L, socket_is_open);
                lua::setfield(L, -2, "is_open");

                lua::pushcfunction(L, socket_is_connecting);
                lua::setfield(L, -2, "is_connecting");

                lua::pushcfunction(L, socket_is_closing);
                lua::setfield(L, -2, "is_closing");

                lua::pushcfunction(L, socket_is_closed);
                lua::setfield(L, -2, "is_closed");

                lua::pushcfunction(L, socket_is_tls);
                lua::setfield(L, -2, "is_tls");
            lua::setfield(L, -2, "__index");

            lua::pop(L);
        }

        LSocket* socket = new LSocket(L, url, headers);
        Class::spawn(L, socket, "socket");

        return 1;
    }

    class Serve;
    std::unordered_map<uintptr_t, std::unordered_map<uint16_t, Serve*>> serves;

    bool is_serve(lua_State* L, void* value)
    {
        uintptr_t id = Tracker::id(L);
        auto it = serves.find(id);
        if (it == serves.end()) {
            return false;
        }
        const auto& handlers = it->second;
        for (const auto& handler : handlers) {
            if (handler.second == value) {
                return true;
            }
        }
        return false;
    }

    Serve* get_serve(lua_State* L, uint16_t port)
    {
        uintptr_t id = Tracker::id(L);
        if (serves.find(id) == serves.end()) {
            return nullptr;
        }
        auto& handlers = serves[id];
        if (handlers.find(port) == handlers.end()) {
            return nullptr;
        }
        return handlers[port];
    }

    bool status_valid(uint16_t code) {
        using namespace restinio;
        switch (code) {
        case 100: // continue_
        case 101: // switching_protocols
        case 102: // processing
        case 200: // ok
        case 201: // created
        case 202: // accepted
        case 203: // non_authoritative_information
        case 204: // no_content
        case 205: // reset_content
        case 206: // partial_content
        case 207: // multi_status
        case 300: // multiple_choices
        case 301: // moved_permanently
        case 302: // found
        case 303: // see_other
        case 304: // not_modified
        case 305: // use_proxy
        case 307: // temporary_redirect
        case 308: // permanent_redirect
        case 400: // bad_request
        case 401: // unauthorized
        case 402: // payment_required
        case 403: // forbidden
        case 404: // not_found
        case 405: // method_not_allowed
        case 406: // not_acceptable
        case 407: // proxy_authentication_required
        case 408: // request_time_out
        case 409: // conflict
        case 410: // gone
        case 411: // length_required
        case 412: // precondition_failed
        case 413: // payload_too_large
        case 414: // uri_too_long
        case 415: // unsupported_media_type
        case 416: // requested_range_not_satisfiable
        case 417: // expectation_failed
        case 422: // unprocessable_entity
        case 423: // locked
        case 424: // failed_dependency
        case 428: // precondition_required
        case 429: // too_many_requests
        case 431: // request_header_fields_too_large
        case 500: // internal_server_error
        case 501: // not_implemented
        case 502: // bad_gateway
        case 503: // service_unavailable
        case 504: // gateway_time_out
        case 505: // http_version_not_supported
        case 507: // insufficient_storage
        case 511: // network_authentication_required
            return true;
        default:
            return false;
        }
    }

    restinio::http_status_line_t get_status(uint16_t code) {
        using namespace restinio;
        switch (code) {
        case 100: // continue_
            return status_continue();
        case 101: // switching_protocols
            return status_switching_protocols();
        case 102: // processing
            return status_processing();
        case 200: // ok
            return status_ok();
        case 201: // created
            return status_created();
        case 202: // accepted
            return status_accepted();
        case 203: // non_authoritative_information
            return status_non_authoritative_information();
        case 204: // no_content
            return status_no_content();
        case 205: // reset_content
            return status_reset_content();
        case 206: // partial_content
            return status_partial_content();
        case 207: // multi_status
            return status_multi_status();
        case 300: // multiple_choices
            return status_multiple_choices();
        case 301: // moved_permanently
            return status_moved_permanently();
        case 302: // found
            return status_found();
        case 303: // see_other
            return status_see_other();
        case 304: // not_modified
            return status_not_modified();
        case 305: // use_proxy
            return status_use_proxy();
        case 307: // temporary_redirect
            return status_temporary_redirect();
        case 308: // permanent_redirect
            return status_permanent_redirect();
        case 400: // bad_request
            return status_bad_request();
        case 401: // unauthorized
            return status_unauthorized();
        case 402: // payment_required
            return status_payment_required();
        case 403: // forbidden
            return status_forbidden();
        case 404: // not_found
            return status_not_found();
        case 405: // method_not_allowed
            return status_method_not_allowed();
        case 406: // not_acceptable
            return status_not_acceptable();
        case 407: // proxy_authentication_required
            return status_proxy_authentication_required();
        case 408: // request_time_out
            return status_request_time_out();
        case 409: // conflict
            return status_conflict();
        case 410: // gone
            return status_gone();
        case 411: // length_required
            return status_length_required();
        case 412: // precondition_failed
            return status_precondition_failed();
        case 413: // payload_too_large
            return status_payload_too_large();
        case 414: // uri_too_long
            return status_uri_too_long();
        case 415: // unsupported_media_type
            return status_unsupported_media_type();
        case 416: // requested_range_not_satisfiable
            return status_requested_range_not_satisfiable();
        case 417: // expectation_failed
            return status_expectation_failed();
        case 422: // unprocessable_entity
            return status_unprocessable_entity();
        case 423: // locked
            return status_locked();
        case 424: // failed_dependency
            return status_failed_dependency();
        case 428: // precondition_required
            return status_precondition_required();
        case 429: // too_many_requests
            return status_too_many_requests();
        case 431: // request_header_fields_too_large
            return status_request_header_fields_too_large();
        case 500: // internal_server_error
            return status_internal_server_error();
        case 501: // not_implemented
            return status_not_implemented();
        case 502: // bad_gateway
            return status_bad_gateway();
        case 503: // service_unavailable
            return status_service_unavailable();
        case 504: // gateway_time_out
            return status_gateway_time_out();
        case 505: // http_version_not_supported
            return status_http_version_not_supported();
        case 507: // insufficient_storage
            return status_insufficient_storage();
        case 511: // network_authentication_required
            return status_network_authentication_required();
        default:
            return status_ok();
        }

        return status_ok();
    }

    struct serve_status_carry {
        bool done = false;
        restinio::http_status_line_t status;
        std::vector<std::pair<std::string, std::string>> headers;
        std::string body;
    };

    int serve_res_headers(lua_State* L)
    {
        serve_status_carry* self = (serve_status_carry*)Class::check(L, 1, "serve.response");
        if (!self || self == nullptr) return 0;
        luaL::checktable(L, 2);
        lua::pushnil(L);
        while (lua::next(L, 1) != 0)
        {
            if (lua::isstring(L, -1) && lua::isstring(L, -2))
                self->headers.emplace_back(std::pair<std::string, std::string>(lua::tocstring(L, -2), lua::tocstring(L, -1)));
            lua::pop(L);
        }
        return 0;
    }

    int serve_res_header(lua_State* L)
    {
        serve_status_carry* self = (serve_status_carry*)Class::check(L, 1, "serve.response");
        if (!self || self == nullptr) return 0;
        self->headers.emplace_back(std::pair<std::string, std::string>(luaL::checkcstring(L, 2), luaL::checkcstring(L, 3)));
        return 0;
    }

    int serve_res_body(lua_State* L)
    {
        serve_status_carry* self = (serve_status_carry*)Class::check(L, 1, "serve.response");
        if (!self || self == nullptr) return 0;
        self->body = luaL::checkcstring(L, 2);
        return 0;
    }

    int serve_res_status(lua_State* L)
    {
        serve_status_carry* self = (serve_status_carry*)Class::check(L, 1, "serve.response");
        if (!self || self == nullptr) return 0;
        uint16_t status = luaL::checknumber(L, 2);
        if (status_valid(status)) {
            self->status = get_status(status);
            self->done = true;
        }
        else {
            luaL::error(L, "invalid status code %d", status);
        }
        return 0;
    }

    int serve_res__gc(lua_State* L)
    {
        if (Class::is(L, 1, "serve.response")) {
            serve_status_carry* self = (serve_status_carry*)Class::to(L, 1);
        }
        return 0;
    }

    namespace rws = restinio::websocket::basic;

    void serve_socket_push(lua_State* L, std::string path, Serve* parent, rws::ws_handle_t socket);

    class Serve {
        using context_t = restinio::io_context_holder_t;
        using server_t = restinio::running_server_handle_t<restinio::default_traits_t>;
        using request_handle_t = restinio::request_handle_t;
        using query_string_params_t = restinio::query_string_params_t;

    public:
        Serve(lua_State* L, uint16_t port) : context(restinio::own_io_context()) {
            this->L = L;
            this->port = port;
            this->active = false;
            this->exchange = false;
            this->processing = false;
            this->awaiting = 0;
            sockets = std::unordered_map<std::string, std::unordered_map<std::uint64_t, rws::ws_handle_t>>();
            serves[Tracker::id(L)][port] = this;
        }

        ~Serve() {
            this->stop();
            uintptr_t id = Tracker::id(L);
            auto it = serves.find(id);
            if (it != serves.end()) {
                auto& handlers = it->second;
                auto it2 = handlers.find(this->port);
                if (it2 != handlers.end()) {
                    handlers.erase(it2);
                }
            }
        }

        void add(std::string method, std::string path, int reference)
        {
            std::transform(method.begin(), method.end(), method.begin(), ::toupper);
            if (handlers.find(method) == handlers.end()) {
                handlers[method] = std::unordered_map<std::string, int>();
            }
            auto& handles = handlers[method];
            handles.emplace(path, reference);
        }

        void remove(std::string method, std::string path)
        {
            std::transform(method.begin(), method.end(), method.begin(), ::toupper);
            if (!this->exists(method, path))
                return;
            this->handlers[method].erase(path);
        }

        bool exists(std::string method, std::string path)
        {
            std::transform(method.begin(), method.end(), method.begin(), ::toupper);
            if (handlers.find(method) != handlers.end()) {
                auto& handles = handlers[method];
                if (handles.find(path) != handles.end()) {
                    return true;
                }
            }
            return false;
        }

        int get(std::string method, std::string path) {
            std::transform(method.begin(), method.end(), method.begin(), ::toupper);
            if (handlers.find(method) != handlers.end()) {
                auto& handles = handlers[method];
                if (handles.find(path) != handles.end()) {
                    return handles[path];
                }
            }
            return 0;
        }

        std::vector<std::tuple<std::string, std::string, int>> list()
        {
            std::vector<std::tuple<std::string, std::string, int>> list;
            for (auto& handles : this->handlers)
            {
                for (auto& handle : handles.second) {
                    list.push_back(std::tuple<std::string, std::string, int>(
                        handles.first,
                        handle.first,
                        handle.second
                    ));
                }
            }
            return list;
        }

        void socket_handle(std::string path, rws::ws_handle_t connection, rws::message_handle_t m, bool internal = false) {
            if (!internal) {
                int id = awaiting++;
                while (exchange != id || !exchanging || processing) {
                    std::this_thread::yield();
                }
                processing = true;
            }

            if (handlers.find("SOCKET") != handlers.end()) {
                auto& handles = handlers["SOCKET"];
                if (handles.find(path) != handles.end()) {
                    int reference = handles[path];

                    lua::pushref(L, reference);
                    serve_socket_push(L, path, this, connection);
                    lua::pushnumber(L, (uint8_t)m->opcode());
                    std::string payload = m->payload();

                    if (m->opcode() == rws::opcode_t::connection_close_frame) {
                        uint16_t code = 1005; // 1005 = no status code (default fallback)
                        std::string reason;

                        if (payload.size() >= 2) {
                            code = (static_cast<uint8_t>(payload[0]) << 8) | static_cast<uint8_t>(payload[1]);
                            if (payload.size() > 2) {
                                reason = payload.substr(2);
                            }
                        }

                        lua::pushnumber(L, code);
                        lua::pushcstring(L, reason);

                        if (lua::tcall(L, 4, 0)) {
                            std::string err = lua::tocstring(L, -1);
                            lua::pop(L);
                            auto& on_error = get_on_error();
                            for (auto const& handle : on_error) handle.second(L, "serve - SOCKET - SOCKET", err);
                        }
                    }
                    else {
                        lua::pushcstring(L, m->payload());

                        if (lua::tcall(L, 3, 0)) {
                            std::string err = lua::tocstring(L, -1);
                            lua::pop(L);
                            auto& on_error = get_on_error();
                            for (auto const& handle : on_error) handle.second(L, "serve - SOCKET - SOCKET", err);
                        }
                    }
                }
            }

            if (m->opcode() == rws::opcode_t::connection_close_frame) {
                if (sockets.find(path) != sockets.end()) {
                    sockets[path].erase(connection->connection_id());
                }
                connection->send_message(*m);
            }

            if (!internal) {
                exchange++;
                processing = false;
            }
        }

        serve_status_carry handle(request_handle_t& req, int reference, int tbl_reference, std::string method, std::string path)
        {
            serve_status_carry response{
                false,
                restinio::status_ok(),
                {},
                ""
            };

            lua::pushref(L, reference);
            lua::pushref(L, tbl_reference);

            if (!Class::existsbyname(L, "serve.response")) {
                Class::create(L, "serve.response");

                lua::newtable(L);
                
                lua::pushcfunction(L, serve_res_headers);
                lua::setfield(L, -2, "headers");

                lua::pushcfunction(L, serve_res_header);
                lua::setfield(L, -2, "header");

                lua::pushcfunction(L, serve_res_body);
                lua::setfield(L, -2, "body");

                lua::pushcfunction(L, serve_res_status);
                lua::setfield(L, -2, "status");

                lua::setfield(L, -2, "__index");

                lua::pushcfunction(L, serve_res__gc);
                lua::setfield(L, -2, "__gc");

                lua::pop(L);
            }

            Class::spawn(L, &response, "serve.response");

            if (lua::tcall(L, 2, 1)) {
                std::string err = lua::tocstring(L, -1);
                lua::pop(L);
                auto& on_error = get_on_error();
                for (auto const& handle : on_error) handle.second(L, "serve - " + method + " - " + path, err);
            }
            else {
                if (lua::istable(L, -1)) {
                    response.done = true;

                    lua::getfield(L, -1, "status");
                    if (lua::isnumber(L, -1)) {
                        uint16_t status = lua::tonumber(L, -1);
                        if (status_valid(status)) {
                            response.status = get_status(status);
                        }
                    }
                    lua::pop(L);

                    lua::getfield(L, -1, "body");
                    if (lua::isstring(L, -1)) {
                        response.body = lua::tocstring(L, -1);
                    }
                    lua::pop(L);

                    lua::getfield(L, -1, "headers");
                    if (lua::istable(L, -1)) {
                        lua::pushnil(L);
                        while (lua::next(L, -2) != 0)
                        {
                            if (lua::isstring(L, -1) && lua::isstring(L, -2))
                                response.headers.emplace_back(std::pair<std::string, std::string>(lua::tocstring(L, -2), lua::tocstring(L, -1)));
                            lua::pop(L);
                        }
                    }
                    lua::pop(L);
                }
                else if (lua::isboolean(L, -1)) {
                    if (lua::toboolean(L, -1) == true) {
                        response.done = true;
                    }
                    else {
                        response.status = restinio::status_bad_request();
                        response.done = true;
                    }
                }
                lua::pop(L);
            }

            return response;
        }

        request_handle_t request;
        std::unordered_map<std::string, std::unordered_map<std::uint64_t, rws::ws_handle_t>> sockets;
        restinio::request_handling_status_t process(request_handle_t& req) {
            std::string path = std::string(req->header().path());
            std::string query = std::string(req->header().query());
            int method_id = req->header().method().raw_id();
            std::string method = std::string(req->header().method().c_str());
            std::string body = std::string(req->body());
            std::vector<std::pair<std::string, std::string>> headers;
            for (auto it = req->header().begin(); it != req->header().end(); ++it) {
                headers.emplace_back(std::pair<std::string, std::string>(it->name(), it->value()));
            }

            int id = awaiting++;
            while (exchange != id || !exchanging || processing) {
                std::this_thread::yield();
            }
            processing = true;
            this->request = req;

            lua::newtable(L);
            lua::pushcstring(L, path);
            lua::setfield(L, -2, "path");
            lua::pushcstring(L, query);
            lua::setfield(L, -2, "query");
            lua::pushcstring(L, method);
            lua::setfield(L, -2, "method");
            lua::pushcstring(L, body);
            lua::setfield(L, -2, "body");
            lua::newtable(L);
            for (auto& header : headers) {
                lua::pushcstring(L, header.second);
                lua::setcfield(L, -2, header.first);
            }
            lua::setfield(L, -2, "headers");

            if (!Class::existsbyname(L, "serve.request")) {
                Class::create(L, "serve.request");

                lua::newtable(L);
                lua::setfield(L, -2, "__index");

                lua::pop(L);
            }

            if (Class::metatable(L, "serve.request")) {
                lua::setmetatable(L, -2);
            }

            int tbl_reference = luaL::newref(L, -1);

            if (handlers.find("ANY") != handlers.end()) {
                auto& handles = handlers[method];
                if (handles.find("ANY") != handles.end()) {
                    int reference = handles["ANY"];
                    serve_status_carry response = this->handle(req, reference, tbl_reference, "ANY", "ANY");
                    if (response.done) {
                        auto res = req->create_response(response.status);
                        res.set_body(response.body);
                        for (auto& header : response.headers) {
                            res.append_header(header.first, header.second);
                        }
                        res.done();
                        luaL::rmref(L, tbl_reference);
                        this->request = nullptr;
                        exchange++;
                        processing = false;
                        return restinio::request_accepted();
                    }
                }
            }

            if (handlers.find(method) != handlers.end()) {
                auto& handles = handlers[method];

                if (handles.find("ANY") != handles.end()) {
                    int reference = handles["ANY"];
                    serve_status_carry response = this->handle(req, reference, tbl_reference, method, "ANY");
                    if (response.done) {
                        auto res = req->create_response(response.status);
                        res.set_body(response.body);
                        for (auto& header : response.headers) {
                            res.append_header(header.first, header.second);
                        }
                        res.done();
                        luaL::rmref(L, tbl_reference);
                        this->request = nullptr;
                        exchange++;
                        processing = false;
                        return restinio::request_accepted();
                    }
                }

                if (handles.find(path) != handles.end()) {
                    int reference = handles[path];
                    serve_status_carry response = this->handle(req, reference, tbl_reference, method, path);
                    if (response.done) {
                        auto res = req->create_response(response.status);
                        res.set_body(response.body);
                        for (auto& header : response.headers) {
                            res.append_header(header.first, header.second);
                        }
                        res.done();
                        luaL::rmref(L, tbl_reference);
                        this->request = nullptr;
                        exchange++;
                        processing = false;
                        return restinio::request_accepted();
                    }
                }
            }

            luaL::rmref(L, tbl_reference);

            this->request = nullptr;
            exchange++;
            processing = false;

            return restinio::request_not_handled();
        }

        void sync() {
            if (awaiting == 0) return;
            exchanging = true;
            while (awaiting != exchange || processing) {
                std::this_thread::yield();
            }
            exchanging = false;
        }

        bool start() {
            if (this->active) return false;
            try {
                this->server = restinio::run_async(
                    this->context,
                    restinio::server_settings_t<restinio::default_traits_t>{}
                .port(this->port)
                    .address("0.0.0.0")
                    .request_handler([this](request_handle_t req) {
                    return this->process(req);
                        }), 4);
            }
            catch (const std::exception& ex) {
                return false;
            }
            this->active = true;
            return true;
        }

        void stop() {
            if (!this->active) return;
            this->server->stop();
            this->server->wait();
            this->server.reset();
            this->active = false;
        }

        uint16_t get_port() { return port; }
        bool get_active() { return active; }
        bool is_processing() { return processing; }
    private:
        lua_State* L;
        std::unordered_map<std::string, std::unordered_map<std::string, int>> handlers;
        uint16_t port;
        context_t context;
        server_t server;
        bool active;
        std::atomic<bool> exchanging;
        std::atomic<unsigned int> exchange;
        std::atomic<bool> processing;
        std::atomic<unsigned int> awaiting;
    };

    class Serve_Socket
    {
    public:
        Serve_Socket(std::string path, Serve* serve, rws::ws_handle_t sock)
        {
            this->path = path;
            this->parent = serve;
            this->socket = sock;
        }

        std::string path;
        Serve* parent;
        rws::ws_handle_t socket;
    };

    // rws::ws_handle_t
    int serve_socket_text(lua_State* L)
    {
        Serve_Socket* sock = (Serve_Socket*)Class::check(L, 1, "serve.socket");

        if (sock->parent->sockets.find(sock->path) == sock->parent->sockets.end()) {
            return 0;
        }

        auto& handlers = sock->parent->sockets[sock->path];

        if (handlers.find(sock->socket->connection_id()) == handlers.end()) {
            return 0;
        }

        rws::message_t msg;
        msg.set_opcode(rws::opcode_t::text_frame);
        msg.set_payload(luaL::checkcstring(L, 2));
        sock->socket->send_message(msg);
        return 0;
    }

    int serve_socket_binary(lua_State* L)
    {
        Serve_Socket* sock = (Serve_Socket*)Class::check(L, 1, "serve.socket");

        if (sock->parent->sockets.find(sock->path) == sock->parent->sockets.end()) {
            return 0;
        }

        auto& handlers = sock->parent->sockets[sock->path];

        if (handlers.find(sock->socket->connection_id()) == handlers.end()) {
            return 0;
        }

        rws::message_t msg;
        msg.set_opcode(rws::opcode_t::binary_frame);
        msg.set_payload(luaL::checkcstring(L, 2));
        sock->socket->send_message(msg);
        return 0;
    }

    int serve_socket_ping(lua_State* L)
    {
        Serve_Socket* sock = (Serve_Socket*)Class::check(L, 1, "serve.socket");

        if (sock->parent->sockets.find(sock->path) == sock->parent->sockets.end()) {
            return 0;
        }

        auto& handlers = sock->parent->sockets[sock->path];

        if (handlers.find(sock->socket->connection_id()) == handlers.end()) {
            return 0;
        }

        rws::message_t msg;
        msg.set_opcode(rws::opcode_t::ping_frame);

        if (lua::isstring(L, 2)) {
            msg.set_payload(lua::tocstring(L, 2));
        }

        sock->socket->send_message(msg);
        return 0;
    }

    int serve_socket_pong(lua_State* L)
    {
        Serve_Socket* sock = (Serve_Socket*)Class::check(L, 1, "serve.socket");

        if (sock->parent->sockets.find(sock->path) == sock->parent->sockets.end()) {
            return 0;
        }

        auto& handlers = sock->parent->sockets[sock->path];

        if (handlers.find(sock->socket->connection_id()) == handlers.end()) {
            return 0;
        }

        rws::message_t msg;
        msg.set_opcode(rws::opcode_t::pong_frame);

        if (lua::isstring(L, 2)) {
            msg.set_payload(lua::tocstring(L, 2));
        }

        sock->socket->send_message(msg);
        return 0;
    }

    int serve_socket_disconnect(lua_State* L)
    {
        Serve_Socket* sock = (Serve_Socket*)Class::check(L, 1, "serve.socket");

        if (sock->parent->sockets.find(sock->path) == sock->parent->sockets.end()) {
            return 0;
        }

        auto& handlers = sock->parent->sockets[sock->path];

        if (handlers.find(sock->socket->connection_id()) == handlers.end()) {
            return 0;
        }

        rws::message_t msg;
        msg.set_opcode(rws::opcode_t::connection_close_frame);

        uint16_t code = (uint16_t)rws::status_code_t::normal_closure;
        std::string reason = "";

        if (lua::isnumber(L, 2)) {
            code = lua::tonumber(L, 2);
            if (lua::isstring(L, 3)) {
                reason = lua::tocstring(L, 2);
            }
        } else if (lua::isstring(L, 2)) {
            reason = lua::tocstring(L, 2);
        }

        char status_code[2];
        status_code[0] = static_cast<char>((code >> 8) & 0xFF);
        status_code[1] = static_cast<char>(code & 0xFF);

        std::string payload(status_code, 2);
        payload += reason;

        msg.set_payload(payload);
        msg.set_final_flag(rws::final_frame);

        rws::message_handle_t hndl = std::make_shared<rws::message_t>(msg);
        sock->parent->socket_handle(sock->path, sock->socket, hndl, true);
        hndl.reset();

        sock->socket->kill();

        if (sock->parent->sockets.find(sock->path) != sock->parent->sockets.end()) {
            sock->parent->sockets[sock->path].erase(sock->socket->connection_id());
        }

        return 0;
    }

    int serve_socket_id(lua_State* L)
    {
        Serve_Socket* sock = (Serve_Socket*)Class::check(L, 1, "serve.socket");

        if (sock->parent->sockets.find(sock->path) == sock->parent->sockets.end()) {
            return 0;
        }

        auto& handlers = sock->parent->sockets[sock->path];

        if (handlers.find(sock->socket->connection_id()) == handlers.end()) {
            return 0;
        }

        lua::pushcstring(L, std::to_string(sock->socket->connection_id()));
        return 1;
    }

    int serve_socket__gc(lua_State* L)
    {
        if (Class::is(L, 1, "serve.socket")) {
            Serve_Socket* sock = (Serve_Socket*)Class::to(L, 1);
            delete sock;
        }
        return 0;
    }

    int serve_socket__tostring(lua_State* L)
    {
        Serve_Socket* sock = (Serve_Socket*)Class::check(L, 1, "serve.socket");

        if (sock->parent->sockets.find(sock->path) == sock->parent->sockets.end()) {
            return 0;
        }

        auto& handlers = sock->parent->sockets[sock->path];

        if (handlers.find(sock->socket->connection_id()) == handlers.end()) {
            return 0;
        }

        lua::pushcstring(L, "serve.socket: " + std::to_string(sock->parent->get_port()) + " #" + std::to_string(sock->socket->connection_id()));
        return 1;
    }

    void serve_socket_push(lua_State* L, std::string path, Serve* parent, rws::ws_handle_t socket)
    {
        Serve_Socket* sock = new Serve_Socket(path, parent, socket);

        if (!Class::existsbyname(L, "serve.socket")) {
            Class::create(L, "serve.socket");

            lua::newtable(L);

            lua::pushcfunction(L, serve_socket_id);
            lua::setfield(L, -2, "id");

            lua::pushcfunction(L, serve_socket_disconnect);
            lua::setfield(L, -2, "disconnect");

            lua::pushcfunction(L, serve_socket_text);
            lua::setfield(L, -2, "text");

            lua::pushcfunction(L, serve_socket_binary);
            lua::setfield(L, -2, "binary");

            lua::pushcfunction(L, serve_socket_ping);
            lua::setfield(L, -2, "ping");

            lua::pushcfunction(L, serve_socket_pong);
            lua::setfield(L, -2, "pong");

            lua::setfield(L, -2, "__index");

            lua::pushcfunction(L, serve_socket__gc);
            lua::setfield(L, -2, "__gc");

            lua::pushcfunction(L, serve_socket__tostring);
            lua::setfield(L, -2, "__tostring");

            lua::pop(L);
        }

        Class::spawn(L, sock, "serve.socket");
    }

    int serve_start(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");
        lua::pushboolean(L, serve->start());
        return 1;
    }

    int serve_stop(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");
        serve->stop();
        return 0;
    }

    int serve_active(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");
        lua::pushboolean(L, serve->get_active());
        return 1;
    }

    int serve_port(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");
        lua::pushnumber(L, serve->get_port());
        return 1;
    }

    int serve_exists(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");
        std::string method = luaL::checkcstring(L, 2);
        std::string path = luaL::checkcstring(L, 3);
        lua::pushboolean(L, serve->exists(method, path));
        return 1;
    }

    int serve_any(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");
        std::string path = luaL::checkcstring(L, 2);

        if (lua::isnil(L, 3)) {
            serve->remove("ANY", path);
            return 0;
        }

        luaL::checkfunction(L, 3);
        int reference = luaL::newref(L, 3);

        if (serve->exists("ANY", path)) {
            luaL::rmref(L, serve->get("ANY", path));
            serve->remove("ANY", path);
        }

        serve->add("ANY", path, reference);

        return 0;
    }

    int serve_socket(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");
        std::string path = luaL::checkcstring(L, 2);

        if (lua::isnil(L, 3)) {
            serve->remove("SOCKET", path);
            return 0;
        }

        luaL::checkfunction(L, 3);
        int reference = luaL::newref(L, 3);

        if (serve->exists("SOCKET", path)) {
            luaL::rmref(L, serve->get("SOCKET", path));
            serve->remove("SOCKET", path);
        }

        serve->add("SOCKET", path, reference);

        return 0;
    }

    int serve_sockets(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");
        std::string path = luaL::checkcstring(L, 2);

        if (serve->sockets.find(path) == serve->sockets.end()) {
            return 0;
        }

        auto& handlers = serve->sockets[path];

        lua::newtable(L);

        int index = 1;
        for (auto& entry : handlers) {
            lua::pushnumber(L, index++);
            serve_socket_push(L, path, serve, entry.second);
            lua::settable(L, -3);
        }

        return 1;
    }
    
    int serve_upgrade(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");

        if (!serve->is_processing()) return 0;

        if (restinio::http_connection_header_t::upgrade == serve->request->header().connection()) {
            std::string path = std::string(serve->request->header().path());
            rws::ws_handle_t wsh =
                rws::upgrade< restinio::default_traits_t >(
                    *serve->request,
                    rws::activation_t::immediate,
                    [serve, path](rws::ws_handle_t wsh, rws::message_handle_t m) {
                        serve->socket_handle(path, wsh, m);
                    }
                );

            if (serve->sockets.find(path) == serve->sockets.end()) {
                serve->sockets[path] = std::unordered_map<std::uint64_t, rws::ws_handle_t>();
            }

            serve->sockets[path].emplace(wsh->connection_id(), wsh);

            serve_socket_push(L, path, serve, wsh);
        } else {
            lua::pushboolean(L, false);
        }

        return 1;
    }

    int serve_get(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");
        std::string path = luaL::checkcstring(L, 2);

        if (lua::isnil(L, 3)) {
            serve->remove("get", path);
            return 0;
        }

        luaL::checkfunction(L, 3);
        int reference = luaL::newref(L, 3);

        if (serve->exists("get", path)) {
            luaL::rmref(L, serve->get("get", path));
            serve->remove("get", path);
        }
        
        serve->add("get", path, reference);

        return 0;
    }

    int serve_head(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");
        std::string path = luaL::checkcstring(L, 2);

        if (lua::isnil(L, 3)) {
            serve->remove("head", path);
            return 0;
        }

        luaL::checkfunction(L, 3);
        int reference = luaL::newref(L, 3);

        if (serve->exists("head", path)) {
            luaL::rmref(L, serve->get("head", path));
            serve->remove("head", path);
        }

        serve->add("head", path, reference);

        return 0;
    }

    int serve_post(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");
        std::string path = luaL::checkcstring(L, 2);

        if (lua::isnil(L, 3)) {
            serve->remove("post", path);
            return 0;
        }

        luaL::checkfunction(L, 3);
        int reference = luaL::newref(L, 3);

        serve->add("post", path, reference);

        return 0;
    }

    int serve_put(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");
        std::string path = luaL::checkcstring(L, 2);

        if (lua::isnil(L, 3)) {
            serve->remove("put", path);
            return 0;
        }

        luaL::checkfunction(L, 3);
        int reference = luaL::newref(L, 3);

        if (serve->exists("put", path)) {
            luaL::rmref(L, serve->get("put", path));
            serve->remove("put", path);
        }

        serve->add("put", path, reference);

        return 0;
    }

    int serve_delete(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");
        std::string path = luaL::checkcstring(L, 2);

        if (lua::isnil(L, 3)) {
            serve->remove("delete", path);
            return 0;
        }

        luaL::checkfunction(L, 3);
        int reference = luaL::newref(L, 3);

        if (serve->exists("delete", path)) {
            luaL::rmref(L, serve->get("delete", path));
            serve->remove("delete", path);
        }

        serve->add("delete", path, reference);

        return 0;
    }

    int serve_options(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");
        std::string path = luaL::checkcstring(L, 2);

        if (lua::isnil(L, 3)) {
            serve->remove("options", path);
            return 0;
        }

        luaL::checkfunction(L, 3);
        int reference = luaL::newref(L, 3);

        if (serve->exists("options", path)) {
            luaL::rmref(L, serve->get("options", path));
            serve->remove("options", path);
        }

        serve->add("options", path, reference);

        return 0;
    }

    int serve_patch(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");
        std::string path = luaL::checkcstring(L, 2);

        if (lua::isnil(L, 3)) {
            serve->remove("patch", path);
            return 0;
        }

        luaL::checkfunction(L, 3);
        int reference = luaL::newref(L, 3);

        if (serve->exists("patch", path)) {
            luaL::rmref(L, serve->get("patch", path));
            serve->remove("patch", path);
        }

        serve->add("patch", path, reference);

        return 0;
    }

    int serve_handlers(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");
        auto list = serve->list();
        lua::newtable(L);
        int i = 0;
        for (auto& entry : list) {
            std::string method = std::get<0>(entry);
            std::string path = std::get<1>(entry);
            int reference = std::get<2>(entry);
            lua::pushnumber(L, ++i);
            lua::newtable(L);
            lua::pushcstring(L, method);
            lua::setfield(L, -2, "method");
            lua::pushcstring(L, path);
            lua::setfield(L, -2, "path");
            lua::pushref(L, reference);
            lua::setfield(L, -2, "callback");
            lua::settable(L, -3);
        }
        return 1;
    }

    int serve__tostring(lua_State* L)
    {
        Serve* serve = (Serve*)Class::check(L, 1, "serve");
        lua::pushcstring(L, "serve: " + std::to_string(serve->get_port()));
        return 1;
    }

    int serve__gc(lua_State* L)
    {
        if (Class::is(L, 1, "serve")) {
            // should probably do something here...?
        }
        return 0;
    }

    int serve(lua_State* L)
    {
        uint16_t port = luaL::checknumber(L, 1);

        if (!Class::existsbyname(L, "serve")) {
            Class::create(L, "serve");

            lua::pushcfunction(L, serve__tostring);
            lua::setfield(L, -2, "__tostring");

            lua::pushcfunction(L, serve__gc);
            lua::setfield(L, -2, "__gc");

            lua::newtable(L);
                lua::pushcfunction(L, serve_start);
                lua::setfield(L, -2, "start");

                lua::pushcfunction(L, serve_stop);
                lua::setfield(L, -2, "stop");

                lua::pushcfunction(L, serve_active);
                lua::setfield(L, -2, "active");

                lua::pushcfunction(L, serve_port);
                lua::setfield(L, -2, "port");

                lua::pushcfunction(L, serve_exists);
                lua::setfield(L, -2, "exists");

                lua::pushcfunction(L, serve_handlers);
                lua::setfield(L, -2, "handlers");

                lua::pushcfunction(L, serve_sockets);
                lua::setfield(L, -2, "sockets");

                lua::pushcfunction(L, serve_upgrade);
                lua::setfield(L, -2, "upgrade");

                lua::pushcfunction(L, serve_socket);
                lua::setfield(L, -2, "socket");

                lua::pushcfunction(L, serve_any);
                lua::setfield(L, -2, "any");

                lua::pushcfunction(L, serve_get);
                lua::setfield(L, -2, "get");

                lua::pushcfunction(L, serve_head);
                lua::setfield(L, -2, "head");

                lua::pushcfunction(L, serve_post);
                lua::setfield(L, -2, "post");

                lua::pushcfunction(L, serve_put);
                lua::setfield(L, -2, "put");

                lua::pushcfunction(L, serve_delete);
                lua::setfield(L, -2, "delete");

                lua::pushcfunction(L, serve_options);
                lua::setfield(L, -2, "options");

                lua::pushcfunction(L, serve_patch);
                lua::setfield(L, -2, "patch");
            lua::setfield(L, -2, "__index");

            lua::pop(L);
        }

        if (Serve* exists = get_serve(L, port); exists != nullptr)
        {
            Class::spawn(L, exists, "serve");
            return 1;
        }

        Class::spawn(L, new Serve(L, port), "serve");
        return 1;
    }

    void runtime_threaded(lua_State* T)
    {
        std::unique_lock<std::mutex> lock_progress(http_progress_lock);

        if (http_progress.size() > 0) {
            for (auto it = http_progress.begin(); it != http_progress.end(); ) {
                auto& result = *it;
                uintptr_t id = std::get<0>(result);
                lua_State* L = Tracker::is_state(id);

                if (L != T) {
                    ++it;
                    continue;
                }

                int reference = std::get<1>(result);
                std::string url = std::get<2>(result);
                cpr::cpr_off_t downloadTotal = std::get<3>(result);
                cpr::cpr_off_t downloadNow = std::get<4>(result);
                cpr::cpr_off_t uploadTotal = std::get<5>(result);
                cpr::cpr_off_t uploadNow = std::get<6>(result);

                if (downloadTotal == -1 && downloadNow == -1 && uploadTotal == -1 && uploadNow == -1) {
                    luaL::rmref(L, reference);
                    it = http_progress.erase(it);
                    continue;
                }

                lua::pushref(L, reference);

                lua::pushnumber(L, downloadTotal);
                lua::pushnumber(L, downloadNow);
                lua::pushnumber(L, uploadTotal);
                lua::pushnumber(L, uploadNow);

                if (lua::tcall(L, 4, 1)) {
                    std::string err = lua::tocstring(L, -1);
                    auto& on_error = get_on_error();
                    for (auto const& handle : on_error) handle.second(L, "progress - " + url, err);
                    std::lock_guard<std::mutex> cancel_lock_guard(progress_cancel_lock);
                    if (!progress_cancel.empty()) {
                        bool should = true;

                        for (auto& cancel : progress_cancel) {
                            if (cancel.first == id && cancel.second == reference) {
                                should = false;
                                break;
                            }
                        }

                        if (should) {
                            progress_cancel.push_back(std::pair<uintptr_t, int>(id, reference));
                        }
                    }
                }
                else if (lua::isboolean(L, -1) && lua::toboolean(L, -1) == false) {
                    std::lock_guard<std::mutex> cancel_lock_guard(progress_cancel_lock);
                    if (!progress_cancel.empty()) {
                        bool should = true;

                        for (auto& cancel : progress_cancel) {
                            if (cancel.first == id && cancel.second == reference) {
                                should = false;
                                break;
                            }
                        }

                        if (should) {
                            progress_cancel.push_back(std::pair<uintptr_t, int>(id, reference));
                        }
                    }
                }

                lua::pop(L);

                it = http_progress.erase(it);
            }
        }

        lock_progress.unlock();


        std::unique_lock<std::mutex> lock_http(http_response_lock);

        if (http_responses.size() > 0) {
            for (auto it = http_responses.begin(); it != http_responses.end(); ) {
                auto& result = *it;
                uintptr_t id = std::get<0>(result);
                lua_State* L = Tracker::is_state(id);

                if (L != T) {
                    ++it;
                    continue;
                }

                int reference = std::get<1>(result);
                cpr::Response response = std::get<2>(result);

                lua::pushref(L, reference);
                luaL::rmref(L, reference);

                lua::newtable(L);

                lua::pushnumber(L, response.status_code);
                lua::setfield(L, -2, "status");

                lua::pushcstring(L, response.text);
                lua::setfield(L, -2, "body");

                lua::pushcstring(L, response.reason);
                lua::setfield(L, -2, "reason");

                lua::pushcstring(L, response.url.str());
                lua::setfield(L, -2, "url");

                lua::newtable(L);
                for (const auto& [key, value] : response.header)
                {
                    lua::pushcstring(L, key);
                    lua::pushcstring(L, value);
                    lua::settable(L, -3);
                }
                lua::setfield(L, -2, "headers");

                if (lua::tcall(L, 1, 0)) {
                    std::string err = lua::tocstring(L, -1);
                    lua::pop(L);
                    auto& on_error = get_on_error();
                    for (auto const& handle : on_error) handle.second(L, "http - " + response.url.str(), err);
                }

                it = http_responses.erase(it);

                std::lock_guard<std::mutex> progress_cancel_lock_guard(progress_cancel_lock);
                if (!progress_cancel.empty()) {
                    for (auto& cancel : progress_cancel) {
                        if (cancel.first == id && cancel.second == reference) {
                            progress_cancel.erase(std::remove(progress_cancel.begin(), progress_cancel.end(), cancel), progress_cancel.end());
                        }
                    }
                }
            }
        }

        lock_http.unlock();

        std::unique_lock<std::mutex> lock_stream(stream_response_lock);

        if (stream_responses.size() > 0)
        {
            for (auto it = stream_responses.begin(); it != stream_responses.end(); ) {
                auto& result = *it;
                uintptr_t id = std::get<0>(result);
                lua_State* L = Tracker::is_state(id);

                if (L != T) {
                    ++it;
                    continue;
                }

                int reference = std::get<1>(result);
                cpr::Response response = std::get<2>(result);

                lua::pushref(L, reference);

                lua::newtable(L);

                lua::pushnumber(L, response.status_code);
                lua::setfield(L, -2, "status");

                lua::pushcstring(L, response.text);
                lua::setfield(L, -2, "body");

                lua::pushcstring(L, response.reason);
                lua::setfield(L, -2, "reason");

                lua::pushcstring(L, response.url.str());
                lua::setfield(L, -2, "url");

                lua::newtable(L);
                for (const auto& [key, value] : response.header)
                {
                    lua::pushcstring(L, key);
                    lua::pushcstring(L, value);
                    lua::settable(L, -3);
                }
                lua::setfield(L, -2, "headers");

                if (lua::tcall(L, 1, 1)) {
                    std::string err = lua::tocstring(L, -1);
                    auto& on_error = get_on_error();
                    for (auto const& handle : on_error) handle.second(L, "stream - " + response.url.str(), err);

                    std::lock_guard<std::mutex> cancel_lock_guard(stream_cancel_lock);
                    if (!stream_cancel.empty()) {
                        bool should = true;

                        for (auto& cancel : stream_cancel) {
                            if (cancel.first == id && cancel.second == reference) {
                                should = false;
                                break;
                            }
                        }

                        if (should) {
                            stream_cancel.push_back(std::pair<uintptr_t, int>(id, reference));
                        }
                    }
                }
                else if (lua::isboolean(L, -1) && lua::toboolean(L, -1) == false) {
                    std::lock_guard<std::mutex> cancel_lock_guard(stream_cancel_lock);
                    if (!stream_cancel.empty()) {
                        bool should = true;

                        for (auto& cancel : stream_cancel) {
                            if (cancel.first == id && cancel.second == reference) {
                                should = false;
                                break;
                            }
                        }

                        if (should) {
                            stream_cancel.push_back(std::pair<uintptr_t, int>(id, reference));
                        }
                    }
                }

                it = stream_responses.erase(it);
                lua::pop(L);

                if (response.status_code != 100) {
                    luaL::rmref(L, reference);

                    std::lock_guard<std::mutex> progress_cancel_lock_guard(progress_cancel_lock);
                    if (!progress_cancel.empty()) {
                        for (auto& cancel : progress_cancel) {
                            if (cancel.first == id && cancel.second == reference) {
                                progress_cancel.erase(std::remove(progress_cancel.begin(), progress_cancel.end(), cancel), progress_cancel.end());
                            }
                        }
                    }

                    std::lock_guard<std::mutex> cancel_lock_guard(stream_cancel_lock);
                    if (!stream_cancel.empty()) {
                        for (auto& cancel : stream_cancel) {
                            if (cancel.first == id && cancel.second == reference) {
                                stream_cancel.erase(std::remove(stream_cancel.begin(), stream_cancel.end(), cancel), stream_cancel.end());
                            }
                        }
                    }
                }
            }
            stream_responses.clear();
        }

        lock_stream.unlock();

        if (sockets.size() > 0) {
            for (auto it = sockets.begin(); it != sockets.end(); ) {
                auto& socket_entry = *it;

                lua_State* L = Tracker::is_state(socket_entry.first);

                if (L != T) {
                    ++it;
                    continue;
                }

                auto& handlers = socket_entry.second;
                for (auto& socket : handlers) {
                    socket->dethreader();
                }

                ++it;
            }
        }

        if (serves.size() > 0) {
            for (auto it = serves.begin(); it != serves.end(); ) {
                auto& serve_entry = *it;

                lua_State* L = Tracker::is_state(serve_entry.first);

                if (L != T) {
                    ++it;
                    continue;
                }

                auto& handlers = serve_entry.second;
                for (auto& serve : handlers) {
                    serve.second->sync();
                }

                ++it;
            }
        }
    }

    void runtime()
    {
        std::unique_lock<std::mutex> lock_progress(http_progress_lock);

        if (http_progress.size() > 0) {
            for (auto it = http_progress.begin(); it != http_progress.end(); ) {
                auto& result = *it;
                uintptr_t id = std::get<0>(result);
                lua_State* L = Tracker::is_state(id);

                if (L == nullptr || Tracker::is_threaded(L)) {
                    ++it;
                    continue;
                }

                int reference = std::get<1>(result);
                std::string url = std::get<2>(result);
                cpr::cpr_off_t downloadTotal = std::get<3>(result);
                cpr::cpr_off_t downloadNow = std::get<4>(result);
                cpr::cpr_off_t uploadTotal = std::get<5>(result);
                cpr::cpr_off_t uploadNow = std::get<6>(result);

                if (downloadTotal == -1 && downloadNow == -1 && uploadTotal == -1 && uploadNow == -1) {
                    luaL::rmref(L, reference);
                    it = http_progress.erase(it);
                    continue;
                }

                lua::pushref(L, reference);

                lua::pushnumber(L, downloadTotal);
                lua::pushnumber(L, downloadNow);
                lua::pushnumber(L, uploadTotal);
                lua::pushnumber(L, uploadNow);

                if (lua::tcall(L, 4, 1)) {
                    std::string err = lua::tocstring(L, -1);
                    auto& on_error = get_on_error();
                    for (auto const& handle : on_error) handle.second(L, "progress - " + url, err);
                    std::lock_guard<std::mutex> cancel_lock_guard(progress_cancel_lock);
                    if (!progress_cancel.empty()) {
                        bool should = true;

                        for (auto& cancel : progress_cancel) {
                            if (cancel.first == id && cancel.second == reference) {
                                should = false;
                                break;
                            }
                        }

                        if (should) {
                            progress_cancel.push_back(std::pair<uintptr_t, int>(id, reference));
                        }
                    }
                }
                else if (lua::isboolean(L, -1) && lua::toboolean(L, -1) == false) {
                    std::lock_guard<std::mutex> cancel_lock_guard(progress_cancel_lock);
                    if (!progress_cancel.empty()) {
                        bool should = true;

                        for (auto& cancel : progress_cancel) {
                            if (cancel.first == id && cancel.second == reference) {
                                should = false;
                                break;
                            }
                        }

                        if (should) {
                            progress_cancel.push_back(std::pair<uintptr_t, int>(id, reference));
                        }
                    }
                }

                lua::pop(L);

                it = http_progress.erase(it);
            }
        }

        lock_progress.unlock();


        std::unique_lock<std::mutex> lock_http(http_response_lock);

        if (http_responses.size() > 0) {
            for (auto it = http_responses.begin(); it != http_responses.end(); ) {
                auto& result = *it;
                uintptr_t id = std::get<0>(result);
                lua_State* L = Tracker::is_state(id);

                if (L == nullptr || Tracker::is_threaded(L)) {
                    ++it;
                    continue;
                }

                int reference = std::get<1>(result);
                cpr::Response response = std::get<2>(result);

                lua::pushref(L, reference);
                luaL::rmref(L, reference);

                lua::newtable(L);

                lua::pushnumber(L, response.status_code);
                lua::setfield(L, -2, "status");

                lua::pushcstring(L, response.text);
                lua::setfield(L, -2, "body");

                lua::pushcstring(L, response.reason);
                lua::setfield(L, -2, "reason");

                lua::pushcstring(L, response.url.str());
                lua::setfield(L, -2, "url");

                lua::newtable(L);
                for (const auto& [key, value] : response.header)
                {
                    lua::pushcstring(L, key);
                    lua::pushcstring(L, value);
                    lua::settable(L, -3);
                }
                lua::setfield(L, -2, "headers");

                if (lua::tcall(L, 1, 0)) {
                    std::string err = lua::tocstring(L, -1);
                    lua::pop(L);
                    auto& on_error = get_on_error();
                    for (auto const& handle : on_error) handle.second(L, "http - " + response.url.str(), err);
                }

                it = http_responses.erase(it);

                std::lock_guard<std::mutex> progress_cancel_lock_guard(progress_cancel_lock);
                if (!progress_cancel.empty()) {
                    for (auto& cancel : progress_cancel) {
                        if (cancel.first == id && cancel.second == reference) {
                            progress_cancel.erase(std::remove(progress_cancel.begin(), progress_cancel.end(), cancel), progress_cancel.end());
                        }
                    }
                }
            }
        }

        lock_http.unlock();

        std::unique_lock<std::mutex> lock_stream(stream_response_lock);

        if (stream_responses.size() > 0)
        {
            for (auto it = stream_responses.begin(); it != stream_responses.end(); ) {
                auto& result = *it;
                uintptr_t id = std::get<0>(result);
                lua_State* L = Tracker::is_state(id);

                if (L == nullptr || Tracker::is_threaded(L)) {
                    ++it;
                    continue;
                }

                int reference = std::get<1>(result);
                cpr::Response response = std::get<2>(result);

                lua::pushref(L, reference);

                lua::newtable(L);

                lua::pushnumber(L, response.status_code);
                lua::setfield(L, -2, "status");

                lua::pushcstring(L, response.text);
                lua::setfield(L, -2, "body");

                lua::pushcstring(L, response.reason);
                lua::setfield(L, -2, "reason");

                lua::pushcstring(L, response.url.str());
                lua::setfield(L, -2, "url");

                lua::newtable(L);
                for (const auto& [key, value] : response.header)
                {
                    lua::pushcstring(L, key);
                    lua::pushcstring(L, value);
                    lua::settable(L, -3);
                }
                lua::setfield(L, -2, "headers");

                if (lua::tcall(L, 1, 1)) {
                    std::string err = lua::tocstring(L, -1);
                    auto& on_error = get_on_error();
                    for (auto const& handle : on_error) handle.second(L, "stream - " + response.url.str(), err);

                    std::lock_guard<std::mutex> cancel_lock_guard(stream_cancel_lock);
                    if (!stream_cancel.empty()) {
                        bool should = true;

                        for (auto& cancel : stream_cancel) {
                            if (cancel.first == id && cancel.second == reference) {
                                should = false;
                                break;
                            }
                        }

                        if (should) {
                            stream_cancel.push_back(std::pair<uintptr_t, int>(id, reference));
                        }
                    }
                }
                else if (lua::isboolean(L, -1) && lua::toboolean(L, -1) == false) {
                    std::lock_guard<std::mutex> cancel_lock_guard(stream_cancel_lock);
                    if (!stream_cancel.empty()) {
                        bool should = true;

                        for (auto& cancel : stream_cancel) {
                            if (cancel.first == id && cancel.second == reference) {
                                should = false;
                                break;
                            }
                        }

                        if (should) {
                            stream_cancel.push_back(std::pair<uintptr_t, int>(id, reference));
                        }
                    }
                }

                it = stream_responses.erase(it);
                lua::pop(L);

                if (response.status_code != 100) {
                    luaL::rmref(L, reference);

                    std::lock_guard<std::mutex> progress_cancel_lock_guard(progress_cancel_lock);
                    if (!progress_cancel.empty()) {
                        for (auto& cancel : progress_cancel) {
                            if (cancel.first == id && cancel.second == reference) {
                                progress_cancel.erase(std::remove(progress_cancel.begin(), progress_cancel.end(), cancel), progress_cancel.end());
                            }
                        }
                    }

                    std::lock_guard<std::mutex> cancel_lock_guard(stream_cancel_lock);
                    if (!stream_cancel.empty()) {
                        for (auto& cancel : stream_cancel) {
                            if (cancel.first == id && cancel.second == reference) {
                                stream_cancel.erase(std::remove(stream_cancel.begin(), stream_cancel.end(), cancel), stream_cancel.end());
                            }
                        }
                    }
                }
            }
            stream_responses.clear();
        }

        lock_stream.unlock();

        if (sockets.size() > 0) {
            for (auto it = sockets.begin(); it != sockets.end(); ) {
                auto& socket_entry = *it;

                lua_State* L = Tracker::is_state(socket_entry.first);

                if (L == nullptr || Tracker::is_threaded(L)) {
                    ++it;
                    continue;
                }

                auto& handlers = socket_entry.second;
                for (auto& socket : handlers) {
                    socket->dethreader();
                }

                ++it;
            }
        }

        if (serves.size() > 0) {
            for (auto it = serves.begin(); it != serves.end(); ) {
                auto& serve_entry = *it;

                lua_State* L = Tracker::is_state(serve_entry.first);

                if (L == nullptr || Tracker::is_threaded(L)) {
                    ++it;
                    continue;
                }

                auto& handlers = serve_entry.second;
                for (auto& serve : handlers) {
                    serve.second->sync();
                }

                ++it;
            }
        }
    }

    void push(lua_State* L, UMODULE hndle)
    {
        std::vector<std::pair<int, std::string>> to_insert;

        lua::newtable(L);

        lua::pushcfunction(L, http);
        lua::setfield(L, -2, "http");

        lua::pushcfunction(L, stream);
        lua::setfield(L, -2, "stream");

        lua::pushcfunction(L, socket);
        lua::setfield(L, -2, "socket");

        lua::pushcfunction(L, serve);
        lua::setfield(L, -2, "serve");

        lua::newtable(L);

        lua::pushstring(L, "GET");
        lua::setfield(L, -2, "get");
        lua::pushstring(L, "HEAD");
        lua::setfield(L, -2, "head");
        lua::pushstring(L, "POST");
        lua::setfield(L, -2, "post");
        lua::pushstring(L, "PUT");
        lua::setfield(L, -2, "put");
        lua::pushstring(L, "DELETE");
        lua::setfield(L, -2, "delete");
        lua::pushstring(L, "OPTION");
        lua::setfield(L, -2, "option");
        lua::pushstring(L, "PATCH");
        lua::setfield(L, -2, "patch");

        lua::setfield(L, -2, "method");

        lua::newtable(L);

        lua::pushnumber(L, (uint8_t)rws::opcode_t::continuation_frame);
        lua::setfield(L, -2, "continuation");
        lua::pushnumber(L, (uint8_t)rws::opcode_t::text_frame);
        lua::setfield(L, -2, "text");
        lua::pushnumber(L, (uint8_t)rws::opcode_t::binary_frame);
        lua::setfield(L, -2, "binary");
        lua::pushnumber(L, (uint8_t)rws::opcode_t::connection_close_frame);
        lua::setfield(L, -2, "close");
        lua::pushnumber(L, (uint8_t)rws::opcode_t::ping_frame);
        lua::setfield(L, -2, "ping");
        lua::pushnumber(L, (uint8_t)rws::opcode_t::unknown_frame);
        lua::setfield(L, -2, "unknown");

        to_insert.clear();

        lua::pushnil(L);
        while (lua::next(L, -2) != 0) {
            if (lua::isstring(L, -2) && lua::isnumber(L, -1)) {
                std::string key = lua::tocstring(L, -2);
                int value = (int)lua::tonumber(L, -1);
                to_insert.emplace_back(value, std::string(key));
            }
            lua::pop(L, 1);
        }

        for (auto& [key, value] : to_insert) {
            lua::pushnumber(L, key);
            lua::pushstring(L, value.c_str());
            lua::settable(L, -3);
        }

        lua::setfield(L, -2, "opcode");

        lua::newtable(L);

        lua::pushnumber(L, (uint16_t)rws::status_code_t::normal_closure);
        lua::setfield(L, -2, "normal");
        lua::pushnumber(L, (uint16_t)rws::status_code_t::going_away);
        lua::setfield(L, -2, "going_away");
        lua::pushnumber(L, (uint16_t)rws::status_code_t::protocol_error);
        lua::setfield(L, -2, "protocol_error");
        lua::pushnumber(L, (uint16_t)rws::status_code_t::cant_accept_data);
        lua::setfield(L, -2, "cant_accept_data");
        lua::pushnumber(L, (uint16_t)rws::status_code_t::no_status_provided);
        lua::setfield(L, -2, "no_status_provided");
        lua::pushnumber(L, (uint16_t)rws::status_code_t::connection_lost);
        lua::setfield(L, -2, "connection_lost");
        lua::pushnumber(L, (uint16_t)rws::status_code_t::invalid_message_data);
        lua::setfield(L, -2, "invalid_message_data");
        lua::pushnumber(L, (uint16_t)rws::status_code_t::policy_violation);
        lua::setfield(L, -2, "policy_violation");
        lua::pushnumber(L, (uint16_t)rws::status_code_t::too_big_message);
        lua::setfield(L, -2, "too_big_message");
        lua::pushnumber(L, (uint16_t)rws::status_code_t::more_extensions_expected);
        lua::setfield(L, -2, "more_extensions_expected");
        lua::pushnumber(L, (uint16_t)rws::status_code_t::unexpected_condition);
        lua::setfield(L, -2, "unexpected_condition");

        to_insert.clear();

        lua::pushnil(L);
        while (lua::next(L, -2) != 0) {
            if (lua::isstring(L, -2) && lua::isnumber(L, -1)) {
                std::string key = lua::tocstring(L, -2);
                int value = (int)lua::tonumber(L, -1);
                to_insert.emplace_back(value, std::string(key));
            }
            lua::pop(L, 1);
        }

        for (auto& [key, value] : to_insert) {
            lua::pushnumber(L, key);
            lua::pushstring(L, value.c_str());
            lua::settable(L, -3);
        }

        lua::setfield(L, -2, "closure");

        lua::newtable(L);

        for (uint16_t i = 100; i < 600; i++) {
            restinio::http_status_line_t line = get_status(i);
            if (i != 200) {
                if (line.status_code().raw_code() == 200) {
                    continue;
                }
            }

            lua::pushnumber(L, i);
            lua::pushcstring(L, line.reason_phrase());
            lua::settable(L, -3);

            lua::pushcstring(L, line.reason_phrase());
            lua::pushnumber(L, i);
            lua::settable(L, -3);
        }

        lua::setfield(L, -2, "status");
    }

    void cleanup(lua_State* L)
    {
        uintptr_t id = Tracker::id(L);

        if (http_progress.size() > 0) {
            for (auto it = http_progress.begin(); it != http_progress.end(); ) {
                auto& result = *it;
                uintptr_t id = std::get<0>(result);

                if ((lua_State*)id == L) {
                    it = http_progress.erase(it);
                    continue;
                }

                ++it;
            }
        }

        if (http_responses.size() > 0) {
            for (auto it = http_responses.begin(); it != http_responses.end(); ) {
                auto& result = *it;
                uintptr_t id = std::get<0>(result);

                if ((lua_State*)id == L) {
                    it = http_responses.erase(it);
                    continue;
                }

                ++it;
            }
        }

        if (serves.size() > 0) {
            for (auto& serve_entry : serves) {
                if (serve_entry.first != id) continue;
                for (auto& entry : serve_entry.second) {
                    serve_entry.second.erase(entry.first);
                    delete entry.second;
                }
            }
            serves.erase(Tracker::id(L));
        }
    }

    void api() {
        Tracker::on_close("iot", cleanup);
        Reflection::on_threaded("iot", runtime_threaded);
        Reflection::on_runtime("iot", runtime);
        Reflection::add("iot", push);
    }
}