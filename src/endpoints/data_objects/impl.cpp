#include "handlers.hpp"

#include "common.hpp"
#include "crlf_parser.hpp"
#include "globals.hpp"
#include "log.hpp"
#include "session.hpp"
#include "version.hpp"

#include <irods/client_connection.hpp>
#include <irods/connection_pool.hpp>
#include <irods/dataObjRepl.h>
#include <irods/dataObjTrim.h>
#include <irods/filesystem.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_exception.hpp>
#include <irods/phyPathReg.h>
#include <irods/rcMisc.h>
#include <irods/rodsErrorTable.h>
#include <irods/rodsKeyWdDef.h>
#include <irods/touch.h>

#include <irods/transport/default_transport.hpp>
#include <irods/dstream.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>

#include <nlohmann/json.hpp>

#include <atomic>
#include <mutex>
#include <span>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// clang-format off
namespace beast = boost::beast;     // from <boost/beast.hpp>
namespace http  = beast::http;      // from <boost/beast/http.hpp>
namespace net   = boost::asio;      // from <boost/asio.hpp>

namespace fs  = irods::experimental::filesystem;
namespace io  = irods::experimental::io;
namespace log = irods::http::log;

using json = nlohmann::json;
// clang-format on

#define IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(name) \
    auto name(irods::http::session_pointer_type _sess_ptr, irods::http::request_type& _req, irods::http::query_arguments_type& _args) -> void

namespace
{
    using handler_type = void(*)(irods::http::session_pointer_type, irods::http::request_type&, irods::http::query_arguments_type&);

    class parallel_write_stream
    {
      public:
        // TODO May need to accept a zone for the client (i.e. federation).
        parallel_write_stream(const std::string& _client_username,
                              const std::string& _path,
                              const irods::experimental::io::odstream* _base = nullptr)
        {
            const auto& client = irods::http::globals::configuration().at("irods_client");
            const auto& zone = client.at("zone").get_ref<const std::string&>();
            const auto& rodsadmin = client.at("rodsadmin");

            conn_.connect(irods::experimental::defer_authentication,
                          client.at("host").get_ref<const std::string&>(),
                          client.at("port").get<int>(),
                          {rodsadmin.at("username").get_ref<const std::string&>(), zone},
                          {_client_username, zone});

            auto password = rodsadmin.at("password").get<std::string>();

            if (clientLoginWithPassword(static_cast<RcComm*>(conn_), password.data()) != 0) {
                conn_.disconnect();
                THROW(SYS_INTERNAL_ERR, "Could not connect to iRODS server as proxied user.");
            }

            tp_ = std::make_unique<irods::experimental::io::client::native_transport>(conn_);

            // TODO Handle truncate and append.
            if (_base) {
                stream_.open(*tp_, _base->replica_token(), _path, _base->replica_number(), std::ios::out);
            }
            else {
                stream_.open(*tp_, _path);
            }

            if (!stream_) {
                tp_.reset();
                conn_.disconnect();
                THROW(SYS_INTERNAL_ERR, fmt::format("Could not open output stream for [{}].", _path));
            }
        } // parallel_write_stream (constructor)

        auto stream() noexcept -> irods::experimental::io::odstream&
        {
            return stream_;
        } // stream

        auto is_in_use() const noexcept -> bool
        {
            return in_use_.load();
        } // is_in_use

        auto in_use(bool _value) noexcept -> void
        {
            in_use_.store(_value);
        } // in_use

      private:
        irods::experimental::client_connection conn_{irods::experimental::defer_connection};
        std::unique_ptr<irods::experimental::io::client::native_transport> tp_;
        irods::experimental::io::odstream stream_;
        std::atomic<bool> in_use_{false};
    }; // class parallel_write_stream

    struct parallel_write_context
    {
        std::vector<std::shared_ptr<parallel_write_stream>> streams;
        std::unique_ptr<std::mutex> mtx;

        auto find_available_parallel_write_stream() -> parallel_write_stream*
        {
            std::scoped_lock lk{*mtx};

            auto iter = std::find_if(std::begin(streams), std::end(streams), [](auto& _stream) {
                return !_stream->is_in_use();
            });

            if (iter == std::end(streams)) {
                return nullptr;
            }

            (*iter)->in_use(true);

            return (*iter).get();
        } // find_available_parallel_write_stream
    }; // struct parallel_write_context

    std::shared_mutex pwc_mtx;
    std::unordered_map<std::string, parallel_write_context> parallel_write_contexts;

    //
    // Handler function prototypes
    //

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_read_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_write_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_parallel_write_init_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_parallel_write_shutdown_op);

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_replicate_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_trim_op);

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_set_permission_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_stat_op);

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_register_op);

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_rename_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_copy_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_remove_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_touch_op);

    //
    // Operation to Handler mappings
    //

    const std::unordered_map<std::string, handler_type> handlers_for_get{
        {"read", handle_read_op},
        {"stat", handle_stat_op}
    };

    const std::unordered_map<std::string, handler_type> handlers_for_post{
        {"touch", handle_touch_op},
        {"remove", handle_remove_op},

        {"write", handle_write_op},
        {"parallel_write_init", handle_parallel_write_init_op},
        {"parallel_write_shutdown", handle_parallel_write_shutdown_op},

        {"rename", handle_rename_op},
        {"copy", handle_copy_op},

        {"replicate", handle_replicate_op},
        {"trim", handle_trim_op},

        {"register", handle_register_op},

        {"set_permission", handle_set_permission_op}

        //{"calculate_checksum", handle_calculate_checksum},
        //{"register_checksum", handle_register_checksum},
        //{"verify_checksum", handle_verify_checksum},
    };
} // anonymous namespace

namespace irods::http::handler
{
    // NOLINTNEXTLINE(performance-unnecessary-value-param)
    IRODS_HTTP_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE(data_objects)
    {
        if (_req.method() == verb_type::get) {
            auto url = irods::http::parse_url(_req);

            const auto op_iter = url.query.find("op");
            if (op_iter == std::end(url.query)) {
                log::error("{}: Missing [op] parameter.", __func__);
                return _sess_ptr->send(irods::http::fail(status_type::bad_request));
            }

            if (const auto iter = handlers_for_get.find(op_iter->second); iter != std::end(handlers_for_get)) {
                return (iter->second)(_sess_ptr, _req, url.query);
            }

            return _sess_ptr->send(fail(status_type::bad_request));
        }

        if (_req.method() == verb_type::post) {
            query_arguments_type args;

            if (auto content_type = _req.base()["content-type"]; boost::istarts_with(content_type, "multipart/form-data")) {
                const auto boundary = irods::http::get_multipart_form_data_boundary(content_type);

                if (!boundary) {
                    log::error("{}: Could not extract [boundary] from [Content-Type] header. ", __func__);
                    return _sess_ptr->send(irods::http::fail(status_type::bad_request));
                }

                args = irods::http::parse_multipart_form_data(*boundary, _req.body());
            }
#if 0
            else if (boost::istarts_with(content_type, "application/x-www-form-urlencoded")) {
                args = irods::http::to_argument_list(_req.body());
            }
            else {
                log::error("{}: Invalid value for [Content-Type] header.", __func__);
                return _sess_ptr->send(irods::http::fail(status_type::bad_request));
            }
#else
            else {
                args = irods::http::to_argument_list(_req.body());
            }
#endif

            const auto op_iter = args.find("op");
            if (op_iter == std::end(args)) {
                log::error("{}: Missing [op] parameter.", __func__);
                return _sess_ptr->send(irods::http::fail(status_type::bad_request));
            }

            if (const auto iter = handlers_for_post.find(op_iter->second); iter != std::end(handlers_for_post)) {
                return (iter->second)(_sess_ptr, _req, args);
            }

            return _sess_ptr->send(fail(status_type::bad_request));
        }

        log::error("{}: Incorrect HTTP method.", __func__);
        return _sess_ptr->send(irods::http::fail(status_type::method_not_allowed));
    } // data_objects
} // namespace irods::http::handler

namespace
{
    //
    // Operation handler implementations
    //

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_read_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto lpath_iter = _args.find("lpath");
                if (lpath_iter == std::end(_args)) {
                    log::error("{}: Missing [lpath] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                auto conn = irods::get_connection(client_info->username);
                io::client::native_transport tp{conn};
                io::idstream in{tp, lpath_iter->second};

                if (!in) {
                    log::error("{}: Could not open data object [{}] for read.", fn, lpath_iter->second);
                    res.result(http::status::bad_request);
                    res.prepare_payload();
                    return _sess_ptr->send(std::move(res));
                }

                auto iter = _args.find("offset");
                if (iter != std::end(_args)) {
                    try {
                        in.seekg(std::stoll(iter->second));
                    }
                    catch (const std::exception& e) {
                        log::error("{}: Could not seek to position [{}] in data object [{}].", fn, iter->second, lpath_iter->second);
                        res.result(http::status::bad_request);
                        res.prepare_payload();
                        return _sess_ptr->send(std::move(res));
                    }
                }

                std::vector<char> buffer;

                iter = _args.find("count");
                if (iter != std::end(_args)) {
                    try {
                        const auto count = std::stoi(iter->second);

                        if (count > irods::http::globals::configuration().at(json::json_pointer{"/irods_client/max_rbuffer_size_in_bytes"}).get<int>()) {
                            res.result(http::status::bad_request);
                            res.prepare_payload();
                            return _sess_ptr->send(std::move(res));
                        }

                        buffer.resize(count);
                    }
                    catch (const std::exception& e) {
                        log::error("{}: Could not initialize read buffer to size [{}] for data object [{}].", fn, iter->second, lpath_iter->second);
                        res.result(http::status::bad_request);
                        res.prepare_payload();
                        return _sess_ptr->send(std::move(res));
                    }
                }
                else {
                    res.result(http::status::bad_request);
                    res.prepare_payload();
                    return _sess_ptr->send(std::move(res));
                }

                in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));

                res.set(http::field::content_type, "application/octet-stream");
                res.body() = std::string_view(buffer.data(), in.gcount());
            }
            catch (const fs::filesystem_error& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code().value()},
                        {"error_message", e.what()}
                    }}
                }.dump();
            }
            catch (const irods::exception& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code()},
                        {"error_message", e.client_display_what()}
                    }}
                }.dump();
            }
            catch (const std::exception& e) {
                res.result(http::status::internal_server_error);
            }

            res.prepare_payload();

            _sess_ptr->send(std::move(res));
        });
    } // handle_read_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_write_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                irods::connection_pool::connection_proxy conn;
                std::unique_ptr<io::client::native_transport> tp;

                std::unique_ptr<io::odstream> out;
                io::odstream* out_ptr{};

                const auto parallel_write_handle_iter = _args.find("parallel-write-handle"); 

                using at_scope_exit_type = irods::at_scope_exit<std::function<void()>>;
                std::unique_ptr<at_scope_exit_type> mark_pw_stream_as_usable;

                if (parallel_write_handle_iter != std::end(_args)) {
                    log::debug("{}: (write) Parallel Write Handle = [{}].", fn, parallel_write_handle_iter->second);

                    decltype(parallel_write_contexts)::iterator iter;

                    {
                        std::shared_lock lk{pwc_mtx};

                        iter = parallel_write_contexts.find(parallel_write_handle_iter->second);
                        if (iter == std::end(parallel_write_contexts)) {
                            log::error("{}: Invalid handle for parallel write.", fn);
                            return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                        }
                    }

                    //
                    // We've found a matching handle!
                    //

                    if (const auto stream_index_iter = _args.find("stream-index"); stream_index_iter != std::end(_args)) {
                        log::debug("{}: Client selected [{}] for [stream-index] parameter.", fn, stream_index_iter->second);

                        try {
                            const auto sindex = std::stoi(stream_index_iter->second);
                            out_ptr = &iter->second.streams.at(sindex)->stream();
                        }
                        catch (const std::exception& e) {
                            log::error("{}: Invalid argument for [stream-index] parameter.");
                            return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                        }
                    }
                    else {
                        auto* pw_stream = iter->second.find_available_parallel_write_stream();
                        if (!pw_stream) {
                            log::error("{}: Parallel write streams are busy. Client must wait for one to become available.", fn);
                            return _sess_ptr->send(irods::http::fail(res, http::status::too_many_requests));
                        }

                        mark_pw_stream_as_usable = std::make_unique<at_scope_exit_type>([pw_stream] { pw_stream->in_use(false); });

                        out_ptr = &pw_stream->stream();
                    }

                    log::debug("{}: (write) Parallel Write - stream memory address = [{}].", fn, fmt::ptr(out_ptr));
                }
                else {
                    const auto lpath_iter = _args.find("lpath");
                    if (lpath_iter == std::end(_args)) {
                        log::error("{}: Missing [lpath] parameter.", fn);
                        return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                    }

                    log::trace("{}: Opening data object [{}] for write.", fn, lpath_iter->second);
                    log::trace("{}: (write) Initializing for single buffer write.", fn);

                    conn = irods::get_connection(client_info->username);
                    tp = std::make_unique<io::client::native_transport>(conn);
                    out = std::make_unique<io::odstream>(*tp, lpath_iter->second);
                    out_ptr = out.get();
                }

                if (!*out_ptr) {
                    log::error("{}: Could not open data object for write.", fn);
                    res.result(http::status::internal_server_error);
                    res.prepare_payload();
                    return _sess_ptr->send(std::move(res));
                }

                auto iter = _args.find("offset");
                if (iter != std::end(_args)) {
                    log::trace("{}: Setting offset for write.", fn);
                    try {
                        out_ptr->seekp(std::stoll(iter->second));
                    }
                    catch (const std::exception& e) {
                        log::error("{}: Could not seek to position [{}] in data object.", fn, iter->second);
                        res.result(http::status::bad_request);
                        res.prepare_payload();
                        return _sess_ptr->send(std::move(res));
                    }
                }

                iter = _args.find("count");
                if (iter == std::end(_args)) {
                    log::error("{}: Missing [count] parameter.", fn);
                    res.result(http::status::bad_request);
                    res.prepare_payload();
                    return _sess_ptr->send(std::move(res));
                }
                const auto count = std::stoll(iter->second);

                static const auto max_wbuffer_size = irods::http::globals::configuration().at(json::json_pointer{"/irods_client/max_wbuffer_size_in_bytes"}).get<std::int64_t>();
                if (count > max_wbuffer_size) {
                    log::error("{}: Argument for [count] parameter exceeds [/irods_client/wbuffer_size_in_bytes].", fn);
                    res.result(http::status::bad_request);
                    res.prepare_payload();
                    return _sess_ptr->send(std::move(res));
                }

                iter = _args.find("bytes");
                if (iter == std::end(_args)) {
                    log::error("{}: Missing [bytes] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                log::debug("{}: Write buffer: size=[{}], count=[{}].", fn, iter->second.size(), count);
                out_ptr->write(iter->second.data(), count);

                res.body() = json{
                    {"irods_response", {
                        {"error_code", 0}
                    }}
                }.dump();
            }
            catch (const fs::filesystem_error& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code().value()},
                        {"error_message", e.what()}
                    }}
                }.dump();
            }
            catch (const irods::exception& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code()},
                        {"error_message", e.client_display_what()}
                    }}
                }.dump();
            }
            catch (const std::exception& e) {
                res.result(http::status::internal_server_error);
            }

            res.prepare_payload();

            _sess_ptr->send(std::move(res));
        });
    } // handle_write_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_parallel_write_init_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto lpath_iter = _args.find("lpath");
                if (lpath_iter == std::end(_args)) {
                    log::error("{}: Missing [lpath] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto stream_count_iter = _args.find("stream-count");
                if (stream_count_iter == std::end(_args)) {
                    log::error("{}: Missing [stream-count] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto stream_count = std::stoi(stream_count_iter->second);
                if (stream_count > irods::http::globals::configuration().at(json::json_pointer{"/irods_client/max_number_of_parallel_write_streams"}).get<int>()) {
                    log::error("{}: Argument for [stream-count] parameter exceeds maximum number of streams allowed.", fn, stream_count_iter->second);
                    res.result(http::status::bad_request);
                    res.prepare_payload();
                    return _sess_ptr->send(std::move(res));
                }

                namespace io = irods::experimental::io;

                log::trace("{}: Opening initial output stream to [{}].", fn, lpath_iter->second);

                std::vector<std::shared_ptr<parallel_write_stream>> pw_streams;
                pw_streams.reserve(stream_count);

                try {
                    // Open the first stream.
                    pw_streams.emplace_back(std::make_shared<parallel_write_stream>(client_info->username, lpath_iter->second));

                    auto& first_stream = pw_streams.front()->stream();
                    log::debug("{}: replica token=[{}], replica number=[{}], leaf resource name=[{}]",
                               fn,
                               first_stream.replica_token().value,
                               first_stream.replica_number().value,
                               first_stream.leaf_resource_name().value);

                    // Open secondary streams using the first stream as a base.
                    for (int i = 0; i < stream_count; ++i) {
                        pw_streams.emplace_back(std::make_shared<parallel_write_stream>(client_info->username,
                                                                                        lpath_iter->second,
                                                                                        &pw_streams.front()->stream()));
                    }
                }
                catch (const irods::exception& e) {
                    log::error("{}: Could not open one or more output streams to [{}].", fn, lpath_iter->second);
                    res.result(http::status::internal_server_error);
                    res.prepare_payload();
                    return _sess_ptr->send(std::move(res));
                }

                std::string transfer_handle;
                decltype(parallel_write_contexts)::iterator pwc_iter;

                {
                    std::scoped_lock lk{pwc_mtx};

                    transfer_handle = irods::generate_uuid(parallel_write_contexts);
                    log::debug("{}: (init) Parallel Write Handle = [{}].", fn, transfer_handle);

                    auto [iter, insertion_result] = parallel_write_contexts.emplace(transfer_handle, parallel_write_context{});
                    if (!insertion_result) {
                        log::error("{}: Could not initialize parallel write context for [{}].", fn, lpath_iter->second);
                        res.result(http::status::internal_server_error);
                        res.prepare_payload();
                        return _sess_ptr->send(std::move(res));
                    }

                    pwc_iter = iter;
                }

                auto& pw_context = pwc_iter->second;
                pw_context.streams = std::move(pw_streams);
                pw_context.mtx = std::make_unique<std::mutex>();

                res.body() = json{
                    {"irods_response", {
                        {"error_code", 0},
                    }},
                    {"parallel_write_handle", transfer_handle}
                }.dump();
            }
            catch (const fs::filesystem_error& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code().value()},
                        {"error_message", e.what()}
                    }}
                }.dump();
            }
            catch (const irods::exception& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code()},
                        {"error_message", e.client_display_what()}
                    }}
                }.dump();
            }
            catch (const std::exception& e) {
                res.result(http::status::internal_server_error);
            }

            res.prepare_payload();

            _sess_ptr->send(std::move(res));
        });
    } // handle_parallel_write_init_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_parallel_write_shutdown_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                // 1. Verify transfer handle and lookup PTC.
                // 2. Close all streams in reverse order.
                // 3. Disassociate the transfer handle and PTC.
                // 4. Free resources.

                const auto parallel_write_handle_iter = _args.find("parallel-write-handle");
                if (parallel_write_handle_iter == std::end(_args)) {
                    log::error("{}: Missing [parallel-write-handle] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(http::status::bad_request));
                }

                log::debug("{}: (shutdown) Parallel Write Handle = [{}].", fn, parallel_write_handle_iter->second);

                {
                    std::scoped_lock lk{pwc_mtx};

                    const auto pw_iter = parallel_write_contexts.find(parallel_write_handle_iter->second);
                    if (pw_iter != std::end(parallel_write_contexts)) {
                        // Ignore the first stream. It must be closed last so that replication resources
                        // are triggered correctly.
                        auto end = std::prev(std::rend(pw_iter->second.streams));

                        io::on_close_success close_input{};
                        close_input.update_size = false;
                        close_input.update_status = false;
                        close_input.compute_checksum = false;
                        close_input.send_notifications = false;
                        close_input.preserve_replica_state_table = false;

                        for (auto iter = std::rbegin(pw_iter->second.streams); iter != end; ++iter) {
                            (*iter)->stream().close(&close_input);
                        }

                        // Allow the first stream to update the catalog.
                        pw_iter->second.streams.front()->stream().close();

                        parallel_write_contexts.erase(pw_iter);
                    }
                }

                res.body() = json{
                    {"irods_response", {
                        {"error_code", 0},
                    }}
                }.dump();
            }
            catch (const fs::filesystem_error& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code().value()},
                        {"error_message", e.what()}
                    }}
                }.dump();
            }
            catch (const irods::exception& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code()},
                        {"error_message", e.client_display_what()}
                    }}
                }.dump();
            }
            catch (const std::exception& e) {
                res.result(http::status::internal_server_error);
            }

            res.prepare_payload();

            _sess_ptr->send(std::move(res));
        });
    } // handle_parallel_write_shutdown_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_replicate_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                DataObjInp input{};
                irods::at_scope_exit free_memory{[&input] { clearKeyVal(&input.condInput); }};

                if (const auto iter = _args.find("lpath"); iter != std::end(_args)) {
                    std::strncpy(input.objPath, iter->second.c_str(), sizeof(DataObjInp::objPath));
                }
                else {
                    log::error("{}: Missing [lpath] parameter.", __func__);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                if (const auto iter = _args.find("dst-resource"); iter != std::end(_args)) {
                    addKeyVal(&input.condInput, DEST_RESC_NAME_KW, iter->second.c_str());
                }
                else {
                    log::error("{}: Missing [dst-resource] parameter.", __func__);
                    return _sess_ptr->send(irods::http::fail(http::status::bad_request));
                }

                if (const auto iter = _args.find("src-resource"); iter != std::end(_args)) {
                    addKeyVal(&input.condInput, RESC_NAME_KW, iter->second.c_str());
                }

                if (const auto iter = _args.find("admin"); iter != std::end(_args) && iter->second == "1") {
                    addKeyVal(&input.condInput, ADMIN_KW, "");
                }

                auto conn = irods::get_connection(client_info->username);
                const auto ec = rcDataObjRepl(static_cast<RcComm*>(conn), &input);

                res.body() = json{
                    {"irods_response", {
                        {"error_code", ec},
                    }},
                }.dump();
            }
            catch (const irods::exception& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code()},
                        {"error_message", e.client_display_what()}
                    }}
                }.dump();
            }
            catch (const std::exception& e) {
                res.result(http::status::internal_server_error);
            }

            res.prepare_payload();

            _sess_ptr->send(std::move(res));
        });
    } // handle_replicate_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_trim_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                DataObjInp input{};
                irods::at_scope_exit free_memory{[&input] { clearKeyVal(&input.condInput); }};

                if (const auto iter = _args.find("lpath"); iter != std::end(_args)) {
                    std::strncpy(input.objPath, iter->second.c_str(), sizeof(DataObjInp::objPath));
                }
                else {
                    log::error("{}: Missing [lpath] parameter.", __func__);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                {
                    const auto resc_iter = _args.find("resource");
                    const auto found_resc = (resc_iter != std::end(_args));

                    const auto repl_iter = _args.find("replica-number");
                    const auto found_repl = (repl_iter != std::end(_args));

                    if (found_resc && found_repl) {
                        log::error("{}: [resource] and [replica-number] cannot be used at the same time.", __func__);
                        return _sess_ptr->send(irods::http::fail(http::status::bad_request));
                    }

                    if (found_resc) {
                        addKeyVal(&input.condInput, RESC_NAME_KW, resc_iter->second.c_str());
                    }
                    else if (found_repl) {
                        addKeyVal(&input.condInput, REPL_NUM_KW, repl_iter->second.c_str());
                    }
                    else {
                        log::error("{}: Missing parameter: [resource] or [replica-number]", __func__);
                        return _sess_ptr->send(irods::http::fail(http::status::bad_request));
                    }
                }

                if (const auto iter = _args.find("unregister"); iter != std::end(_args) && iter->second == "1") {
                    input.oprType = UNREG_OPR;
                }

                if (const auto iter = _args.find("admin"); iter != std::end(_args) && iter->second == "1") {
                    addKeyVal(&input.condInput, ADMIN_KW, "");
                }

                auto conn = irods::get_connection(client_info->username);
                const auto ec = rcDataObjTrim(static_cast<RcComm*>(conn), &input);

                res.body() = json{
                    {"irods_response", {
                        {"error_code", ec},
                    }},
                }.dump();
            }
            catch (const irods::exception& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code()},
                        {"error_message", e.client_display_what()}
                    }}
                }.dump();
            }
            catch (const std::exception& e) {
                res.result(http::status::internal_server_error);
            }

            res.prepare_payload();

            _sess_ptr->send(std::move(res));
        });
    } // handle_trim_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_set_permission_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto lpath_iter = _args.find("lpath");
                if (lpath_iter == std::end(_args)) {
                    log::error("{}: Missing [lpath] parameter.", __func__);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                auto conn = irods::get_connection(client_info->username);

                if (!fs::client::is_data_object(conn, lpath_iter->second)) {
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request, json{
                        {"irods_response", {
                            {"error_code", NOT_A_DATA_OBJECT}
                        }}
                    }.dump()));
                }

                const auto entity_name_iter = _args.find("entity-name");
                if (entity_name_iter == std::end(_args)) {
                    log::error("{}: Missing [entity-name] parameter.", __func__);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto perm_iter = _args.find("permission");
                if (perm_iter == std::end(_args)) {
                    log::error("{}: Missing [permission] parameter.", __func__);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto perm_enum = irods::to_permission_enum(perm_iter->second);
                if (!perm_enum) {
                    log::error("{}: Invalid value for [permission] parameter.", __func__);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto admin_mode_iter = _args.find("admin");
                if (admin_mode_iter != std::end(_args) && admin_mode_iter->second == "1") {
                    fs::client::permissions(fs::admin, conn, lpath_iter->second, entity_name_iter->second, *perm_enum);
                }
                else {
                    fs::client::permissions(conn, lpath_iter->second, entity_name_iter->second, *perm_enum);
                }

                res.body() = json{
                    {"irods_response", {
                        {"error_code", 0},
                    }}
                }.dump();
            }
            catch (const fs::filesystem_error& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code().value()},
                        {"error_message", e.what()}
                    }}
                }.dump();
            }
            catch (const irods::exception& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code()},
                        {"error_message", e.client_display_what()}
                    }}
                }.dump();
            }
            catch (const std::exception& e) {
                res.result(http::status::internal_server_error);
            }

            res.prepare_payload();

            _sess_ptr->send(std::move(res));
        });
    } // handle_set_permission_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_stat_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto lpath_iter = _args.find("lpath");
                if (lpath_iter == std::end(_args)) {
                    log::error("{}: Missing [lpath] parameter.", __func__);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                auto conn = irods::get_connection(client_info->username);

                const auto status = fs::client::status(conn, lpath_iter->second);

                if (!fs::client::is_data_object(status)) {
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request, json{
                        {"irods_response", {
                            {"error_code", NOT_A_DATA_OBJECT}
                        }}
                    }.dump()));
                }

                json perms;
                for (auto&& ep : status.permissions()) {
                    perms.push_back(json{
                        {"name", ep.name},
                        {"zone", ep.zone},
                        {"type", ep.type},
                        {"perm", irods::to_permission_string(ep.prms)},
                    });
                }

                res.body() = json{
                    {"irods_response", {
                        {"error_code", 0},
                    }},
                    {"type", irods::to_object_type_string(status.type())},
                    {"permissions", perms},
                    {"size", fs::client::data_object_size(conn, lpath_iter->second)},
                    {"checksum", fs::client::data_object_checksum(conn, lpath_iter->second)},
                    {"registered", fs::client::is_data_object_registered(conn, lpath_iter->second)},
                    {"modified_at", fs::client::last_write_time(conn, lpath_iter->second).time_since_epoch().count()}
                }.dump();
            }
            catch (const fs::filesystem_error& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code().value()},
                        {"error_message", e.what()}
                    }}
                }.dump();
            }
            catch (const irods::exception& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code()},
                        {"error_message", e.client_display_what()}
                    }}
                }.dump();
            }
            catch (const std::exception& e) {
                res.result(http::status::internal_server_error);
            }

            res.prepare_payload();

            _sess_ptr->send(std::move(res));
        });
    } // handle_stat_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_register_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                DataObjInp input{};

                if (const auto lpath_iter = _args.find("lpath"); lpath_iter != std::end(_args)) {
                    std::strncpy(input.objPath, lpath_iter->second.c_str(), sizeof(DataObjInp::objPath) - 1);
                }
                else {
                    log::error("{}: Missing [lpath] parameter.", __func__);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                if (const auto iter = _args.find("ppath"); iter != std::end(_args)) {
                    addKeyVal(&input.condInput, FILE_PATH_KW, iter->second.c_str());
                }
                else {
                    log::error("{}: Missing [ppath] parameter.", __func__);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                if (const auto iter = _args.find("resource"); iter != std::end(_args)) {
                    addKeyVal(&input.condInput, DEST_RESC_NAME_KW, iter->second.c_str());
                }

                if (const auto iter = _args.find("replica-number"); iter != std::end(_args) && iter->second == "1") {
                    addKeyVal(&input.condInput, REG_REPL_KW, "");
                }

                if (const auto iter = _args.find("data-size"); iter != std::end(_args)) {
                    addKeyVal(&input.condInput, DATA_SIZE_KW, iter->second.c_str());
                }

                if (const auto iter = _args.find("checksum"); iter != std::end(_args)) {
                    if (iter->second == "register") {
                        addKeyVal(&input.condInput, REG_CHKSUM_KW, "");
                    }
                    else if (iter->second == "verify") {
                        addKeyVal(&input.condInput, VERIFY_CHKSUM_KW, "");
                    }
                }

                if (const auto iter = _args.find("force"); iter != std::end(_args)) {
                    addKeyVal(&input.condInput, FORCE_FLAG_KW, "");
                }

                auto conn = irods::get_connection(client_info->username);

                if (const auto ec = rcPhyPathReg(static_cast<RcComm*>(conn), &input); ec < 0) {
                    res.result(http::status::bad_request);
                    res.body() = json{
                        {"irods_response", {
                            {"error_code", ec},
                        }}
                    }.dump();
                    res.prepare_payload();
                    _sess_ptr->send(std::move(res));
                }

                res.body() = json{
                    {"irods_response", {
                        {"error_code", 0},
                    }}
                }.dump();
            }
            catch (const irods::exception& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code()},
                        {"error_message", e.client_display_what()}
                    }}
                }.dump();
            }
            catch (const std::exception& e) {
                res.result(http::status::internal_server_error);
            }

            res.prepare_payload();

            _sess_ptr->send(std::move(res));
        });
    } // handle_register_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_remove_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto lpath_iter = _args.find("lpath");
                if (lpath_iter == std::end(_args)) {
                    log::error("{}: Missing [lpath] parameter.", __func__);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                auto conn = irods::get_connection(client_info->username);

                if (!fs::client::is_data_object(conn, lpath_iter->second)) {
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request, json{
                        {"irods_response", {
                            {"error_code", NOT_A_DATA_OBJECT}
                        }}
                    }.dump()));
                }

                fs::extended_remove_options opts{};

                if (const auto iter = _args.find("no-trash"); iter != std::end(_args) && iter->second == "1") {
                    opts.no_trash = true;
                }

                if (const auto iter = _args.find("unregister"); iter != std::end(_args) && iter->second == "1") {
                    opts.unregister = true;
                }

                // There's no admin flag for removal.
                fs::client::remove(conn, lpath_iter->second, opts);

                res.body() = json{
                    {"irods_response", {
                        {"error_code", 0}
                    }}
                }.dump();
            }
            catch (const fs::filesystem_error& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code().value()},
                        {"error_message", e.what()}
                    }}
                }.dump();
            }
            catch (const irods::exception& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code()},
                        {"error_message", e.client_display_what()}
                    }}
                }.dump();
            }
            catch (const std::exception& e) {
                res.result(http::status::internal_server_error);
            }

            res.prepare_payload();

            _sess_ptr->send(std::move(res));
        });
    } // handle_remove_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_rename_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto old_lpath_iter = _args.find("old-lpath");
                if (old_lpath_iter == std::end(_args)) {
                    log::error("{}: Missing [old-lpath] parameter.", __func__);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                auto conn = irods::get_connection(client_info->username);

                if (!fs::client::is_data_object(conn, old_lpath_iter->second)) {
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request, json{
                        {"irods_response", {
                            {"error_code", NOT_A_DATA_OBJECT}
                        }}
                    }.dump()));
                }

                const auto new_lpath_iter = _args.find("new-lpath");
                if (new_lpath_iter == std::end(_args)) {
                    log::error("{}: Missing [new-lpath] parameter.", __func__);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                fs::client::rename(conn, old_lpath_iter->second, new_lpath_iter->second);

                res.body() = json{
                    {"irods_response", {
                        {"error_code", 0},
                    }}
                }.dump();
            }
            catch (const fs::filesystem_error& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code().value()},
                        {"error_message", e.what()}
                    }}
                }.dump();
            }
            catch (const irods::exception& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code()},
                        {"error_message", e.client_display_what()}
                    }}
                }.dump();
            }
            catch (const std::exception& e) {
                res.result(http::status::internal_server_error);
            }

            res.prepare_payload();

            _sess_ptr->send(std::move(res));
        });
    } // handle_rename_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_copy_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto src_lpath_iter = _args.find("src-lpath");
                if (src_lpath_iter == std::end(_args)) {
                    log::error("{}: Missing [src-lpath] parameter.", __func__);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto dst_lpath_iter = _args.find("dst-lpath");
                if (dst_lpath_iter == std::end(_args)) {
                    log::error("{}: Missing [dst-lpath] parameter.", __func__);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                fs::copy_options opts = fs::copy_options::none;

                if (const auto iter = _args.find("option"); iter != std::end(_args)) {
                    if (iter->second == "skip_existing") {
                        opts = fs::copy_options::skip_existing;
                    }
                    else if (iter->second == "overwrite_existing") {
                        opts = fs::copy_options::overwrite_existing;
                    }
                    else if (iter->second == "update_existing") {
                        opts = fs::copy_options::update_existing;
                    }
                    else if (iter->second != "none") {
                        return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                    }
                }

                auto conn = irods::get_connection(client_info->username);
                const auto copied = fs::client::copy_data_object(conn, src_lpath_iter->second, dst_lpath_iter->second, opts);

                res.body() = json{
                    {"irods_response", {
                        {"error_code", 0}
                    }},
                    {"copied", copied}
                }.dump();
            }
            catch (const fs::filesystem_error& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code().value() == INVALID_OBJECT_TYPE ? NOT_A_DATA_OBJECT : e.code().value()},
                        {"error_message", e.what()}
                    }}
                }.dump();
            }
            catch (const irods::exception& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code()},
                        {"error_message", e.client_display_what()}
                    }}
                }.dump();
            }
            catch (const std::exception& e) {
                res.result(http::status::internal_server_error);
            }

            res.prepare_payload();

            _sess_ptr->send(std::move(res));
        });
    } // handle_copy_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_touch_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto lpath_iter = _args.find("lpath");
                if (lpath_iter == std::end(_args)) {
                    log::error("{}: Missing [lpath] parameter.", __func__);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                json::object_t options;

                auto opt_iter = _args.find("no-create");
                if (opt_iter != std::end(_args)) {
                    options["no_create"] = (opt_iter->second == "1");
                }

                opt_iter = _args.find("replica-number");
                if (opt_iter != std::end(_args)) {
                    try {
                        options["replica_number"] = std::stoi(opt_iter->second);
                    }
                    catch (const std::exception& e) {
                        log::error("{}: Could not convert replica number [{}] into an integer.", __func__, opt_iter->second);
                        return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                    }
                }

                opt_iter = _args.find("leaf-resource");
                if (opt_iter != std::end(_args)) {
                    options["leaf_resource_name"] = opt_iter->second;
                }

                opt_iter = _args.find("seconds-since-epoch");
                if (opt_iter != std::end(_args)) {
                    try {
                        options["seconds_since_epoch"] = std::stoi(opt_iter->second);
                    }
                    catch (const std::exception& e) {
                        log::error("{}: Could not convert seconds-since-epoch [{}] into an integer.", __func__, opt_iter->second);
                        return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                    }
                }

                opt_iter = _args.find("reference");
                if (opt_iter != std::end(_args)) {
                    options["reference"] = opt_iter->second;
                }

                const json input{
                    {"logical_path", lpath_iter->second},
                    {"options", options}
                };

                auto conn = irods::get_connection(client_info->username);
                const auto ec = rc_touch(static_cast<RcComm*>(conn), input.dump().c_str());

                res.body() = json{
                    {"irods_response", {
                        {"error_code", ec}
                    }}
                }.dump();
            }
            catch (const irods::exception& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code()},
                        {"error_message", e.client_display_what()}
                    }}
                }.dump();
            }
            catch (const std::exception& e) {
                res.result(http::status::internal_server_error);
            }

            res.prepare_payload();

            _sess_ptr->send(std::move(res));
        });
    } // handle_touch_op
} // anonymous namespace
