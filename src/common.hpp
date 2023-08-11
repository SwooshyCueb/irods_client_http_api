#ifndef IRODS_HTTP_API_ENDPOINT_COMMON_HPP
#define IRODS_HTTP_API_ENDPOINT_COMMON_HPP

#include <irods/connection_pool.hpp>
#include <irods/filesystem/object_status.hpp>
#include <irods/filesystem/permissions.hpp>
#include <irods/irods_exception.hpp>

#include <boost/beast/http/status.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace irods::http
{
    class session;

    // clang-format off
    using field_type    = boost::beast::http::field;
    using request_type  = boost::beast::http::request<boost::beast::http::string_body>;
    using response_type = boost::beast::http::response<boost::beast::http::string_body>;
    using status_type   = boost::beast::http::status;
    using verb_type     = boost::beast::http::verb;

    using session_pointer_type = std::shared_ptr<irods::http::session>;
    using request_handler_type = void(*)(session_pointer_type, request_type&);

    using request_handler_map_type = std::unordered_map<std::string_view, request_handler_type>;

    using query_arguments_type = std::unordered_map<std::string, std::string>;
    // clang-format on

    enum class authorization_scheme
    {
        basic = 0,
        openid_connect
    }; // enum class authorization_scheme

    struct authenticated_client_info
    {
        authorization_scheme auth_scheme;
        std::string username;
        std::string password; // TODO Probably not needed.
        std::chrono::steady_clock::time_point expires_at; // TODO This may be controlled by OIDC. Think about how to handle that.
        // TODO Store an expiration timestamp here. Post discush: let it expire and send reauth code to client.
        // Perhaps a purge timestamp as well. This is an optimization situation.
    }; // struct authenticated_client_info

    struct url
    {
        std::string path;
        query_arguments_type query;
    }; // struct url

    struct client_identity_resolution_result
    {
        std::optional<response_type> response;
        const authenticated_client_info* client_info{};
    }; // struct client_identity_resolution_result

    auto fail(response_type& _response, status_type _status, const std::string_view _error_msg) -> response_type;

    auto fail(response_type& _response, status_type _status) -> response_type;

    auto fail(status_type _status, const std::string_view _error_msg) -> response_type;

    auto fail(status_type _status) -> response_type;

    auto decode(const std::string_view _v) -> std::string;

	auto encode(std::string_view to_encode) -> std::string;

    // TODO Create a better name.
    auto to_argument_list(const std::string_view _urlencoded_string) -> std::unordered_map<std::string, std::string>;

    auto get_url_path(const std::string& _url) -> std::optional<std::string>;

    auto parse_url(const std::string& _url) -> url;

    auto parse_url(const request_type& _req) -> url;

    auto resolve_client_identity(const request_type& _req) -> client_identity_resolution_result;
} // namespace irods::http

namespace irods
{
    template <typename Map>
    auto generate_uuid(const Map& _map) -> std::string
    {
        std::string uuid;
        uuid.reserve(36); // NOLINT(cppcoreguidelines-avoid-magic-numbers, readability-magic-numbers)
        uuid = to_string(boost::uuids::random_generator{}());

        while (_map.find(uuid) != std::end(_map)) {
            uuid = to_string(boost::uuids::random_generator{}());
        }

        return uuid;
    } // generate_uuid

    auto to_permission_string(const irods::experimental::filesystem::perms _p) -> const char*;

    auto to_permission_enum(const std::string_view _s) -> std::optional<irods::experimental::filesystem::perms>;

    auto to_object_type_string(const irods::experimental::filesystem::object_type _t) -> const char*;

    auto to_object_type_enum(const std::string_view _s) -> std::optional<irods::experimental::filesystem::object_type>;

    // TODO May require the zone name be passed as well for federation?
    auto get_connection(const std::string& _username) -> irods::connection_pool::connection_proxy;

    auto fail(boost::beast::error_code ec, char const* what) -> void;
} // namespace irods

#endif // IRODS_HTTP_API_ENDPOINT_COMMON_HPP
