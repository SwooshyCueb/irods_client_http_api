#include "handlers.hpp"

#include "common.hpp"
#include "globals.hpp"
#include "log.hpp"
#include "session.hpp"
#include "version.hpp"

#include <curl/urlapi.h>
#include <irods/base64.hpp>
#include <irods/check_auth_credentials.h>
#include <irods/irods_exception.hpp>
#include <irods/process_stash.hpp>
#include <irods/rcConnect.h>
#include <irods/user_administration.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>

#include <nlohmann/json.hpp>

#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>

#include <curl/curl.h>

#include <array>
#include <chrono>
#include <string>
#include <string_view>
#include <vector>

#include <unordered_map>
#include <algorithm>

// clang-format off
namespace beast = boost::beast; // from <boost/beast.hpp>
namespace net   = boost::asio;  // from <boost/asio.hpp>
// clang-format on

using BodyArguments = std::unordered_map<std::string, std::string>;

namespace irods::http::handler
{
	auto hit_token_endpoint(std::string encoded_body) -> nlohmann::json
	{
		const auto token_endpoint{irods::http::globals::oidc_endpoint_configuration()->at("token_endpoint").get<const std::string>()};

		// Setup net
		net::io_context io_ctx;
		net::ip::tcp::resolver tcp_res{io_ctx};
		beast::tcp_stream tcp_stream{io_ctx};

		// Setup curl
		CURLU* endpoint{curl_url()};

		// Parse url
		CURLUcode rc{curl_url_set(endpoint, CURLUPART_URL, token_endpoint.data(), 0)};
		if (rc != 0) {
			log::debug("Something happend....");
		}

		// Get host
		char* host{};
		rc = curl_url_get(endpoint, CURLUPART_HOST, &host, 0);
		if (rc != 0) {
			log::debug("Something happend....");
		}

		// Get service/port
		//char *port{};
		//rc = curl_url_get(endpoint, CURLUPART_PORT, &port, 0);
		//if (rc != 0) {
		//    log::debug("Something happend....");
		//}
		// KEYCLOAK does not return the port?
		const auto port{irods::http::globals::oidc_configuration()->at("port").get<const std::string>()};

		// Get path
		char* path{};
		rc = curl_url_get(endpoint, CURLUPART_PATH, &path, 0);
		if (rc != 0) {
			log::debug("Something happend....");
		}

		// Addr
		const auto resolve{tcp_res.resolve(host, port)};

		// TCP thing
		tcp_stream.connect(resolve);

		// Build Request
		constexpr auto version_number{11};
		beast::http::request<beast::http::string_body> req{beast::http::verb::post, path, version_number};
		req.set(beast::http::field::host, host);
		req.set(beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);
		req.set(beast::http::field::content_type,
		        "application/x-www-form-urlencoded"); // Possibly set a diff way?

		// Send
		req.body() = encoded_body;
		req.prepare_payload();

		// Send request
		beast::http::write(tcp_stream, req);

		// Read back req
		beast::flat_buffer buffer;
		beast::http::response<beast::http::string_body> res;
		beast::http::read(tcp_stream, buffer, res);

		log::debug("Got the following resp back: {}", res.body());

		// Close socket
		beast::error_code ec;
		tcp_stream.socket().shutdown(net::ip::tcp::socket::shutdown_both, ec);

		// Free up all items created, reverse n all
		curl_free(path);
		//curl_free(port);
		curl_free(host);

		// Done
		curl_url_cleanup(endpoint);

		// JSONize response
		return nlohmann::json::parse(res.body());
	}

	auto encode_string(std::string_view to_encode) -> std::string
	{
		// Init CURL
		CURL* curl{curl_easy_init()};

		// Ensure that CURL was successfully enabled
		if (curl != nullptr)
		{
			// Encode the data & ensure success
			char* tmp_encoded_data{curl_easy_escape(curl, to_encode.data(), to_encode.size())};
			if (tmp_encoded_data == nullptr) {
				log::debug("{}: Error encoding the redirect uri!!!", __func__);
			}

			// Save the data
			std::string encoded_data{tmp_encoded_data};

			// Clean up CURL
			curl_free(tmp_encoded_data);
			curl_easy_cleanup(curl);
			return encoded_data;
		}

		// Return Result
		return "";
	}

	auto encode_body(BodyArguments args) -> std::string
	{
		auto encode_pair{
			[](const BodyArguments::value_type& i) { return encode_string(i.first) + "=" + encode_string(i.second); }};

		return std::transform_reduce(
			std::next(std::begin(args)),
			std::end(args),
			encode_pair(*std::begin(args)),
			[](auto a, auto b) { return a + "?" + b; },
			encode_pair);
	}

	auto get_encoded_redirect_uri() -> std::string
	{
		return encode_string(irods::http::globals::oidc_configuration()->at("redirect_uri").get_ref<const std::string&>());
	}

	auto decode_username_and_password()
	{
		constexpr auto basic_auth_scheme_prefix_size{6};
		std::string authorization{iter->value().substr(pos + basic_auth_scheme_prefix_size)};
		boost::trim(authorization);
		log::debug("{}: Authorization value (trimmed): [{}]", fn, authorization);

		constexpr auto max_creds_size{128};
		unsigned long size = max_creds_size;
		//std::vector<std::uint8_t> creds(size);
		std::array<std::uint8_t, max_creds_size> creds{};
		// NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
		const auto ec{irods::base64_decode(
				reinterpret_cast<unsigned char*>(authorization.data()), authorization.size(), creds.data(), &size)};
		log::debug("{}: base64 - error code=[{}], decoded size=[{}]", fn, ec, size);

		// NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
		std::string_view sv{reinterpret_cast<char*>(creds.data()), size};
		log::debug("{}: base64 decode credentials = [{}]", fn, sv); // TODO Don't print the password

		const auto colon{sv.find(':')};
		if (colon == std::string_view::npos) {
			return _sess_ptr->send(fail(status_type::unauthorized));
		}

		std::string username{sv.substr(0, colon)};
		std::string password{sv.substr(colon + 1)};
	}

	auto authentication(session_pointer_type _sess_ptr, request_type& _req) -> void
	{
		if (_req.method() == boost::beast::http::verb::get) {
			url url;
			bool did_except{false};
			try {
				url = irods::http::parse_url(_req);
			}
			catch (irods::exception& e) {
				did_except = true;
			}

			if (did_except) {
				irods::http::globals::background_task([fn = __func__, _sess_ptr, _req = std::move(_req)] {
					BodyArguments args{
						{"client_id", irods::http::globals::oidc_configuration()->at("client_id").get_ref<const std::string&>()},
						{"response_type", "code"},
						{"scope", "openid"},
						{"redirect_uri",
					     irods::http::globals::oidc_configuration()->at("redirect_uri").get_ref<const std::string&>()},
						{"state", "placeholder"}};

					const auto auth_endpoint{irods::http::globals::oidc_endpoint_configuration()->at("authorization_endpoint")
					                             .get_ref<const std::string&>()};
					const auto yep{fmt::format("{}?{}", auth_endpoint, encode_body(args))};

					log::debug("{}: Proper redirect to [{}]", fn, yep);

					response_type res{status_type::found, _req.version()};
					res.set(field_type::server, BOOST_BEAST_VERSION_STRING);
					res.set(field_type::location, yep);
					res.keep_alive(_req.keep_alive());
					res.prepare_payload();

					return _sess_ptr->send(std::move(res));
				});
			}
			else {
				irods::http::globals::background_task(
					[fn = __func__, _sess_ptr, _req = std::move(_req), url = std::move(url)] {
						// Two query params requiured by OAuth 2.0
					    // TODO: Double check with OIDC for bonus params
						const auto code_iter{url.query.find("code")};
						const auto state_iter{url.query.find("state")};

						// Check to see if querys are valid
						if (state_iter == std::end(url.query) || code_iter == std::end(url.query)) {
							return _sess_ptr->send(fail(status_type::bad_request));
						}

						// Code here...
					    // Verify the state here!!!
						log::debug("{}: Code is [{}]", fn, code_iter->second);
						log::debug("{}: State is [{}]", fn, state_iter->second);

						// Populate arguments
						BodyArguments args{
							{"grant_type", "authorization_code"},
							{"client_id",
					         irods::http::globals::oidc_configuration()->at("client_id").get_ref<const std::string&>()},
							{"code", code_iter->second},
							{"redirect_uri",
					         irods::http::globals::oidc_configuration()->at("redirect_uri").get_ref<const std::string&>()}};

						// Encode the string, hit endpoint, get res
						nlohmann::json res_item{hit_token_endpoint(encode_body(args))};

						// Assume passed, get oidc token
						const std::string jwt_token{res_item.at("id_token").get_ref<const std::string&>()};

						// Get OIDC token && feed to JWT parser
					    // TODO: Handle case where we throw!!!
						auto decoded_token{jwt::decode<jwt::traits::nlohmann_json>(
							res_item.at("id_token").get_ref<const std::string&>())};

						// Get irods username
						const std::string irods_name{
							decoded_token.get_payload_json().at("irods_username").get<const std::string>()};

						// Issue token?
						static const auto seconds = irods::http::globals::config
					                                    ->at(nlohmann::json::json_pointer{
															"/http_server/authentication/basic/timeout_in_seconds"})
					                                    .get<int>();

						auto bearer_token = irods::process_stash::insert(authenticated_client_info{
							.auth_scheme = authorization_scheme::basic,
							.username = std::move(irods_name),
							.expires_at = std::chrono::steady_clock::now() + std::chrono::seconds{seconds}});

						response_type res_rep{status_type::ok, _req.version()};
						res_rep.set(field_type::server, BOOST_BEAST_VERSION_STRING);
						res_rep.set(field_type::content_type, "text/plain");
						res_rep.keep_alive(_req.keep_alive());
						res_rep.body() = std::move(bearer_token);
						res_rep.prepare_payload();

						return _sess_ptr->send(std::move(res_rep));
					});
			}
		}
		// Handle posts
		else if (_req.method() == boost::beast::http::verb::post) {
			irods::http::globals::background_task([fn = __func__, _sess_ptr, _req = std::move(_req)] {
				// Right, we're kinda being a proxy, so how about proxy-authorization?
				const auto& hdrs{_req.base()};
				const auto iter{hdrs.find("authorization")};

				// Failed to find auth header, use OIDC auth_code flow instead
				if (iter == std::end(hdrs)) {
					return _sess_ptr->send(fail(status_type::bad_request));
				}

				log::debug("{}: Authorization value: [{}]", fn, iter->value());

				//
				// TODO Here is where we determine what form of authentication to perform (e.g. Basic or OIDC).

				//
				// BLAH BLAH BLAH, assume we have the user & pass...
				// Prob via Proxy-Authorization????
				//

				const auto pos = iter->value().find("Basic ");
				if (std::string_view::npos == pos) {
					// TEMPORARY PLS MAKE BETTER LATER :)

					const auto alt_method{iter->value().find("iRODS ")};
					if (std::string_view::npos == alt_method) {
						return _sess_ptr->send(fail(status_type::bad_request));
					}

					// BEGIN BASE64 HEADER DECODE

					constexpr auto basic_auth_scheme_prefix_size = 6;
					std::string authorization{iter->value().substr(alt_method + basic_auth_scheme_prefix_size)};
					boost::trim(authorization);
					log::debug("{}: Authorization value (trimmed): [{}]", fn, authorization);

					constexpr auto max_creds_size = 128;
					unsigned long size = max_creds_size;
					//std::vector<std::uint8_t> creds(size);
					std::array<std::uint8_t, max_creds_size> creds{};
					// NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
					const auto ec = irods::base64_decode(
						reinterpret_cast<unsigned char*>(authorization.data()),
						authorization.size(),
						creds.data(),
						&size);
					log::debug("{}: base64 - error code=[{}], decoded size=[{}]", fn, ec, size);

					// NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
					std::string_view sv{reinterpret_cast<char*>(creds.data()), size};
					log::debug("{}: base64 decode credentials = [{}]", fn, sv); // TODO Don't print the password

					const auto colon = sv.find(':');
					if (colon == std::string_view::npos) {
						return _sess_ptr->send(fail(status_type::unauthorized));
					}

					std::string username{sv.substr(0, colon)};
					std::string password{sv.substr(colon + 1)};
					log::debug(
						"{}: username=[{}], password=[{}]", fn, username, password); // TODO Don't print the password

					// BEGIN OG OAUTH THING
					BodyArguments args{
						{"client_id", irods::http::globals::oidc_configuration()->at("client_id").get_ref<const std::string&>()},
						{"grant_type", "password"},
						{"scope", "openid"},
						{"username", username},
						{"password", password}};

					// Query endpoint
					nlohmann::json res_item{hit_token_endpoint(encode_body(args))};

					// Assume passed, get oidc token
					const std::string jwt_token{res_item.at("id_token").get<const std::string>()};

					// Feed to JWT parser
					auto decoded_token{jwt::decode<jwt::traits::nlohmann_json>(jwt_token)};

					// Get irods username
					// Zones?
					// uname#zname
					const std::string irods_name{
						decoded_token.get_payload_json().at("irods_username").get<const std::string>()};

					// Issue token?
					static const auto seconds =
						irods::http::globals::config
							->at(nlohmann::json::json_pointer{"/http_server/authentication/basic/timeout_in_seconds"})
							.get<int>();
					auto bearer_token = irods::process_stash::insert(authenticated_client_info{
						.auth_scheme = authorization_scheme::basic,
						.username = std::move(irods_name),
						.expires_at = std::chrono::steady_clock::now() + std::chrono::seconds{seconds}});

					response_type res_rep{status_type::ok, _req.version()};
					res_rep.set(field_type::server, BOOST_BEAST_VERSION_STRING);
					res_rep.set(field_type::content_type, "text/plain");
					res_rep.keep_alive(_req.keep_alive());
					res_rep.body() = std::move(bearer_token);
					res_rep.prepare_payload();

					return _sess_ptr->send(std::move(res_rep));
				}

				constexpr auto basic_auth_scheme_prefix_size = 6;
				std::string authorization{iter->value().substr(pos + basic_auth_scheme_prefix_size)};
				boost::trim(authorization);
				log::debug("{}: Authorization value (trimmed): [{}]", fn, authorization);

				constexpr auto max_creds_size = 128;
				unsigned long size = max_creds_size;
				//std::vector<std::uint8_t> creds(size);
				std::array<std::uint8_t, max_creds_size> creds{};
				// NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
				const auto ec = irods::base64_decode(
					reinterpret_cast<unsigned char*>(authorization.data()), authorization.size(), creds.data(), &size);
				log::debug("{}: base64 - error code=[{}], decoded size=[{}]", fn, ec, size);

				// NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
				std::string_view sv{reinterpret_cast<char*>(creds.data()), size};
				log::debug("{}: base64 decode credentials = [{}]", fn, sv); // TODO Don't print the password

				const auto colon = sv.find(':');
				if (colon == std::string_view::npos) {
					return _sess_ptr->send(fail(status_type::unauthorized));
				}

				std::string username{sv.substr(0, colon)};
				std::string password{sv.substr(colon + 1)};
				log::debug("{}: username=[{}], password=[{}]", fn, username, password); // TODO Don't print the password

				bool login_successful = false;

				try {
					const auto& svr = irods::http::globals::config->at("irods_client");
					const auto& host = svr.at("host").get_ref<const std::string&>();
					const auto port = svr.at("port").get<std::uint16_t>();
					const auto& zone = svr.at("zone").get_ref<const std::string&>();

					irods::experimental::client_connection conn{
						irods::experimental::defer_authentication, host, port, {username, zone}};

					login_successful = (clientLoginWithPassword(static_cast<RcComm*>(conn), password.data()) == 0);
				}
				catch (const irods::exception& e) {
					log::error(e.client_display_what());
				}

				if (!login_successful) {
					return _sess_ptr->send(fail(status_type::unauthorized));
				}

				static const auto seconds =
					irods::http::globals::config
						->at(nlohmann::json::json_pointer{"/http_server/authentication/basic/timeout_in_seconds"})
						.get<int>();
				auto bearer_token = irods::process_stash::insert(authenticated_client_info{
					.auth_scheme = authorization_scheme::basic,
					.username = std::move(username),
					.password = std::move(password),
					.expires_at = std::chrono::steady_clock::now() + std::chrono::seconds{seconds}});

				response_type res{status_type::ok, _req.version()};
				res.set(field_type::server, BOOST_BEAST_VERSION_STRING);
				res.set(field_type::content_type, "text/plain");
				res.keep_alive(_req.keep_alive());
				res.body() = std::move(bearer_token);
				res.prepare_payload();

				return _sess_ptr->send(std::move(res));
			});
		}
		else {
			// Nothing recognized
			return _sess_ptr->send(fail(status_type::method_not_allowed));
		}
	} // authentication
} //namespace irods::http::handler
