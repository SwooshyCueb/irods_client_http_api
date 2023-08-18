# iRODS HTTP API

A project that presents an iRODS 4.3.1+ server as HTTP v1.1.

## Build Dependencies

- iRODS development package
- iRODS externals package for boost
- iRODS externals package for nlohmann-json
- iRODS externals package for spdlog 
- Curl development package
- OpenSSL development package
- GenQuery2 package (optional)

## Build

This project can be built with or without support for [GenQuery2](https://github.com/irods/irods_api_plugin_genquery2).

GenQuery2 is disabled by default.

### Building without GenQuery2

If you don't need support for GenQuery2, follow the normal CMake steps.

```bash
mkdir build # Preferably outside of the repository
cd build
cmake /path/to/repository
make package # Use -j to use more parallelism.
```

Upon success, you should have an installable package.

### Building with GenQuery2

To build with GenQuery2 enabled, the HTTP API needs access to files only provided by the GenQuery2 package.

If you haven't already done so, install the GenQuery2 package. See the [GenQuery2](https://github.com/irods/irods_api_plugin_genquery2) repository for details on how to do that.

Now, run the following steps to produce an installable package.

```bash
mkdir build # Preferably outside of the repository
cd build
cmake -DIRODS_ENABLE_GENQUERY2=YES /path/to/repository
make package # Use -j to use more parallelism.
```

Keep in mind that even though you've compiled the HTTP API with support for GenQuery2, that is half the story. You must also install the GenQuery2 package on the iRODS server which the HTTP API will connect to and the iRODS Catalog Service Provider.

## Configuration

Before you can run the server, you'll need to create a configuration file.

You can generate a configuration file by running the following:
```bash
irods_http_api --dump-config-template > config.json
```

**IMPORTANT: `--dump-config-template` does not produce a fully working configuration. It must be updated before it can be used.**

### Configuration File Structure

The JSON structure below represents the default configuration.

Notice how some of the configuration values are wrapped in angle brackets (e.g. `"<string>"`). These are placeholder values that must be updated before launch.

**IMPORTANT: The comments in the JSON structure are there for explanatory purposes and must not be included in your configuration. Failing to follow this requirement will result in the server failing to start up.**

```js
{
    // Defines HTTP options that affect how the client-facing component of the
    // server behaves.
    "http_server": {
        // The hostname or IP address to bind.
        // "0.0.0.0" instructs the server to listen on all network interfaces.
        "host": "0.0.0.0",

        // The port used to accept incoming client requests.
        "port": 9000,

        // The minimum log level needed before logging activity.
        "log_level": "warn",

        // Defines options that affect various authentication schemes.
        "authentication": {
            // The amount of time that must pass before checking for expired
            // bearer tokens.
            "eviction_check_interval_in_seconds": 60,

            // Defines options for the "Basic" authentication scheme.
            "basic": {
                // The amount of time before a user's "Basic" authentication
                // token expires.
                "timeout_in_seconds": 3600
            },

            // Defines required OIDC related configuration.
            "oidc": {
                // The hostname or ip address of the OIDC provider.
                "config_host": "oidc.example.com",

                // The port the OIDC provider is listening on.
                "port": "8080",

                // The path to the OIDC well-known endpoint.
                "uri": "/realms/example/.well-known/openid-configuration",

                // The client id associated with the application given by the OIDC provider.
                "client_id": "irods_http",

                // URI pointing to the irods HTTP API auth endpoint.
                "redirect_uri": "https://rods.example.com/irods-http/0.9.5/authenticate"
            }
        },

        // Defines options that affect how client requests are handled.
        "requests": {
            // The number of threads dedicated to servicing client requests.
            // When adjusting this value, consider adjusting "background_io/threads"
            // and "irods_client/connection_pool/size" as well.
            "threads": 3,

            // The maximum size allowed for the body of a request.
            "max_rbuffer_size_in_bytes": 8388608,

            // The amount of time allowed to service a request. If the timeout
            // is exceeded, the client's connection is terminated immediately.
            "timeout_in_seconds": 30
        },

        // Defines options that affect tasks running in the background.
        // These options are primarily related to long-running tasks.
        "background_io": {
            // The number of threads dedicated to background I/O.
            "threads": 3
        }
    },

    // Defines iRODS connection information.
    "irods_client": {
        // The hostname or IP of the target iRODS server.
        "host": "<string>",

        // The port of the target iRODS server.
        "port": 1247,

        // The zone of the target iRODS server.
        "zone": "<string>",

        // Defines options for secure communication with the target iRODS server.
        "tls": {
            // Controls whether the client and server communicate using TLS.
            //
            // The following values are supported:
            // - CS_NEG_REFUSE:    Do not use secure communication.
            // - CS_NEG_REQUIRE:   Demand secure communication.
            // - CS_NEG_DONT_CARE: Let the server decide.
            "client_server_policy": "CS_NEG_REFUSE",

            // The file containing trusted CA certificates in PEM format.
            //
            // Note that the certificates in this file are used in conjunction
            // with the system default trusted certificates.
            "ca_certificate_file": "<string>",

            // The file containing the server's certificate chain.
            //
            // The certificates must be in PEM format and must be sorted
            // starting with the subject's certificate (actual client or server
            // certificate), followed by intermediate CA certificates if
            // applicable, and ending at the highest level (root) CA.
            "certificate_chain_file": "<string>",

            // The file containing Diffie-Hellman parameters.
            "dh_params_file": "<string>",

            // Defines the level of server certificate authentication to
            // perform.
            //
            // The following values are supported:
            // - none:     Authentication is skipped.
            // - cert:     The server verifies the certificate is signed by
            //             a trusted CA.
            // - hostname: Equivalent to "cert", but also verifies the FQDN
            //             of the iRODS server matches either the common
            //             name or one of the subjectAltNames.
            "verify_server": "cert"
        },

        // The credentials for the rodsadmin user that will act as a proxy
        // for all authenticated users.
        "proxy_rodsadmin": {
            "username": "<string>",
            "password": "<string>"
        },

        // Defines options for the connection pool.
        "connection_pool": {
            // The number of connections in the pool.
            "size": 6,

            // The amount of time that must pass before a connection is
            // renewed (i.e. replaced).
            "refresh_timeout_in_seconds": 600
        },

        // The buffer size used for read operations.
        // Clients are not allowed to read more bytes than this value in
        // one API call.
        "max_rbuffer_size_in_bytes": 8192,

        // The buffer size used for write operations.
        // Clients are not allowed to write more bytes than this value in
        // one API call.
        "max_wbuffer_size_in_bytes": 8192,

        // The number of rows that can be returned by a General or Specific
        // query. If the client specifies a number greater than the value
        // defined here, it will be clamped to this value. If the client does
        // not specify a value, it will be defaulted to this value.
        "max_number_of_rows_per_catalog_query": 15
    }
}
```

## Run

To run the server, do the following:
```bash
irods_http_api /path/to/config.json
```

To stop the server, you can use **CTRL-C** or send **SIGINT** or **SIGTERM** to the process.

## Documentation

API documentation can be found in [API.md](./API.md).
