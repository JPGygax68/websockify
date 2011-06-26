#ifndef __WEBSERVER_H
#define __WEBSERVER_H

/* The following structure is opaque to library users. It holds the information
 *   that is internally needed to service an HTTP request.
 */
struct _wsv_context;
typedef struct _wsv_context wsv_ctx_t;

/* Forward declaration...
 */
struct _wsv_settings_struct;
typedef struct _wsv_settings_struct wsv_settings_t;

/* This is the signature of HTTP request servicing functions. 
 */
typedef void (*wsv_handler_t)(wsv_ctx_t *ctx, const char *header, wsv_settings_t *settings);

/* Server settings
 */
struct _wsv_settings_struct {
    //int verbose;                    
    char listen_host[256];          // IP address/hostname on which to listen
    int listen_port;                // port on which to listen
    wsv_handler_t handler;           // handler for established connections
    const char *certfile;
    const char *keyfile;
    int ssl_only;
    void *userdata;
};

int wvs_initialize();

/* Service requests according to the specified settings. 
 * This routine does not return until it is terminated by a signal.
 */
void wsv_start_server(wsv_settings_t *settings);

/*
 * Extract the path from an HTTP request.
 * Does NOT URL-decode!
 */
const char *wsv_extract_url(const char *header, char *buffer);

/* Checks if the specified header field exists in an HTTP request header.
 */
int wsv_exists_header_field(char *header, const char *name);

/* Extracts a header field from an HTTP request header.
 */
const char * wsv_extract_header_field(const char *header, const char *name, char *buffer);

/* Extract the payload that may follow an HTTP request header.
 */
const char * wsv_extract_payload(const char *handshake, char *buffer);

/* URL-decode input buffer into destination buffer.
 * 0-terminate the destination buffer. Return the length of decoded data.
 * form-url-encoded data differs from URI encoding in a way that it
 * uses '+' as character for space, see RFC 1866 section 8.2.1
 * http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
 */
size_t wsv_url_decode(const char *src, size_t slen, char *dst, size_t dlen,
                      int is_form_url_encoded);

/* Convert a standardized path to a native one.
 */
size_t wsv_path_to_native(const char *std, char *native, size_t nlen);

/* Serve the file specified in "path". That parameter must be URL-decoded and
 * must not contain either protocol, host or port, yet must still be in
 * machine-independent format.
 * The parameter "content_type" can be set to zero, in which case "text/html"
 * will be sent.
 * Returns non-zero if an error occurred.
 */
int wsv_serve_file(wsv_ctx_t *ctx, const char *path, const char *content_type);

/* Utility function, not restricted to web server usage.
 * Returns non-zero if an error occurred.
 */
int wsv_resolve_host(struct in_addr *sin_addr, const char *hostname);

#endif // __WEBSERVER_H
