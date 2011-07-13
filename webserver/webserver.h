#ifndef __WEBSERVER_H
#define __WEBSERVER_H

#include <unistd.h>
#ifdef _WIN32
#else
#include <netinet/in.h>
#endif

/* Codes to be returned by protocol upgrade handlers (see wsv_upgrader_t).
 */
#define WSVE_PROTOCOL_UPGRADE_OK            (0)
#define WSVE_PROTOCOL_UPGRADE_FAILED        (-1)

/* URL parsing error codes.
 */
#define WSVE_UPP_NO_MORE_PARAMETERS         (0)
#define WSVE_UPP_OK                         (1)
#define WSVE_UPP_OUT_OF_MEMORY              (-1)
#define WSVE_UPP_SYNTAX_ERROR               (-2)

/* The following structure is opaque to library users. It holds the information
 *   that is internally needed to service an HTTP request.
 */
struct _wsv_context;
typedef struct _wsv_context wsv_ctx_t;

/* Forward declaration...
 */
struct _wsv_settings_struct;
typedef struct _wsv_settings_struct wsv_settings_t;

/* Another opaque structure, for URL parameter parsing.
 */
struct _wsv_url_parsing_struct;
typedef struct _wsv_url_parsing_struct wsv_url_parsing_t;

/* This is the signature of HTTP request servicing functions. 
 * Must return 0 to indicate success.
 * TODO: pass "userdata" instead of the settings ?
 */
typedef int (*wsv_handler_t)(wsv_ctx_t *ctx, const char *header, void *userdata);

/* Internal use only: associates upgradable protocols with their handlers.
 */
struct _wsv_upgrade_entry {
    struct _wsv_upgrade_entry *next;
    const char *protocol;
    wsv_handler_t handler;
    void *userdata;
};

typedef enum { wsv_no_ssl, wsv_allow_ssl, wsv_ssl_only } wsv_ssl_policy_t;

/* Server settings
 */
struct _wsv_settings_struct {
    //int verbose;                    
    char listen_host[256];          // IP address/hostname on which to listen
    int listen_port;                // port on which to listen
    wsv_handler_t handler;          // HTTP handler
    struct _wsv_upgrade_entry *protocols; // linked list of upgraded protocol handlers
    wsv_ssl_policy_t ssl_policy;
    const char *certfile;
    const char *keyfile;
    void *userdata;
};

int
wvs_initialize();

//TODO: function to initialize settings struct ?

//TODO: function to register a custom HTTP handler ?

/* Register a handler for an upgradable protocol (such as "WebSocket").
 * Returns non-zero if unsuccessful.
 */
int 
wsv_register_protocol(wsv_settings_t* settings, const char* name, 
                      wsv_handler_t handler, void *userdata);

/* Service requests according to the specified settings. 
 * This routine does not return until it is terminated by a signal, unless it encounters
 * an error, in which case it will return immediately with a non-zero code.
 */
int 
wsv_start_server(wsv_settings_t *settings);

/* Extract the path from an HTTP request.
 * Does NOT URL-decode!
 */
const char *
wsv_extract_url(const char *header, char *buffer);

/* Checks if the specified header field exists in an HTTP request header.
 */
int 
wsv_exists_header_field(char *header, const char *name);

/* Extracts a header field from an HTTP request header.
 */
const char * 
wsv_extract_header_field(const char *header, const char *name, char *buffer);

/* Extract the payload that may follow an HTTP request header.
 */
const char * 
wsv_extract_payload(const char *handshake, char *buffer);

/* URL-decode input buffer into destination buffer.
 * 0-terminate the destination buffer. Return the length of decoded data.
 * form-url-encoded data differs from URI encoding in a way that it
 * uses '+' as character for space, see RFC 1866 section 8.2.1
 * http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
 */
size_t 
wsv_url_decode(const char *src, size_t slen, char *dst, size_t dlen, int is_form_url_encoded);

/* URL-encode input string into destination buffer.
 */
void
wsv_url_encode(const char *src, char *dst, size_t dst_len);

wsv_url_parsing_t *
wsv_begin_url_param_parsing(const char *start);

int 
wsv_parse_next_url_parameter(wsv_url_parsing_t *par, 
                             const char **nptr, size_t *nlen,
                             const char **vptr, size_t *vlen);

int
wsv_done_url_param_parsing(wsv_url_parsing_t *par);

/* Convert a standardized file path to a native one.
 * The "chroot" parameter indicates whether paths beginning with a slash 
 * should map to the actual root of the filesystem (chroot = 0) or be treated
 * as relative to the web server process' current directory (chroot = 1).
 */
size_t 
wsv_path_to_native(const char *std, char *native, size_t nlen, int chroot);

/* Serve the file specified in "path". That parameter must be URL-decoded and
 * must not contain either protocol, host or port, yet must still be in
 * machine-independent format.
 * The parameter "content_type" can be set to zero, in which case "text/html"
 * will be sent.
 * Returns non-zero if an error occurred.
 */
int 
wsv_serve_file(wsv_ctx_t *ctx, const char *path, const char *content_type);

/* Send data to the client (TCP or SSL depending on the connection).
 * This function will send as much data as can be sent right away, without
 * blocking, and return the number of bytes sent.
 */
ssize_t 
wsv_send(wsv_ctx_t *ctx, const void *pbuf, size_t blen);

/* Based on wsv_send(), wsv_sendall() will send the whole data buffer, taking
 * as long as it will take, sleeping for one ms between each call to 
 * wsv_send().
 */
ssize_t
wsv_sendall(wsv_ctx_t *ctx, const void *pbuf, size_t blen);

/* Receive data from the client, TCP or SSL depending on the connection.
 * (Only really useful if the connection has been upgraded to a bidirectional
 * protocol.)
 */
ssize_t 
wsv_recv(wsv_ctx_t *ctx, void *pbuf, size_t blen);

/* Same as wsv_recv() but does not consume the data, only peeks at the already
 * available bytes.
 */
ssize_t
wsv_peek(wsv_ctx_t *ctx, void *pbuf, size_t blen);

/* Utility function, not restricted to web server usage.
 * Returns non-zero if an error occurred.
 */
int 
wsv_resolve_host(struct in_addr *sin_addr, const char *hostname);

/* Obtain the socket file descriptor of this context.
 * Do not use for anything else than select().
 */
int 
wsv_getsockfd(wsv_ctx_t *ctx);

#endif // __WEBSERVER_H
