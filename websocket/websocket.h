#ifndef __WEBSOCKET_H
#define __WEBSOCKET_H

#ifndef _WIN32
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <unistd.h>
#endif

#include <webserver/webserver.h>

typedef unsigned char wsk_byte_t;

/* WebSocket subprotocols supported by this library.
 */
typedef enum { 
    WSKSP_UNKNOWN, 
    WSKSP_NONE,
    WSKSP_BINARY,
    WSKSP_BASE64
} wsk_subprotocol_t;

/* The following structure is opaque to library users. It represents an "upgradable"
 * web service. You use that to register your WebSocket subprotocol handlers.
 */
struct _wsk_service;
typedef struct _wsk_service_struct wsk_service_t;

/* The following structure is opaque to library users. It holds the information
 * that is internally needed to service an established WebSocket connection. 
 */
struct _wsk_context;
typedef struct _wsk_context wsk_ctx_t;

/* This is the signature of WebSocket subprotocol handler function. 
 */
typedef int (*wsk_handler_t)(wsk_ctx_t *ctx, const char *location, void *userdata);

/* Error conditions.
 * Note: these values can be inverted if returned by functions that return
 * positive values when successful.
 */
typedef enum {
    WSKE_OK = 0,     // no error
    WSKE_ABANDONED,
    WSKE_OUT_OF_MEMORY,
    WSKE_UNSUPPORTED_PROTOCOL,
    WSKE_ENCODING_ERROR,
    WSKE_RECEIVING_ERROR,
    WSKE_DECODING_ERROR,
    WSKE_FRAMING_ERROR,
    WSKE_TRANSMITTING_ERROR
} wsk_error_t;

/* The following function "extends" a web service, rendering it capable of upgrading
 * connections to the "WebSocket" protocol. 
 * FUTURE EXTENSION: the returned websocket service handle can be used to set options,
 * such as supported subprotocols etc.
 */
wsk_service_t *
wsk_extend_webservice(wsv_settings_t *websvc, wsk_handler_t handler, void *userdata);

/* This function will upgrade an HTTP connection that has requested an upgrade
 * to WebSocket by sending the proper handshake.
 * Call this function from the connection handler you registered using 
 * wsk_register_handler().
 */
wsk_ctx_t *
wsk_handshake(wsv_ctx_t *wsctx, int use_ssl);

/* Access the location parameter specified by the client (URL).
 */
const char *
wsk_get_location(wsk_ctx_t *ctx);

/* Allocate a block for sending and/or receiving through a WebSocket.
   You MUST use this function to allocate data blocks because extra space
   may be added before the beginning and/or after the end to optimize
   framing.
 */
wsk_byte_t *
wsk_alloc_block(wsk_ctx_t *ctx, size_t size);

/* Use this to free data blocks allocated with wsk_alloc_block(). DO NOT use 
 * free() !
 */
void 
wsk_free_block(wsk_ctx_t *ctx, wsk_byte_t *buffer);

/* Call this from within your handler routine to fetch data sent by the 
 * client. The specified buffer MUST have been allocated by wsk_alloc_block()!
 */
ssize_t 
wsk_recv(wsk_ctx_t *ctx, wsk_byte_t *buf, size_t len);

/* Send a block of data.
   A positive return value indicates that the whole block has already been 
   sent in one go, while zero means that ws_cont() will have to be called 
   until all the data is gone. (A negative return value means that an error 
   occurred.)
   It is illegal to call this function before the previous outgoing data 
   block has either been fully sent or successfully aborted with ws_abort().
 */
int 
wsk_send(wsk_ctx_t *ctx, wsk_byte_t *data, size_t len);

/* Continue sending the data block that was begun, but not completed, by 
   ws_send(). May not be called unless in that situation.
   Return codes are similar to ws_send(): a positive value means that
   we are done sending.
 */
int 
wsk_cont(wsk_ctx_t *ctx);

/* Synchronously send a buffer of data. Combines wsk_send() and wsk_cont() 
 * into one call, with a one micro-second sleep between each attempt.
 * Same return values as wsk_send()/wsk_cont().
 */
int
wsk_sendall(wsk_ctx_t *ctx, wsk_byte_t *data, size_t len);

/* Abort the transmission of a data block begun with ws_send().
   Returns 1 for success, 0 if not yet done (can happen if the outgoing
   socket is blocked), or -1 if an error occurred.
 */
int 
wsk_abort(wsk_ctx_t *ctx);

/* Retrieve the socket file descriptor associated with a WebSocket
   context. Do not use for anything else than select()!
 */
int 
wsk_getsockfd(wsk_ctx_t *ctx);

#endif // __WEBSOCKET_H
