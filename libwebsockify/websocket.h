#ifndef __WEBSOCKET_H
#define __WEBSOCKET_H

#include <openssl/ssl.h>

#ifdef _WIN32
typedef long int ssize_t;
#else
#include <unistd.h>
#endif

typedef unsigned char ws_byte_t;

typedef enum { binary = 1, base64 } ws_protocol_t;

/* The following structure is opaque to library users. It holds the information
   that is internally needed to service an established WebSocket connection. 
 */
typedef struct _ws_context *ws_ctx_t;

struct _ws_listener_struct;

typedef struct _ws_listener_struct ws_listener_t;

/* This is the signature of WebSocket servicing functions. 
 */
typedef void (*ws_handler_t)(ws_ctx_t ctx, ws_listener_t *settings);

/* Configuration of a "listener". A fully initialized struct of this type must
   be passed to ws_run_listener().
 */
struct _ws_listener_struct {
    int verbose;                    
    char listen_host[256];          // IP address/hostname on which to listen
    int listen_port;                // port on which to listen
    ws_handler_t handler;           // handler for established connections
    const char *certfile;
    const char *keyfile;
    int ssl_only;
    void *userdata;
};

/* Error codes
 */
typedef enum {
    WSE_ABANDONED               = -11,  // Closed by client but without orderly closing frame
    WSE_OUT_OF_MEMORY           = -20,
    WSE_UNSUPPORTED_PROTOCOL    = -21,
    WSE_ENCODING_ERROR          = -22,
    WSE_RECEIVING_ERROR         = -23,
    WSE_DECODING_ERROR          = -24,
    WSE_FRAMING_ERROR           = -25,
    WSE_TRANSMITTING_ERROR      = -26
} ws_error_t;

/* Service connections according to the specified settings. 
   This routine does not return until it is terminated by a signal.
 */
void ws_start_server(ws_listener_t *settings);

// int ws_run_listener_detached(listener_t *settings);

/* Allocate a block for sending and/or receiving through a WebSocket.
   You MUST use this function to allocate data blocks because extra space
   may be added before the beginning and/or after the end to optimize
   framing.
 */
ws_byte_t *ws_alloc_block(ws_ctx_t ctx, size_t size);

/* Use this to free data blocks allocated with ws_alloc_block(). DO NOT
   use free() !
 */
void ws_free_block(ws_ctx_t ctx, ws_byte_t *buffer);

/* Call this from within your handler routine to fetch data sent by the 
   client. The specified buffer MUST have been allocated by ws_alloc_block()!
 */
ssize_t ws_recv(ws_ctx_t ctx, ws_byte_t *buf, size_t len);

/* Send a block of data.
   A positive return value indicates that the whole block has already been 
   sent in one go, while zero means that ws_cont() will have to be called 
   until all the data is gone. (A negative return value means that an error 
   occurred.)
   It is illegal to call this function before the previous outgoing data 
   block has either been fully sent or successfully aborted with ws_abort().
 */
int ws_send(ws_ctx_t ctx, ws_byte_t *data, size_t len);

/* Continue sending the data block that was begun, but not completed, by 
   ws_send(). May not be called unless in that situation.
   Return codes are similar to ws_send(): a positive value means that
   we are done sending.
 */
int ws_cont(ws_ctx_t ctx);

/* Abort the transmission of a data block begun with ws_send().
   Returns 1 for success, 0 if not yet done (can happen if the outgoing
   socket is blocked), or -1 if an error occurred.
 */
int ws_abort(ws_ctx_t ctx);

/* Retrieve the socket file descriptor associated with a WebSocket
   context. Do not use for anything else than select().
 */
int ws_getsockfd(ws_ctx_t ctx);

/* This utility function is not specific to WebSockets. It is included
   for convenience.
 */
int ws_resolve_host(struct in_addr *sin_addr, const char *hostname);

#endif // __WEBSOCKET_H
