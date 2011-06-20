#ifndef __WSPROXY_H
#define __WSPROXY_H

#include <websocket/websocket.h>

/* Use this with wsp_default_connection_handler().
 */
typedef struct wsp_target {
    char host[256];
    int  port;
} wsp_target_t;

/* This is the main routine. It receives and forwards data blocks both ways 
 * between the websocket client and the TCP/SSL target.
 */
void wsp_do_proxy(ws_ctx_t *ctx, int target);

/* This is a default connection handler that you can pass to ws_start_server().
 * It expects a pointer to a properly initialized wsp_target_t structure
 * in the "userdata" member of "settings".
 * If you do not know the target host and port in advance, write your own
 * handler and call wsp_do_proxy() from that.
 */
void wsp_connection_handler(ws_ctx_t *ctx, ws_listener_t *settings);

#endif // __WSPROXY_H
