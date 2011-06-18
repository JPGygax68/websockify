#ifndef __WSPROXY_H
#define __WSPROXY_H

#include <websocket/websocket.h>

typedef struct wsp_target {
    char host[256];
    int  port;
} wsp_target_t;

/* Set this as the "handler" in the ws_listener_t structure.
 * The "userdata" member of "settings" must point to a properly initialized 
 * wsp_target_t structure.
 */
void wsp_connection_handler(ws_ctx_t *ctx, ws_listener_t *settings);

#endif // __WSPROXY_H
