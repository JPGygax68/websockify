#ifndef __WEBSOCKIFY_H
#define __WEBSOCKIFY_H

#include <websocket.h>

typedef struct wsf_target {
    char host[256];
    int  port;
} wsf_target_t;

/* Set this as the handler in the ws_listener_t structure.
 */
void proxy_handler(ws_ctx_t ctx, ws_listener_t *settings);

#endif // __WEBSOCKIFY_H
