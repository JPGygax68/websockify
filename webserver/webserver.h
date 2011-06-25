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
typedef void (*wsv_handler_t)(wsv_ctx_t *ctx, wsv_settings_t *settings);

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
void wsv_start_server(wsv_settings_t *settings, wsv_handler_t handler);

#endif // __WEBSERVER_H
