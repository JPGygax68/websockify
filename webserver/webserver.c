#ifdef _WIN32
#include <Winsock2.h>
#else
#include <netinet/in.h>
#include <signal.h>
#endif 
#include <openssl/ssl.h>

#include "webserver.h"

/* Struct required to service an HTTP request. 
 */
struct _wsv_context {
    int             sockfd;
    wsv_settings_t  *settings;
    int             id;             // Identifies connections established by a listener
    SSL_CTX         *ssl_ctx;
    SSL             *ssl;
};

//--- GLOBAL VARIABLES --------------------------------------------------------

static int daemonized = 0; // TODO: support daemonizing

//--- LOGGING/TRACING ---------------------------------------------------------

#define __LOG(stream, ...) \
if (! daemonized) { \
    fprintf(stream, "  "); \
    fprintf(stream, __VA_ARGS__); \
    fprintf(stream, "\n" ); \
    }
    
#define LOG_MSG(...) __LOG(stdout, __VA_ARGS__);
#define LOG_ERR(...) __LOG(stderr, __VA_ARGS__);
#define LOG_DBG LOG_MSG

//--- PRIVATE ROUTINES AND FUNCTIONS ------------------------------------------

/* Default request handler.
 */
static void handle_request(int socket, wsv_settings_t *settings)
{
    // TODO
}

#ifdef _WIN32

typedef struct {
    int socket;
    wsv_settings_t *settings;
    int conn_id;
} thread_params_t;

static DWORD WINAPI proxy_thread( LPVOID lpParameter )
{
    thread_params_t *params;
    
    params = lpParameter;
    
    handle_request(params->socket, params->settings);
    
    return 0;
}

#else // !__WIN32

static void signal_handler(int sig)
{
    // TODO
}

#endif

//--- PUBLIC FUNCTIONALITY IMPLEMENTATIONS ------------------------------------

int wsv_initialize()
{
    static int done = 0;
    
    if ( ! done )
    {
        #ifdef _WIN32       
        WORD wVersionRequested;
        WSADATA wsaData;
        int err;
        
        /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
        wVersionRequested = MAKEWORD(2, 2);
        
        err = WSAStartup(wVersionRequested, &wsaData);
        if (err != 0) {
            /* Tell the user that we could not find a usable */
            /* Winsock DLL.                                  */
            fprintf(stderr, "WSAStartup failed with error: %d\n", err);
            return 1;
        }
        #endif // _WIN32
        done = 1;
    }
    
    return 0;
}

void wsv_start_server(wsv_settings_t *settings, wsv_handler_t handler)
{
    int lsock, csock, pid, clilen, sopt = 1;
    struct sockaddr_in serv_addr, cli_addr;
    int conn_id;
    #ifdef _WIN32
    thread_params_t thparams;
    HANDLE hThread;
    #endif
    
    wsv_initialize();
    
    csock = lsock = 0;
    
    conn_id = 1;
    
    lsock = socket(AF_INET, SOCK_STREAM, 0);
    if (lsock < 0) { LOG_ERR("ERROR creating listener socket"); return; }
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(settings->listen_port);
    
    /* Resolve listen address */
    if (settings->listen_host && (settings->listen_host[0] != '\0')) {
        if (ws_resolve_host(&serv_addr.sin_addr, settings->listen_host) < -1) {
            LOG_ERR("Could not resolve listen address");
            close(lsock);
            return;
        }
    } else {
        serv_addr.sin_addr.s_addr = INADDR_ANY;
    }
    
    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (char *)&sopt, sizeof(sopt));
    if (bind(lsock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        //int err = WSAGetLastError();
        LOG_ERR("ERROR on binding listener socket");
        close(lsock);
        return;
    }
    listen(lsock, 100);
    
    #ifndef _WIN32
    signal(SIGPIPE, signal_handler);  // catch pipe
    #endif
    
    #ifndef _WIN32
    // Reep zombies
    signal(SIGCHLD, SIG_IGN);
    #endif
    
    printf("Waiting for connections on %s:%d\n",
           settings->listen_host, settings->listen_port);
    
    while (1) {
        clilen = sizeof(cli_addr);
        pid = 0;
        csock = accept(lsock, 
                       (struct sockaddr *) &cli_addr, 
                       &clilen);
        if (csock < 0) {
            LOG_ERR("ERROR on accept");
            continue;
        }
        LOG_MSG("got client connection from %s", inet_ntoa(cli_addr.sin_addr));
        
        #ifdef _WIN32
        thparams.settings = settings;
        thparams.socket = csock;
        thparams.conn_id = conn_id;
        hThread = CreateThread(NULL, 0, proxy_thread, (LPVOID) &thparams, 0, NULL );
        if (hThread == NULL) {
            LOG_ERR("failed to create proxy thread");
            break;
        }
        conn_id += 1;
        #else
        LOG_MSG("forking handler process");
        pid = fork();
        
        if (pid == 0) {  // handler process
            handle_request(csock, settings);
            break;   // Child process exits
        } else {         // parent process
            conn_id += 1;
        }
        #endif
    }
    #ifndef _WIN32
    if (pid == 0) {
        shutdown(csock, SHUT_RDWR);
        close(csock);
        LOG_MSG("handler exit");
    } else {
        // TODO: can this ever be reached ?
        LOG_MSG("webserver listener exit");
    }
    #endif
}
