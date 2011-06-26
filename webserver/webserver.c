#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <netdb.h>
#ifdef _WIN32
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#include <signal.h>
#include <fcntl.h>
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
    fprintf(stream, __VA_ARGS__); \
    fprintf(stream, "\n" ); \
    }
    
#define LOG_MSG(...) __LOG(stdout, __VA_ARGS__);
#define LOG_ERR(...) __LOG(stderr, __VA_ARGS__);
#define LOG_DBG LOG_MSG

//--- PRIVATE ROUTINES AND FUNCTIONS ------------------------------------------

// TODO: make public ?

static ssize_t do_send(wsv_ctx_t *ctx, const void *pbuf, size_t blen)
{
    if (ctx->ssl) {
        LOG_DBG("SSL send");
        return SSL_write(ctx->ssl, pbuf, blen);
    } else {
        return send(ctx->sockfd, (char*) pbuf, blen, 0);
    }
}

// TODO: make public ?

static ssize_t do_recv(wsv_ctx_t *ctx, void *pbuf, size_t blen)
{
    if (ctx->ssl) {
        LOG_DBG("SSL recv");
        return SSL_read(ctx->ssl, pbuf, blen);
    } else {
        return recv(ctx->sockfd, (char*) pbuf, blen, 0);
    }
}

/* Default request handler.
 */
static void dflt_request_handler(wsv_ctx_t *ctx, const char *header, wsv_settings_t *settings)
{
    char url[1024], dec[1024], path[1024];
    
    LOG_DBG("%s %s", __FILE__, __FUNCTION__);
    
    // Extract the URL and decode it
    if (!wsv_extract_url(header, url)) {
        LOG_ERR("Request does not contain a URL");
        return;
    }
    wsv_url_decode(url, sizeof(url), dec, sizeof(dec), 0);
    LOG_DBG("%s %s: request URL (decoded) = \"%s\"", __FILE__, __FUNCTION__, dec);
    
    // Serve the requested file
    if (strlen(dec) > 0) {
        // TODO: remove the parameters
        if (wsv_path_to_native(dec, path, 1024) == 0) {
            LOG_ERR("Failed to convert standardized path \"%s\" to native", dec);
            // TODO: send error message
            return;
        }
        wsv_serve_file(ctx, path, "text/html");
    }
}

/* Find a handler for an upgrade protocol.
 */
static wsv_handler_t get_protocol_handler(const char *protocol, wsv_settings_t *settings)
{
    struct _wsv_upgrade_entry *pr;
    
    for (pr = settings->protocols; pr; pr = pr->next) {
        if (strcmp(protocol, pr->protocol) == 0) {
            LOG_DBG("Found handler for upgrade protocol \"%s\"", protocol);
            return pr->handler;
        }
    }

    return NULL;
}

static void handle_request(int conn_id, int sockfd, wsv_settings_t *settings)
{
    char header[2048];
    wsv_ctx_t ctx;
    ssize_t len;
    char protocol[256];
    const char *p;
    char *q;
    wsv_handler_t handler;
    
    // Create a context
    ctx.id = conn_id;
    ctx.sockfd = sockfd;
    ctx.settings = settings;
    ctx.ssl = 0; // TODO
    ctx.ssl_ctx = 0; // TODO
    
    // Get the header (peek, but don't actually consume the data yet)
    // TODO: support SSL
    len = recv(sockfd, header, sizeof(header)-1, MSG_PEEK);
    header[len] = 0;
    LOG_DBG("%s %s: peeked %d bytes HTTP request", __FILE__, __FUNCTION__, len);
    
    // Do we have an "Upgrade" header field ?
    if (wsv_extract_header_field(header, "Upgrade", protocol)) {
        LOG_DBG("Client asks to upgrade the protocol to any of: %s", protocol);
        p = protocol;
        while (p && *p) {
            q = strchr(p, ',');
            if (q) *q = '\0';
            LOG_DBG("Looking for handler for upgrade protocol \"%s\"", p);
            handler = get_protocol_handler(p, settings);
            if (handler) {
                LOG_DBG("Handler found for upgrade protocol \"%s\", calling it", p);
                handler(&ctx, header, settings);
                return; // TODO: return value ?
            }
            if (q) while (*q && isspace(*q)) q++;
            p = q;
        }
        LOG_ERR("No handler found for upgrade protocol \"%s\"", protocol);
    }
    else { // no protocol upgrade request, use standard handler
        settings->handler(&ctx, header, settings);
    }

    // Look at each protocol the client will accept
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

// TODO: check if protocol already registered ?

int wsv_register_protocol(wsv_settings_t *settings, const char *name, wsv_handler_t handler)
{
    struct _wsv_upgrade_entry *pred, *node;
    
    for (pred = (struct _wsv_upgrade_entry*) &settings->protocols; pred->next == NULL; pred = pred->next);
    
    node = pred->next = malloc(sizeof(struct _wsv_upgrade_entry));
    
    node->next = NULL;
    node->protocol = strdup(name);
    node->handler = handler;
    
    return 0;
}

size_t wsv_path_to_native(const char *std, char *native, size_t nlen)
{
#ifndef _WIN32
    if (!getcwd(native, nlen)) return 0;
    LOG_DBG("getcwd() -> %s", native);
    if (!strncat(native, std, nlen)) return 0;
    LOG_DBG("native path = \"%s\"", native);
    return strnlen(native, nlen);   
#else
#endif
}

int wsv_serve_file(wsv_ctx_t *ctx, const char *path, const char *content_type)
{
    int fd;
    struct stat stat_buf;
    char buf[512];
    char *p = buf;
    int n;

    if (!content_type) content_type = "text/html";
    
    //#ifdef _WIN32
    //fd = open(path, O_RDONLY | _O_BINARY);
    //#else
    fd = open(path, O_RDONLY);
    //#endif
    if (fd < 1) {
        LOG_ERR("Cannot open file \"%s\"", path);
        p += sprintf(p, "HTTP/1.0 400 Bad\x0d\x0a"
            "Server: libwebserver (GPC)\x0d\x0a" // TODO: better identifier ?
            "\x0d\x0a"
        );
        do_send(ctx, buf, p - buf);

        return -1;
    }

    fstat(fd, &stat_buf);
    p += sprintf(p, "HTTP/1.0 200 OK\x0d\x0a"
            "Server: libwebserver (GPC)\x0d\x0a" // TODO: better identifier ?
            "Content-Type: %s\x0d\x0a"
            "Content-Length: %u\x0d\x0a"
            "\x0d\x0a", content_type, (unsigned int)stat_buf.st_size);

    do_send(ctx, buf, p - buf);

    n = 1;
    while (n > 0) {
        n = read(fd, buf, 512);
        if (n <= 0)
            continue;
        do_send(ctx, buf, n);
        LOG_DBG("Served %d bytes of file \"%s\"", n, path); 
    }

    close(fd);

    return 0;
}

const char * wsv_extract_url(const char *header, char *buffer) 
{
    const char *start, *end;
    
    if ((strlen(header) < 92) || (memcmp(header, "GET ", 4) != 0)) {
        return 0;
    }
    
    start = header+4;
    end = strstr(start, " HTTP/1.1");
    if (!end) { return 0; }
    
    strncpy(buffer, start, end - start);
    buffer[end-start] = '\0';
    
    return buffer;
}

int wsv_exists_header_field(char *header, const char *name)
{
    char key[128];
    sprintf(key, "\r\n%s: ", name );
    return strstr(header, key) != NULL;
}

const char * wsv_extract_header_field(const char *header, const char *name, char *buffer) 
{
    const char *p, *q;
    size_t nlen;
    
    nlen = strlen(name);
    do {
        p = strstr(header, name);
        if (!p) return 0;
        // repeat search if match was incomplete
    } while (*(p-1) != '\n' || *(p + nlen) != ':');
    
    p += nlen + 2;
    q = strstr(p, "\r\n");
    if (!q) return 0;
    
    if (buffer != NULL) {
        strncpy(buffer, p, q - p);
        buffer[q-p] = '\0';
        return buffer;
    }
    else {
        return p;
    }
}

const char * wsv_extract_payload(const char *handshake, char *buffer) 
{
    const char *p;
    p = strstr(handshake, "\r\n\r\n");
    if (!p) return NULL;
    if (buffer != NULL) {
        strcpy(buffer, p + 4);
        return buffer;
    }
    else return p + 4;
}

#ifdef NOT_DEFINED

/* Code adapted from post by Michael B. Allen, found on bytes.com through Google.
 * Many thanks!
 */
size_t wsv_url_decode(const char *src, size_t slen, char *dst, size_t dlen)
{
    int state = 0, code;
    const char *slim;
    char *dlim;
    char *start = dst;

    slim = src + slen;
    dlim = dst + dlen;
    
    if (dst >= dlim) {
        return 0;
    }
    dlim--; /* ensure spot for '\0' */
    
    while (src < slim && dst < dlim) {
        switch (state) {
            case 0:
                if (*src == '%') {
                    state = 1;
                } else {
                    *dst++ = *src;
                }
                break;
            case 1:
                code = *src - 48;
            case 2:
                if (!isdigit(*src)) {
                    return -1;
                }
                if (state == 2) {
                    *dst++ = (code * 16) + *src - 48;
                    state = 0;
                } else {
                    state = 2;
                }
                break;
        }
        src++;
    }
    *dst = '\0'; /* I'll be back */
    
    return dst - start;
}

#else

/* FROM THE MONGOOSE SOURCE CODE
 */
size_t wsv_url_decode(const char *src, size_t src_len, char *dst,
                      size_t dst_len, int is_form_url_encoded) 
{
    size_t i, j;
    int a, b;
    #define HEXTOI(x) (isdigit(x) ? x - '0' : x - 'W')
    
    for (i = j = 0; i < src_len && j < dst_len - 1; i++, j++) {
        if (src[i] == '%' &&
            isxdigit(* (const unsigned char *) (src + i + 1)) &&
            isxdigit(* (const unsigned char *) (src + i + 2))) {
            a = tolower(* (const unsigned char *) (src + i + 1));
        b = tolower(* (const unsigned char *) (src + i + 2));
        dst[j] = (char) ((HEXTOI(a) << 4) | HEXTOI(b));
        i += 2;
            } else if (is_form_url_encoded && src[i] == '+') {
                dst[j] = ' ';
            } else {
                dst[j] = src[i];
            }
    }
    
    dst[j] = '\0'; /* Null-terminate the destination */
    
    return j;
}
                  
#endif

/* Resolve host, with IP address parsing 
 */ 
int wsv_resolve_host(struct in_addr *sin_addr, const char *hostname) 
{ 
    if (!inet_pton(AF_INET, hostname, sin_addr)) { 
        struct addrinfo *ai, *cur; 
        struct addrinfo hints; 
        memset(&hints, 0, sizeof(hints)); 
        hints.ai_family = AF_INET; 
        if (getaddrinfo(hostname, NULL, &hints, &ai)) 
            return -1; 
        for (cur = ai; cur; cur = cur->ai_next) { 
            if (cur->ai_family == AF_INET) { 
                *sin_addr = ((struct sockaddr_in *)cur->ai_addr)->sin_addr; 
                freeaddrinfo(ai); 
                return 0; 
            } 
        } 
        freeaddrinfo(ai); 
        return -1; 
    } 
    return 0; 
} 

void wsv_start_server(wsv_settings_t *settings)
{
    int lsock, csock, pid, sopt = 1;
    size_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    char addr_buf[128];
    int conn_id;
    #ifdef _WIN32
    thread_params_t thparams;
    HANDLE hThread;
    #endif
    
    wsv_initialize();
    
    if (!settings->handler) settings->handler = dflt_request_handler;
    
    csock = lsock = 0;
    
    conn_id = 1;
    
    lsock = socket(AF_INET, SOCK_STREAM, 0);
    if (lsock < 0) { LOG_ERR("ERROR creating listener socket"); return; }
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(settings->listen_port);
    
    /* Resolve listen address */
    if (settings->listen_host && (settings->listen_host[0] != '\0')) {
        if (wsv_resolve_host(&serv_addr.sin_addr, settings->listen_host) < -1) {
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
        LOG_MSG("got client connection from %s", inet_ntop(cli_addr.sin_family, &cli_addr.sin_addr,
            addr_buf, sizeof(addr_buf)));
        
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
            handle_request(conn_id, csock, settings);
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
