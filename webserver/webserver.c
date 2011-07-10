#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>
#ifdef _WIN32
#include <Winsock2.h>
#include <osisock.h>
#include <WS2tcpip.h>
#include <direct.h>
#else
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#include <arpa/inet.h>
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

/* Windows / Visual Studio Quirks */

#ifdef _WIN32

#pragma warning(disable:4996)
#define close closesocket
#define strdup _strdup
#define usleep Sleep

#endif

/* Global variables */

static int daemonized = 0; // TODO: support daemonizing
static int ssl_initialized = 0;

/* Logging/Tracing */

#define __LOG(stream, ...) \
if (! daemonized) { \
    fprintf(stream, __VA_ARGS__); \
    fprintf(stream, "\n" ); \
    }
    
#define LOG_MSG(...) __LOG(stdout, __VA_ARGS__);
#define LOG_ERR(...) __LOG(stderr, __VA_ARGS__);
#define LOG_DBG LOG_MSG

/* Private routines */

static void 
context_free(wsv_ctx_t *ctx) 
{
    if (ctx->ssl) {
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
    }
    if (ctx->ssl_ctx) {
        SSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
    }
    if (ctx->sockfd) {
        shutdown(ctx->sockfd, SHUT_RDWR);
        close(ctx->sockfd);
        ctx->sockfd = 0;
    }
    free(ctx);
}

static wsv_ctx_t *
create_context(int socket, wsv_settings_t *settings) {
    wsv_ctx_t *ctx;
    ctx = malloc(sizeof(wsv_ctx_t));
    ctx->settings = settings;
    ctx->sockfd = socket;
    ctx->ssl = NULL;
    ctx->ssl_ctx = NULL;
    return ctx;
}

static wsv_ctx_t *
create_context_ssl(int socket, wsv_settings_t *settings) 
{
    int ret;
    const char * use_keyfile;
    wsv_ctx_t *ctx;

    ctx = create_context(socket, settings);

    if (settings->keyfile && (settings->keyfile[0] != '\0')) {
        // Separate key file
        use_keyfile = settings->keyfile;
    } else {
        // Combined key and cert file
        use_keyfile = settings->certfile;
    }

    // Initialize the library
    if (! ssl_initialized) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ssl_initialized = 1;
    }

    ctx->ssl_ctx = SSL_CTX_new(TLSv1_server_method());
    if (ctx->ssl_ctx == NULL) {
        LOG_ERR("Failed to configure SSL context");
        goto fail;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, use_keyfile,
                                    SSL_FILETYPE_PEM) <= 0) {
        LOG_ERR("Unable to load private key file %s\n", use_keyfile);
        goto fail;
    }

    if (SSL_CTX_use_certificate_file(ctx->ssl_ctx, settings->certfile,
                                     SSL_FILETYPE_PEM) <= 0) {
        LOG_ERR("Unable to load certificate file %s\n", settings->certfile);
        goto fail;
    }

//    if (SSL_CTX_set_cipher_list(ctx->ssl_ctx, "DEFAULT") != 1) {
//        sprintf(msg, "Unable to set cipher\n");
//        fatal(msg);
//    }

    // Associate socket and ssl object
    ctx->ssl = SSL_new(ctx->ssl_ctx);
    SSL_set_fd(ctx->ssl, socket);

    ret = SSL_accept(ctx->ssl);
    if (ret < 0) {
        LOG_ERR("Failed to accept the SSL connection");
        goto fail;
    }

    return ctx;
    
fail:
    if (ctx) context_free(ctx);
    return NULL;
}

/* Default request handler.
 * TODO: real error codes
 */
static int 
dflt_request_handler(wsv_ctx_t *ctx, const char *header, void *userdata)
{
    char url[1024], dec[1024], path[1024];
    
    LOG_DBG("%s %s", __FILE__, __FUNCTION__);
    
    // Extract the URL and decode it
    if (!wsv_extract_url(header, url)) {
        LOG_ERR("Request does not contain a URL");
        return -1;
    }
    wsv_url_decode(url, sizeof(url), dec, sizeof(dec), 0);
    //LOG_DBG("%s %s: request URL (decoded) = \"%s\"", __FILE__, __FUNCTION__, dec);
    
    // Serve the requested file
    if (strlen(dec) > 0) {
        // TODO: remove the parameters
        if (wsv_path_to_native(dec, path, 1024, 1) == 0) {
            LOG_ERR("Failed to convert standardized path \"%s\" to native", dec);
            // TODO: send error message
            return -1;
        }
        wsv_serve_file(ctx, path, NULL); // TODO: return code ?
    }
    
    return 0; // all is well
}

static void 
handle_request(int conn_id, int sockfd, wsv_settings_t *settings)
{
    char header[2048];
    wsv_ctx_t *ctx;
    ssize_t len, hlen;
    char protocol[256];
    const char *p;
    char *q;
    int upgraded;
    struct _wsv_upgrade_entry *pr;
    int err;
    
    LOG_DBG("%s", __FUNCTION__);
    
    ctx = NULL;
    
    // Look at the first byte of the HTTP request
    len = recv(sockfd, header, 1, MSG_PEEK);
    if (len != 1) {
        LOG_DBG("Failed to peek at first byte of header");
        while (1) {
            len = recv(sockfd, header, 1, MSG_PEEK);
            if (len == 1) break;
            usleep(10);
        }
    };
    header[len] = '\0';

    // Detect / check for HTTPS
    if ((header[0] == '\x16' || header[0] == '\x80')) {
        if (settings->ssl_policy == wsv_no_ssl) {
            LOG_ERR("HTTP request seems to be SSL-encoded but no SSL connections are allowed");
            goto fail;
        }
        ctx = create_context_ssl(sockfd, settings);
        if (!ctx) goto fail;
    }
    else {
        if (settings->ssl_policy == wsv_ssl_only) {
            LOG_ERR("Receiving plain HTTP request but HTTPS is required");
            goto fail;
        }
        ctx = create_context(sockfd, settings);
        if (!ctx) goto fail;
        //LOG_DBG("Using plain (not SSL) socket");
    }

    // Now get the full header
    hlen = 0;
    while (1) {
        LOG_DBG("About to get a chunk of the header");
        len = wsv_recv(ctx, header+hlen, sizeof(header)-hlen);
        if (len <= 0) break;
        hlen += len;
    }
    header[hlen] = '\0';
    LOG_DBG("-- Header ---:\n%s\n-------------", header);

    // TODO: handle the CONNECTION method before looking at upgrades
    
    // Do we have an "Upgrade" header field ?
    if (wsv_extract_header_field(header, "Upgrade", protocol)) {
        LOG_DBG("Client asks to upgrade the protocol to any of: %s", protocol);
        p = protocol;
        upgraded = 0;
        while (p && *p) {
            q = strchr(p, ',');
            if (q) *q = '\0';
            LOG_DBG("Looking for handler for upgrade protocol \"%s\"", p);
            for (pr = settings->protocols; pr; pr = pr->next) {
                if (strcasecmp(protocol, pr->protocol) == 0) {
                    upgraded = 1;
                    //LOG_DBG("Found handler for upgrade protocol \"%s\"", protocol);
                    err = pr->handler(ctx, header, pr->userdata);
                    if (err) LOG_ERR("Handler for upgrade protocol \"%s\" returned non-zero exit code", protocol);
                    break;
                }
            }
            if (upgraded) break;
            if (q) while (*q && isspace(*q)) q++;
            p = q;
        }
        if (!upgraded) LOG_ERR("No handler found for upgrade protocol \"%s\"", protocol);
    }
    else {
        // Call the standard handler
        LOG_DBG("%s calling the standard handler", __FUNCTION__);
        settings->handler(ctx, header, settings->userdata);
    }    

    // We're done
    shutdown(sockfd, SHUT_RDWR);
    close(sockfd);
    LOG_DBG("--- Request handled ---------------------------");
    
    return;
    
fail:
    if (ctx) context_free(ctx);
}

static const char *get_mime_type(const char *path)
{
    const char *p, *q;
    size_t n;

    p = strrchr(path, '.');
    if (p) {
        p ++;
        q = strchr(p, '?');
        n = q ? q - p : strlen(p);
        if (strncmp(p, "js", n) == 0)
            return "text/javascript";
        else if (strncmp(p, "html", n) == 0) 
            return "text/html";
        else if (strncmp(p, "htm", n) == 0)
            return "text/htm";
        else if (strncmp(p, "css", n) == 0)
            return "text/css";
        else if (strncmp(p, "text", n) == 0)
            return "text/plain";
        else if (strncmp(p, "ico", n) == 0)
            return "image/x-icon";
        else
            return "text/plain";
    }
    else
        return "text/plain";
}

#ifdef _WIN32

typedef struct {
    int socket;
    wsv_settings_t *settings;
    int conn_id;
} thread_params_t;

static DWORD WINAPI client_thread( LPVOID lpParameter )
{
    thread_params_t params;
    
    params = * ((thread_params_t*) lpParameter);
    free(lpParameter);

    LOG_DBG("%s", __FUNCTION__);
    
    handle_request(params.conn_id, params.socket, params.settings);
    
    return 0;
}

/* We get (or assume we get...) the normalized path as UTF-8 (URL-decoded).
 * RETURNS THE NUMBER OF BYTES, *NOT* UTF-8 CHARACTER SEQUENCES!
 * "Normalized" means that absolute paths start with a slash, followed by
 * the drive letter (TODO: support volume names?). Relative paths are used
 * "as is" (except that forward slashes are replaced by backward ones).
 * The parameter cwdroot can be used to force absolute paths to be treated
 * as relative to the working directory. In that case, the initial slash
 * must still be there, but it doesn't have to be followed by a drive letter.
 */
static size_t 
normalized_path_to_native_w32(const char *normalized, char *native, size_t bufsize, int cwdroot)
{
    size_t nsize;
    const char * p;
    char *q;
    size_t ntsize, size;
    
    p = normalized;
    nsize = strnlen(normalized, FILENAME_MAX);
    q = native;
    *q = '\0';
    ntsize = 0;
    
    // Absolute path ?
    if (normalized[0] == '/')
    {
        if (cwdroot) {
            if (!getcwd(q, bufsize)) {
                LOG_ERR("Failed to retrieve the current working directory");
                return 0; }
                size = strlen(q);
                q += size;
                ntsize += size;
        }
        else {
            char drive;
            p ++;
            if ( ! *p ) return 1; // legal: an empty native path means we want the list of drives       
            if ( !isalpha(*p) ) return 0; // illegal: if there is a name after the root specifier, it must be a drive letter
            drive = *p ++;
            if ( ! *p ) return 0; // 
            if ( *p != '/' ) return 0; // illegal: drive letter must be followed by nothing or a slash
            p ++;
            *q ++ = toupper(drive);
            *q ++ = ':';
            *q ++ = '\\';
            ntsize = 3;
        }
    }
    
    for ( ; *p; p ++, q++, ntsize ++ ) 
    {
        if ( q >= (native+bufsize-1) )
            return 0;
        *q = (*p == '/' ? '\\' : *p);
    }
    *q = '\0';
    
    return ntsize;
}

#else // !__WIN32

static void signal_handler(int sig)
{
    // TODO
}

#endif

/* Public functionality implementations */

int 
wsv_initialize()
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

int 
wsv_register_protocol(wsv_settings_t *settings, const char *name, wsv_handler_t handler, void *userdata)
{
    struct _wsv_upgrade_entry *pred, *node;
    
    for (pred = (struct _wsv_upgrade_entry*) &settings->protocols; pred->next != NULL; pred = pred->next);
    
    node = pred->next = malloc(sizeof(struct _wsv_upgrade_entry));
    
    node->next = NULL;
    node->protocol = strdup(name);
    node->handler = handler;
    node->userdata = userdata;
    
    return 0;
}

size_t 
wsv_path_to_native(const char *std, char *native, size_t size, int cwdroot)
{
#ifndef _WIN32
    size_t cwdlen, plen;
    if (cwdroot || (std[0] && std[0] != '/')) {
        if (!getcwd(native, size)) return 0;
        LOG_DBG("getcwd() -> %s", native);
        cwdlen = strlen(native);
        plen = strlen(std);
        if (cwdlen + plen >= size) return 0;
        strcat(native, std);
        LOG_DBG("Native path: \"%s\"", native);
        return cwdlen + plen;
    }
    else {
        plen = strlen(native);
        if (plen >= size) return 0;
        strcpy(native, std);
        LOG_DBG("Native path is same as standardized: \"%s\"", native);
        return plen;
    }
#else
    size_t nlen;
    nlen = normalized_path_to_native_w32(std, native, size, cwdroot);
    LOG_DBG("Native path: \"%s\"", native);
    return nlen;
#endif
}

int 
wsv_serve_file(wsv_ctx_t *ctx, const char *path, const char *content_type)
{
    int fd;
    struct stat stat_buf;
    char buf[512];
    char *p = buf;
    int nr, ns;

    LOG_DBG("%s serving file \"%s\"", __FUNCTION__, path);

    #ifdef _WIN32
    fd = open(path, O_RDONLY | _O_BINARY);
    #else
    fd = open(path, O_RDONLY);
    #endif
    if (fd < 1) {
        LOG_ERR("Cannot open file \"%s\"", path);
        p += sprintf(p, "HTTP/1.0 400 Bad\x0d\x0a"
            "Server: libwebserver (GPC)\x0d\x0a" // TODO: better identifier ?
            "\x0d\x0a"
        );
        wsv_sendall(ctx, buf, p - buf);
        return -1;
    }

    if (!content_type) {
        content_type = get_mime_type(path); //content_type = "text/html";
    }
    
    fstat(fd, &stat_buf);
    p += sprintf(p, "HTTP/1.0 200 OK\x0d\x0a"
            "Server: GPC-libwebserver\x0d\x0a" // TODO: better identifier ?
            "Content-Type: %s\x0d\x0a"
            "Content-Length: %u\x0d\x0a"
            "\x0d\x0a", content_type, (unsigned int)stat_buf.st_size);

    wsv_sendall(ctx, buf, p - buf);

    while (1) {
        nr = read(fd, buf, 512);
        if (nr <= 0)
            break;
        ns = wsv_sendall(ctx, buf, nr);
        LOG_DBG("Served %d bytes of file \"%s\"", ns, path); 
    }

    close(fd);

    return 0;
}

const char * 
wsv_extract_url(const char *header, char *buffer) 
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

int 
wsv_exists_header_field(char *header, const char *name)
{
    char key[256];
    assert(strlen(header) < 4096);
    sprintf(key, "\r\n%s: ", name );
    return strstr(header, key) != NULL;
}

const char * 
wsv_extract_header_field(const char *header, const char *name, char *buffer) 
{
    const char *p, *q;
    size_t nlen;
    
    buffer[0] = '\0';
    
    nlen = strlen(name);
    p = header;
    do {
        p++;
        p = strstr(p, name);
        if (!p) return 0;
        // repeat search if match was incomplete
    } while (*(p-1) != '\n' || *(p-2) != '\r' || *(p + nlen) != ':');
    
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

const char * 
wsv_extract_payload(const char *handshake, char *buffer) 
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
 * Thanks a lot!
 */
size_t 
wsv_url_decode(const char *src, size_t src_len, char *dst,
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

/* FROM THE MONGOOSE SOURCE CODE
 * Thanks a lot!
 */
void
wsv_url_encode(const char *src, char *dst, size_t dst_len)
{
    const char  *dont_escape = "._-$,;~()";
    const char  *hex = "0123456789abcdef";
    const char  *end = dst + dst_len - 1;
    
    for (; *src != '\0' && dst < end; src++, dst++) {
        if (isalnum(*(unsigned char *) src) ||
            strchr(dont_escape, * (unsigned char *) src) != NULL) {
            *dst = *src;
            } else if (dst + 2 < end) {
                dst[0] = '%';
                dst[1] = hex[(* (unsigned char *) src) >> 4];
                dst[2] = hex[(* (unsigned char *) src) & 0xf];
                dst += 2;
            }
    }
    
    *dst = '\0';
}

/* Resolve host, with IP address parsing 
 * Returns non-zero if an error occurred.
 */ 
int 
wsv_resolve_host(struct in_addr *sin_addr, const char *hostname) 
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

int 
wsv_start_server(wsv_settings_t *settings)
{
    int err;
    int lsock, csock, pid, sopt = 1;
    size_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    char addr_buf[128];
    int conn_id;
#ifdef _WIN32
    thread_params_t *thparams;
    HANDLE hThread;
    DWORD dwParam;
    u_long ulParam;
#endif
    
    err = wsv_initialize();
    if (err != 0) return -1;
    
    if (!settings->handler) settings->handler = dflt_request_handler;
    
    csock = lsock = 0;
    
    conn_id = 1;
    
    lsock = socket(AF_INET, SOCK_STREAM, 0);
    if (lsock < 0) { LOG_ERR("ERROR creating listener socket"); return -1; }
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(settings->listen_port);
    
    /* Resolve listen address */
    if (settings->listen_host && (settings->listen_host[0] != '\0')) {
        if (wsv_resolve_host(&serv_addr.sin_addr, settings->listen_host) < -1) {
            LOG_ERR("Could not resolve listen address");
            close(lsock);
            return -1;
        }
    } else {
        serv_addr.sin_addr.s_addr = INADDR_ANY;
    }
    
    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (char *)&sopt, sizeof(sopt));
    if (bind(lsock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        //int err = WSAGetLastError();
        LOG_ERR("ERROR on binding listener socket");
        close(lsock);
        return -1;
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
        csock = accept(lsock, (struct sockaddr *) &cli_addr, &clilen);
        if (csock < 0) {
            LOG_ERR("ERROR on accept");
            continue;
        }
        LOG_MSG("Got client connection from %s", inet_ntop(cli_addr.sin_family, &cli_addr.sin_addr,
            addr_buf, sizeof(addr_buf)));
        
#ifdef _WIN32
        ulParam = 1;
        if (ioctlsocket(csock, FIONBIO, &ulParam) != 0) {
            LOG_ERR("Failed to set client socket in non-blocking mode");
        }
        dwParam = 100;
        if (setsockopt(csock, SOL_SOCKET, SO_RCVTIMEO, (char*)&dwParam, sizeof(dwParam)) != 0) {
            LOG_ERR("Failed to set client socket timeout, error: %d", err);
        }
        thparams = (thread_params_t*) malloc(sizeof(thread_params_t));
        if (thparams == NULL) {
            LOG_ERR("Failed to allocate thread parameter structure");
            return -1;
        }
        thparams->settings = settings;
        thparams->socket = csock;
        thparams->conn_id = conn_id;
        conn_id += 1;
        LOG_DBG("Creating thread to handle connection #%d", thparams->conn_id);
        hThread = CreateThread(NULL, 0, client_thread, (LPVOID) thparams, 0, NULL );
        if (hThread == NULL) {
            LOG_ERR("failed to create proxy thread");
            break;
        }
#else
        if (fcntl(csock, F_SETFL, O_NONBLOCK) < 0) {
            LOG_ERR("Failed to set client socket to non-blocking mode");
        }
        LOG_MSG("forking handler process");
        pid = fork();
        
        if (pid == 0) {  // handler process
            handle_request(conn_id, csock, settings);
            LOG_MSG("exiting child process");
            break;   // Child process exits
        } else {         // parent process
            conn_id += 1;
        }
#endif
    }
    #ifndef _WIN32
    if (pid == 0) {
    } else {
        // TODO: can this ever be reached ?
        LOG_MSG("webserver listener exit");
    }
    #endif
    
    return 0;
}

#ifndef _WIN32

// TODO

void 
wsv_daemonize(int keepfd) 
{
    int pid, i;
    
    umask(0);
    chdir("/");
    setgid(getgid());
    setuid(getuid());
    
    /* Double fork to daemonize */
    pid = fork();
    if (pid<0) { LOG_ERR("fork error"); exit(-1); }
    if (pid>0) { exit(0); }  // parent exits
    setsid();                // Obtain new process group
    pid = fork();
    if (pid<0) { LOG_ERR("fork error"); exit(-1); }
    if (pid>0) { exit(0); }  // parent exits

    /* Signal handling */
    signal(SIGHUP, signal_handler);   // catch HUP
    signal(SIGTERM, signal_handler);  // catch kill
    
    /* Close open files */
    for (i=getdtablesize(); i>=0; --i) {
        if (i != keepfd) {
            close(i);
        } /* else if (settings.verbose) {
            printf("keeping fd %d\n", keepfd);
    } */
    }
    i=open("/dev/null", O_RDWR);  // Redirect stdin
    dup(i);                       // Redirect stdout
    dup(i);                       // Redirect stderr
}

#endif // ! _WIN32

ssize_t 
wsv_send(wsv_ctx_t *ctx, const void *pbuf, size_t blen)
{
    int size;
    int err;

    if (ctx->ssl) {
        LOG_DBG("SSL send");
        size = SSL_write(ctx->ssl, pbuf, blen);
        if (size <= 0) {
            err = SSL_get_error(ctx->ssl, size);
            switch (err) {
            case SSL_ERROR_WANT_WRITE: 
            case SSL_ERROR_WANT_CONNECT:
            case SSL_ERROR_WANT_ACCEPT:
            case SSL_ERROR_WANT_X509_LOOKUP:
                return WSVSR_WAIT;
            default:
                return WSVSR_CONNECTION_LOST;
            }
        }
        return size;
    } else {
        size = send(ctx->sockfd, (char*) pbuf, blen, 0);
        return size;
    }
}

ssize_t
wsv_sendall(wsv_ctx_t *ctx, const void *pbuf, size_t blen)
{
    size_t total, slen;
    total = 0;
    while (1) {
        slen = wsv_send(ctx, (char*) pbuf + total, blen - total);
        if (slen < 0) return slen;
        total += slen;
        if (total >= blen) 
            return (ssize_t) total;
        usleep(1);
    }
    return -1;
}

ssize_t 
wsv_recv(wsv_ctx_t *ctx, void *pbuf, size_t blen)
{
    int size;
    int err;

    if (ctx->ssl) {
        LOG_DBG("SSL recv");
        size = SSL_read(ctx->ssl, pbuf, blen);
        if (size <= 0) {
            err = SSL_get_error(ctx->ssl, size);
            switch (err) {
            case SSL_ERROR_WANT_READ: 
            case SSL_ERROR_WANT_CONNECT:
            case SSL_ERROR_WANT_ACCEPT:
            case SSL_ERROR_WANT_X509_LOOKUP:
                return WSVSR_WAIT;
            default:
                return WSVSR_CONNECTION_LOST;
            }
        }
        return size;
    } else {
        //LOG_DBG("TCP recv");
        size = recv(ctx->sockfd, (char*) pbuf, blen, 0);
        return size;
    }
}

ssize_t 
wsv_peek(wsv_ctx_t *ctx, void *pbuf, size_t blen)
{
    if (ctx->ssl) {
        LOG_DBG("SSL peek");
        return SSL_peek(ctx->ssl, pbuf, blen);
    } else {
        LOG_DBG("TCP peek");
        return recv(ctx->sockfd, (char*) pbuf, blen, MSG_PEEK);
    }
}

int 
wsv_getsockfd(wsv_ctx_t* ctx)
{
    return ctx->sockfd;
}
