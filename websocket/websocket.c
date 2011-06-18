/*
 * WebSocket lib with support for "wss://" encryption.
 * Copyright 2010 Joel Martin
 * Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
 *
 * You can make a cert/key with openssl using:
 * openssl req -new -x509 -days 365 -nodes -out self.pem -keyout self.pem
 * as taken from http://docs.python.org/dev/library/ssl.html#certificates
 *
 * 2011-06-12 gygax@practicomp.ch   Separating websocket from "websockifying"
 *      functionality
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <assert.h>
#include <sys/types.h> 
#ifdef _WIN32
#include <Winsock2.h>
#include <WS2tcpip.h>
#include <osisock.h>
#include <base64.h>
#else
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <resolv.h>      /* base64 encode/decode */
#include <signal.h> // daemonizing
#include <fcntl.h>  // daemonizing
#endif
#include <openssl/err.h>
#include <openssl/ssl.h>
//#include "md5.h"
#include "websocket.h"

/* External declarations not found in headers */

extern void *md5_buffer (const char *buffer, size_t len, void *resblock);

/* Adaptation to platform specifics */

#ifndef _WIN32
#define closesocket close
#endif

/* Debugging utilities */

#ifdef _DEBUG

#define BLOCKSTART_MAGIC            (0xabcd)

static void check_block(ws_protocol_t prot, ws_byte_t *block) {
    switch (prot) {
    case base64: 
        assert(*((unsigned short*)(block-sizeof(unsigned short))) == BLOCKSTART_MAGIC);
        break;
    default:
        assert(0);
    }
}

#define CHECK_BLOCK(prot, block)    check_block(prot, block)

#else

#define BLOCK_MAGIC_SIZE    0
#define CHECK_BLOCK(prot, block)

#endif

/* Struct required to service an established connection. 
 */
struct _ws_context {
    int             sockfd;
    ws_listener_t   *settings;
    int             id;             // Identifies connections established by a listener
    SSL_CTX         *ssl_ctx;
    SSL             *ssl;
    ws_protocol_t   protocol;
    ws_byte_t       *encbuf;        // buffer used for encoding/decoding  TODO: allocate/free
    size_t          encsize;        // number of bytes in encoding buffer
    ws_byte_t       *tsfrag;        // "to send" fragment pointer
    size_t          tslen;          // length left to send
};

static const char server_handshake_hixie[] = "\
HTTP/1.1 101 Web Socket Protocol Handshake\r\n\
Upgrade: WebSocket\r\n\
Connection: Upgrade\r\n\
%sWebSocket-Origin: %s\r\n\
%sWebSocket-Location: %s://%s%s\r\n\
%sWebSocket-Protocol: base64\r\n\
\r\n%s";

static const char server_handshake_hybi[] = "\
HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: %s\r\n\
Sec-WebSocket-Protocol: %s\r\n\
\r\n\
";

const char policy_response[] = "<cross-domain-policy><allow-access-from domain=\"*\" to-ports=\"*\" /></cross-domain-policy>\n";

static int daemonized = 0;

// TODO: replace with real logging mechanism
// TODO: version that takes connection ID

#define __LOG(stream, ...) \
    if (! daemonized) { \
        fprintf(stream, "  "); \
        fprintf(stream, __VA_ARGS__); \
        fprintf(stream, "\n" ); \
    }

#define LOG_MSG(...) __LOG(stdout, __VA_ARGS__);
#define LOG_ERR(...) __LOG(stderr, __VA_ARGS__);
#define LOG_DBG LOG_MSG

/*
 * Get the path from the handhake header.
 */
static const char * get_path(const char *handshake, char *buffer) 
{
	const char *start, *end;

    if ((strlen(handshake) < 92) || (memcmp(handshake, "GET ", 4) != 0)) {
        return 0;
    }

    start = handshake+4;
    end = strstr(start, " HTTP/1.1");
    if (!end) { return 0; }

	strncpy(buffer, start, end - start);
    buffer[end-start] = '\0';

    return buffer;
}

/* Checks if the specified header field exists in the header.
 */
static int check_header_field(char *handshake, const char *name)
{
	char key[128];
	sprintf(key, "\r\n%s: ", name );
    return strstr(handshake, key) != NULL;
}

/* Extracts a header field from the handshake.
 */
static const char * get_header_field(const char *handshake, const char *name, char *buffer) 
{
	const char *p, *q;
	size_t nlen;

    nlen = strlen(name);
	do {
        p = strstr(handshake, name);
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

static const char * get_payload(const char *handshake, char *buffer) 
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

static size_t b64_buffer_size(size_t block_size)
{
    // Delimiters (00 and ff), 4/3 ratio, and rounding up to 4-byte groups
    return 1 + 4 * ((block_size*4 / 3 + 3) / 4) + 1;
}

/* Calculate the worst-case quantity of payload data that can be carried by a
   base64-encoded buffer of the specified size (reverse of b64_buffer_size()).
 */
static size_t b64_data_size(size_t buffer_size)
{
    return 3 * (buffer_size - 3 - 1 - 1) / 4;
}

static int encode_b64(u_char const *src, size_t srclength, char *target, size_t targsize) 
{
    int sz = 0, len = 0;
    target[sz++] = '\x00';
    len = b64_ntop(src, srclength, target+sz, targsize-sz);
    if (len < 0) {
        LOG_ERR("Base64 encoding error");
        return len;
    }
    sz += len;
    target[sz++] = '\xff';
    return sz;
}

static ssize_t decode_b64(char *src, size_t srclength, u_char *target, size_t targsize) 
{
    char *start, *end;
    int len, framecount = 0, retlen = 0;
    // Orderly "close" frame ?
    if (src[0] == '\xff' && src[srclength-1] == '\x00') {
        return 0;
    }
    else if ((src[0] != '\x00') || (src[srclength-1] != '\xff')) {
        LOG_ERR("WebSocket framing error");
        return WSE_FRAMING_ERROR;
    }
    start = src+1; // Skip '\x00' start
    do {
        /* We may have more than one frame */
        end = memchr(start, '\xff', srclength);
        *end = '\x00';
        len = b64_pton(start, target+retlen, targsize-retlen);
        if (len < 0) {
            LOG_ERR("Base64 decoding error");
            return WSE_DECODING_ERROR;
        }
        retlen += len;
        start = end + 2; // Skip '\xff' end and '\x00' start 
        framecount++;
    } while (end < (src+srclength-1));
    if (framecount > 1) {
        LOG_MSG("%d", framecount); // TODO: formerly traffic()
    }
    return retlen;
}

/* Ensures that the base64 encoding buffer is big enough to hold an encoded 
   data block of the specified size, and reallocate a big enough one if
   that is not the case.

   TODO: provide some rounding up and padding so it won't reallocate too often.
 */
static int check_b64_buffer(ws_ctx_t *ctx, size_t blocklen)
{
    size_t bsize;

    bsize = b64_buffer_size(blocklen);
    if (ctx->encsize < bsize) {
        free(ctx->encbuf);
        ctx->encbuf = malloc(bsize);
        if (ctx->encbuf == NULL) 
            return WSE_OUT_OF_MEMORY;
        ctx->encsize = bsize;
    }

    return 0;
}

/* Prepares a data block for sending. What this means exactly depends on the
   protocol; for base64, it involves the base64 encoding proper, plus the 
   framing (delimiting between 00 and ff bytes). For binary (not implemented
   yet), it might mean enclosing the block in framing bytes.
   Note: there is no guarantee that this function will leave the passed data
    block untouched. With the binary protocol for instance (not implemented
    yet), framing can be done without having to copy the data, provided that 
    the data block was allocated with ws_alloc_block().
 */
static int prep_block(ws_ctx_t *ctx, ws_byte_t *block, size_t len)
{
    int err;
    int size;

    CHECK_BLOCK(ctx->protocol, block);

    switch(ctx->protocol) {
    case base64:
        err = check_b64_buffer(ctx, len);
        if (err < 0) return err;
        size = encode_b64(block, len, ctx->encbuf, ctx->encsize);
        if (size < 0 || (size_t) size <= len) {
            err = WSE_ENCODING_ERROR;
            return err;
        }
        ctx->tsfrag = ctx->encbuf;
        ctx->tslen = (size_t) size;
        break;
    //case binary:
        //...
        //break;
    default:
        return WSE_UNSUPPORTED_PROTOCOL;
    };

    return 0;
}

static void free_context(ws_ctx_t *ctx) 
{
    if (ctx->encbuf) free(ctx->encbuf);
    if (ctx->ssl_ctx) SSL_CTX_free(ctx->ssl_ctx);
    if (ctx->ssl) SSL_free(ctx->ssl);
    free(ctx);
}

static ws_ctx_t *create_socket(int socket, ws_listener_t *settings) 
{
    ws_ctx_t *ctx;

    ctx = malloc(sizeof(struct _ws_context));
    if (ctx == NULL) return NULL;
    ctx->sockfd = socket;
    ctx->ssl = NULL;
    ctx->ssl_ctx = NULL;
    ctx->encbuf = NULL;
    ctx->encsize = 0;
    ctx->tsfrag = NULL;
    ctx->settings = settings;
    return ctx;
}

static ws_ctx_t *create_socket_ssl(int socket, ws_listener_t *settings) 
{
    static int ssl_initialized = 0;
    int ret;
    const char * use_keyfile;
    ws_ctx_t *ctx = NULL;

    ctx = create_socket(socket, settings);
    if (ctx == NULL) return NULL;

    if (settings->keyfile && (settings->keyfile[0] != '\0')) {
        // Separate key file
        use_keyfile = settings->keyfile;
    } else {
        // Combined key and cert file
        use_keyfile = settings->certfile;
    }

    // Initialize the SSL library
    if (! ssl_initialized) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ssl_initialized = 1;
    }

    ctx->ssl_ctx = SSL_CTX_new(TLSv1_server_method());
    if (ctx->ssl_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        LOG_ERR("Failed to configure SSL context");
        goto fail;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, use_keyfile,
                                    SSL_FILETYPE_PEM) <= 0) {
        LOG_ERR("Unable to load private key file %s\n", use_keyfile);
        goto fail;
    }

    if (SSL_CTX_use_certificate_file(ctx->ssl_ctx, settings->certfile, SSL_FILETYPE_PEM) <= 0) {
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
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return ctx;

fail:
    free_context(ctx);
    return NULL;
}

// TODO: use atexit() to call this ?

static void socket_free(ws_ctx_t *ctx) 
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
        closesocket(ctx->sockfd);
        ctx->sockfd = 0;
    }
    free(ctx);
}

/* Generate the 16-byte MD5 code from the keys provided in the handshake
 * header.
 */
static int gen_md5(const char *handshake, char *target)
{
    unsigned int i, spaces1 = 0, spaces2 = 0;
    unsigned long num1 = 0, num2 = 0;
    unsigned char buf[17];
    char valbuf[128];
	const char *value;

	value = get_header_field(handshake, "Sec-WebSocket-Key1", valbuf);
    if (!value) return 0;

    for (i=0; i < strlen(value); i++) {
        if (value[i] == ' ') {
            spaces1 += 1;
        }
        if ((value[i] >= 48) && (value[i] <= 57)) {
            num1 = num1 * 10 + (value[i] - 48);
        }
    }
    num1 = num1 / spaces1;

	value = get_header_field(handshake, "Sec-WebSocket-Key2", valbuf);
    if (!value) return 0;

    for (i=0; i < strlen(value); i++) {
        if (value[i] == ' ') {
            spaces2 += 1;
        }
        if ((value[i] >= 48) && (value[i] <= 57)) {
            num2 = num2 * 10 + (value[i] - 48);
        }
    }
    num2 = num2 / spaces2;

    /* Pack it big-endian */
    buf[0] = (unsigned char) ((num1 & 0xff000000) >> 24);
    buf[1] = (unsigned char) ((num1 & 0xff0000) >> 16);
    buf[2] = (unsigned char) ((num1 & 0xff00) >> 8);
    buf[3] = (unsigned char)  (num1 & 0xff);

    buf[4] = (unsigned char) ((num2 & 0xff000000) >> 24);
    buf[5] = (unsigned char) ((num2 & 0xff0000) >> 16);
    buf[6] = (unsigned char) ((num2 & 0xff00) >> 8);
    buf[7] = (unsigned char)  (num2 & 0xff);

    if (!get_payload(handshake, valbuf)) return 0;
    assert(strlen(valbuf) == 8);
	strncpy(buf+8, value, 8);
    buf[16] = '\0';

    md5_buffer(buf, 16, target);
    target[16] = '\0';

    return 1;
}

static ssize_t do_send(ws_ctx_t *ctx, const void *pbuf, size_t blen)
{
    if (ctx->ssl) {
        LOG_DBG("SSL send");
        return SSL_write(ctx->ssl, pbuf, blen);
    } else {
        return send(ctx->sockfd, (char*) pbuf, blen, 0);
    }
}

static ssize_t do_recv(ws_ctx_t *ctx, void *pbuf, size_t blen)
{
    if (ctx->ssl) {
        LOG_DBG("SSL recv");
        return SSL_read(ctx->ssl, pbuf, blen);
    } else {
        return recv(ctx->sockfd, (char*) pbuf, blen, 0);
    }
}
    
// TODO: support non-upgrade (HTTP)

static ws_ctx_t *do_handshake(int sock, ws_listener_t *settings) 
{
    char handshake[4096], response[4096], trailer[17], keynguid[1024+36+1], hash[20+1], accept[30+1];
    int len;
    int ver;
    char version[8+1];
    char key[64+1];
    char protocol[32+1];
    char origin[64+1];
    char host[256+1];
    char path[256+1];
    char *scheme, *pre;
    ws_ctx_t *ctx;
    size_t rlen, slen;

    // Peek, but don't read the data
    len = recv(sock, handshake, 1024, MSG_PEEK);
    handshake[len] = 0;
	LOG_DBG("Handshake:\n%s", handshake);
    if (len == 0) {
        LOG_MSG("ignoring empty handshake");
        return NULL;
    } else if (memcmp(handshake, "<policy-file-request/>", 22) == 0) {
        len = recv(sock, handshake, 1024, 0);
        handshake[len] = 0;
        LOG_MSG("sending flash policy response");
        send(sock, policy_response, sizeof(policy_response), 0);
        return NULL;
    } else if (handshake[0] == '\x16' || handshake[0] == '\x80') {
        // SSL
        if (!settings->certfile) {
            LOG_MSG("SSL connection but no cert specified");
            return NULL;
        } else if (access(settings->certfile, R_OK) != 0) {
            LOG_MSG("SSL connection but '%s' not found", settings->certfile);
            return NULL;
        }
        ctx = create_socket_ssl(sock, settings);
        if (! ctx) { return NULL; }
        scheme = "wss";
        LOG_MSG("using SSL socket");
    } else if (settings->ssl_only) {
        LOG_MSG("non-SSL connection disallowed");
        return NULL;
    } else {
        ctx = create_socket(sock, settings);
        if (! ctx) { return NULL; }
        scheme = "ws";
        LOG_MSG("using plain (not SSL) socket");
    }
    len = recv(ctx->sockfd, handshake, 4096, 0); // not in SSL yet, so use recv() directly
    if (len == 0) {
        LOG_ERR("Client closed connection during handshake");
        return NULL;
    }
    handshake[len] = 0;

	// HyBi/IETF version of the protocol ?
	if (get_header_field(handshake, "Sec-WebSocket-Version", version)) {
		ver = atoi(version);
		if (!get_header_field(handshake, "Sec-WebSocket-Protocol", protocol)) return 0;
		ctx->protocol = strcmp(protocol, "base64") == 0 ? base64 : binary;
		if (!get_header_field(handshake, "Sec-WebSocket-Key", key)) return 0;
		strcpy(keynguid, key);
		strcat(keynguid, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
		SHA1((const unsigned char*)keynguid, strlen(keynguid), hash);
		b64_ntop(hash, 20, accept, sizeof(accept));
		rlen = sprintf(response, server_handshake_hybi, accept, protocol);
	}
    // Hixie version of the protocol (75 or 76) ?
	else if (check_header_field(handshake, "Sec-WebSocket-Key1"))
	{
		if (get_payload(handshake, NULL)) {
			gen_md5(handshake, trailer);
			pre = "Sec-";
			LOG_MSG("using protocol version 76");
		} else {
			trailer[0] = '\0';
			pre = "";
			LOG_MSG("using protocol version 75");
		}
		ctx->protocol = base64; 
		if (!get_header_field(handshake, "Origin", origin)) return NULL;
		if (!get_header_field(handshake, "Host", host)) return NULL;
		if (!get_path(handshake, path)) return NULL;
		rlen = sprintf(response, server_handshake_hixie, pre, origin, pre, scheme, host, path, pre, trailer);
	}
    
    LOG_MSG("Response: %s", response);

    slen = do_send(ctx, response, rlen);
    if (slen <= 0) {
        LOG_ERR("Error sending handshake response");
    }

    return ctx;
}

#ifndef _WIN32

static void signal_handler(int sig)
{
// TODO
}

void daemonize(int keepfd) {
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

// TODO: move to websockify module ?

#ifdef _WIN32

typedef struct {
    int socket;
    ws_listener_t *settings;
    int conn_id;
} thread_params_t;

static DWORD WINAPI proxy_thread( LPVOID lpParameter )
{
    thread_params_t *params;
    ws_ctx_t *ctx;

    params = lpParameter;

    ctx = do_handshake(params->socket, params->settings);
    if (ctx == NULL) {
        LOG_MSG("No connection after handshake");
        return 0;
    }

    params->settings->handler(ctx, ctx->settings);
    // TODO? error reporting ?

    socket_free(ctx);
    closesocket(params->socket);

	return 0;
}

#endif

//--- Public functions --------------------------------------------------------

int ws_initialize()
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

/* resolve host with also IP address parsing 
 */ 
int ws_resolve_host(struct in_addr *sin_addr, const char *hostname) 
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

ws_byte_t *ws_alloc_block(ws_ctx_t *ctx, size_t size)
{
    ws_byte_t *ptr;

    switch (ctx->protocol) {
    case base64: 
#ifdef _DEBUG
        size += sizeof(unsigned short);
#endif
        ptr = malloc(size);
#ifdef _DEBUG
        size += sizeof(unsigned short);
        *((unsigned short*)ptr) = BLOCKSTART_MAGIC;
        ptr += sizeof(unsigned short);
#endif
        return ptr;
    //case binary:
    //    ...
    //    break;
    default: 
        LOG_ERR("%s: unsupported protocol", __FUNCTION__); 
        return NULL;
    }
}

void ws_free_block(ws_ctx_t *ctx, ws_byte_t *block)
{
    switch (ctx->protocol) {
    case base64:
#ifdef _DEBUG
        block -= sizeof(unsigned short);
#endif
        free(block);
        break;
    default:
        LOG_ERR("%s: unsupported protocol", __FUNCTION__);
    }
}

void ws_run_daemonized() 
{
	daemonized = 1;
}

void ws_start_server(ws_listener_t *settings) 
{
    int lsock, csock, pid, clilen, sopt = 1;
    struct sockaddr_in serv_addr, cli_addr;
    int conn_id;
#ifdef _WIN32
    thread_params_t thparams;
	HANDLE hThread;
#else
    ws_ctx_t *ctx;
#endif

    ws_initialize();

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

    // TODO: remove, but make sure daemonization remains possible
    if (daemonized) {
#ifndef _WIN32
        daemonize(lsock);
#endif
    }

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
            ctx = do_handshake(csock, settings);
            if (ctx == NULL) {
                LOG_MSG("No connection after handshake");
                break;   // Child process exits
            }

            settings->handler(ctx, ctx->settings);
            /* if (pipe_error) { // TODO
                LOG_ERR("Closing due to SIGPIPE");
            } */
            break;   // Child process exits
        } else {         // parent process
            conn_id += 1;
        }
#endif
    }
#ifndef _WIN32
    if (pid == 0) {
        if (ctx) {
            socket_free(ctx);
        } else {
            shutdown(csock, SHUT_RDWR);
            close(csock);
        }
        LOG_MSG("handler exit");
    } else {
		// TODO: can this ever be reached ?
        LOG_MSG("wsproxy exit");
    }
#endif
}

ssize_t ws_recv(ws_ctx_t *ctx, ws_byte_t *data, size_t len) 
{
    int err;
    void *pbuf;
    size_t blen;
    ssize_t rlen;

    assert(ctx->tsfrag == NULL); // we must not be sending
    CHECK_BLOCK(ctx->protocol, data);

    // Get pointer to and length of reception buffer (protocol-dependent)
    switch (ctx->protocol) {
    case base64:
        err = check_b64_buffer(ctx, len);
        if (err < 0) return err;
        pbuf = ctx->encbuf;
        blen = ctx->encsize;
        break;
    default:
        return WSE_UNSUPPORTED_PROTOCOL;
    }

    // Get the data, either through SSL or from a regular socket
    rlen = do_recv(ctx, pbuf, blen);
    if (rlen < 0) {
        LOG_ERR("WebSocket receiving error");
        return WSE_RECEIVING_ERROR;
    }
    else if (rlen == 0) {
        LOG_MSG("Connection abandoned by client");
        return WSE_ABANDONED;
    }

    // Decode / unframe the received data if necessary
    switch (ctx->protocol) {
    case base64:
        rlen = decode_b64(pbuf, rlen, data, len);
        if (rlen < 0) return rlen;
        return rlen;
    default:
        return WSE_UNSUPPORTED_PROTOCOL;
    }
}

int ws_send(ws_ctx_t *ctx, ws_byte_t *data, size_t len)
{
    int err;

    assert(ctx->tsfrag == NULL); // must not have any fragments left to send
    CHECK_BLOCK(ctx->protocol, data);

    err = prep_block(ctx, data, len); 
    if (err) return err;

    return ws_cont(ctx);
}

int ws_cont(ws_ctx_t *ctx)
{
    ssize_t sent;

    // Send, either through the SSL layer or directly through the socket
    sent = do_send(ctx, ctx->tsfrag, ctx->tslen);
    if (sent < 0) return WSE_TRANSMITTING_ERROR;

    // All done ?
    if (sent == ctx->tslen) {
        // No more remaining fragment
        ctx->tsfrag = NULL;
        ctx->tslen = 0;
        return 1;
    }
    else // no, data remaining to be sent
    {
        // Update the fragment pointer and length
        ctx->tsfrag += (size_t) sent;
        ctx->tslen -= (size_t) sent;
        return 0;
    }
}

int ws_getsockfd(ws_ctx_t *ctx)
{
    return ctx->sockfd;
}
