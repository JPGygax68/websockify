/*
 * WebSocket lib with support for "wss://" encryption.
 * Copyright 2010 Joel Martin
 * Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
 *
 * You can make a cert/key with openssl using:
 * openssl req -new -x509 -days 365 -nodes -out self.pem -keyout self.pem
 * as taken from http://docs.python.org/dev/library/ssl.html#certificates
 *
 * Forked and modified 2011 by Hans-Peter Gygax
 */

//#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <assert.h>
#include <sys/types.h> 
#include <sys/stat.h>
#ifdef _WIN32
#include <Winsock2.h>
#include <WS2tcpip.h>
//#include <osisock.h>
#include <base64.h>
#else
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <resolv.h>        // base64 encode/decode
#include <signal.h>        // daemonizing
#include <fcntl.h>        // daemonizing
#endif
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sptl/sptl.h>
#include "sptl_webserver.h"
#include "sptl_hybi.h"
#include "sptl_hixie.h"
#include "sptl_base64.h"
#include "sha1.h"
#include "websocket.h"

/* Windows/Visual Studio quirks */

#ifdef _WIN32

#pragma warning(disable:4996)
#define close _close
#define strdup _strdup
#define usleep Sleep

#endif

/* External declarations not found in headers */

extern void *md5_buffer (const char *buffer, size_t len, void *resblock);

/* Adaptation to platform specifics */

#ifndef _WIN32
#define closesocket close
#endif

/* Debugging utilities */

// TODO: differentiate between blocks for reading and for writing
#ifdef DEBUG
#define BLOCKSTART_MAGIC            (0xabcd)
#define CHECK_BLOCK(ctx, block)        { \
    size_t hdlen, trlen; \
    (void) framing_sizes(ctx, &hdlen, &trlen); \
    assert(*(unsigned short*)((block)-(hdlen)-sizeof(unsigned short)) == BLOCKSTART_MAGIC); \
}
#else
#define CHECK_BLOCK(ctx, block)
#endif

// Data types, structs --------------------------------------------------------

typedef unsigned long long u_longlong;    // they just couldn't accept a 64kB limit on packet sizes?
    
/* Struct holding the data required to service a WebSocket connection.
 */
// TODO: separate buffers for sending and receiving
struct _wsk_context {
    wsv_ctx_t            *wsvctx;        // web servicing context
    wsk_protfamily_t    protfamily;        // websocket protocol family
    unsigned            protver;        // protocol version
    wsk_subprotocol_t    subprot;
    wsk_byte_t            *outbuf;        // buffer for outgoing fragments
    size_t                outbsize;        // size
    wsk_byte_t            *tsfrag;
    size_t                tslen;
    // Transmission Stack
    SPTL_Stack          *stack;
};

struct _wsk_service_struct {
    wsk_handler_t handler;                // Session handler
    void *userdata;                     // User data for the handler
};

// Global constants -----------------------------------------------------------

const char policy_response[] = 
    "<cross-domain-policy>"
        "<allow-access-from domain=\"*\" to-ports=\"*\" />"
    "</cross-domain-policy>\n";

// TODO: version that takes connection ID
// TODO: use a generalized logging system (piggy-back onto webserver ?)

// Logging/tracing -----------------------------------------------------------
    
#define __LOG(stream, ...) \
{ \
    fprintf(stream, __VA_ARGS__); \
    fprintf(stream, "\n" ); \
}

#define LOG_MSG(...) __LOG(stdout, __VA_ARGS__);
#define LOG_ERR(...) __LOG(stderr, __VA_ARGS__);
#define LOG_DBG LOG_MSG

// Private routines -----------------------------------------------------------

static u_longlong
htonll(u_longlong x)
{
#if BYTE_ORDER == LITTLE_ENDIAN
    u_char *s = (u_char *)&x;
    return (u_longlong) 
        ( (u_longlong)s[0] << 56 | (u_longlong)s[1] << 48 | (u_longlong)s[2] << 40 | (u_longlong)s[3] << 32 
        | (u_longlong)s[4] << 24 | (u_longlong)s[5] << 16 | (u_longlong)s[6] <<  8 | (u_longlong)s[7] <<  0 );
#else
    return x;
#endif
}

/* Calculate the size needed for a buffer to base64-encode the specified
 * payload size.
 */
static size_t 
b64_buffer_size(size_t block_size)
{
    // 4/3 ratio and rounding up to 4-byte groups
    return 1 + 4 * ((block_size*4 / 3 + 3) / 4) + 1;
}

/* Calculate the worst-case quantity of payload data that can be carried by a
   base64-encoded buffer of the specified size (reverse of b64_buffer_size()).
 */
static size_t 
b64_data_size(size_t buffer_size)
{
    return 3 * (buffer_size - 3) / 4;
}

/* Return the protocol-dependent sizes of the frame header and trailer.
 */
static size_t
framing_sizes(wsk_ctx_t *ctx, size_t *header, size_t *trailer)
{
    switch (ctx->protfamily) {
    case WSKPV_HIXIE:    
        if (header ) *header  = 1;
        if (trailer) *trailer = 1;
        return 2;
    case WSKPV_HYBI:    
        if (header ) *header  = 10;
        if (trailer) *trailer = 0;
        return 10;
    default: 
        assert(0);
    }
    return 0;
}

/* Allocate a buffer, including extra space for framing if the protocol
 * version requires it, and expanding to base64 if required by the 
 * subprotocol.
 */
static wsk_byte_t *
allocate_buffer(wsk_ctx_t *ctx, size_t minSize)
{
    if (ctx->subprot == WSKSP_BASE64) {
        minSize = b64_buffer_size(minSize);
    }

    minSize += framing_sizes(ctx, NULL, NULL);

    return (wsk_byte_t*) malloc(minSize);
}

// TODO: we need our own base64 encoding/decoding

/* May return an error code (inverted).
 */
static ssize_t 
decode_b64(char *src, size_t srclength, u_char *target, size_t targsize) 
{
    char *start, *end;
    int len, framecount = 0, retlen = 0;
    start = src;
    do {
        /* We may have more than one frame */
        end = (char*) memchr(start, '\xff', srclength);
        *end = '\x00';
        len = b64_pton(start, target+retlen, targsize-retlen);
        if (len < 0) {
            LOG_ERR("Base64 decoding error");
            return WSKER_DECODING; }
        retlen += len;
        start = end + 2; // Skip '\xff' end and '\x00' start 
        framecount++;
    } while (end < (src+srclength-1));
    if (framecount > 1) {
        LOG_MSG("%d", framecount);
    }
    return retlen;
}

/* Prepares a data block for sending. What this means exactly depends on the
   protocol version and subprotocol used.
   Returns 0 if successful, otherwise a (positive) error code.
 */
static int 
prep_block(wsk_ctx_t *ctx, wsk_byte_t *block, size_t len, unsigned short flags)
{
    wsk_byte_t *buf;
    size_t size, frmlen, hdlen, trlen;
    wsk_byte_t opcode;
    ssize_t encsize;

    LOG_DBG("%s: block len = %u", __FUNCTION__, len);
    
    assert(ctx->protfamily != WSKPV_UNDEFINED);

    // Calculations
    frmlen = framing_sizes(ctx, &hdlen, &trlen);

    // Encode (if necessary)
    if (ctx->subprot == WSKSP_BASE64) {
        // Make sure fragment buffer is big enough
        size = b64_buffer_size(len);
        if (ctx->outbuf == NULL || ctx->outbsize < (size+frmlen)) {
            if (ctx->outbuf) free(ctx->outbuf);
            ctx->outbuf = (wsk_byte_t*) malloc(size+frmlen);
            ctx->outbsize = size + frmlen;
        }
        // Encode
        buf = ctx->outbuf + hdlen;
        if (len > 0) 
            encsize = b64_ntop(block, len, (char*) buf, ctx->outbsize - frmlen);
        else
            encsize = 0;
        size = (size_t) encsize;
    }
    else // no encoding, so we insert framing directly into the block
    {
        buf  = block;
        size = len;
    }
    // Framing
    if (ctx->protfamily == WSKPV_HIXIE) {
        if (block == NULL || len == 0) {
            buf[-1]   = '\xff';
            buf[ 0]   = '\x00';
        }
        else {
            buf[-1]   = '\x00';
            buf[size] = '\xff';
        }
        ctx->tsfrag = buf  - 1;
        ctx->tslen  = size + 2;
    }
    else if (ctx->protfamily == WSKPV_HYBI) {
        // Determine op-code
        if (block == NULL || len == 0) {
            opcode = 0x8;
            // TODO: this is a hack, better closing frames are needed
            *((unsigned short*)buf) = htons(1000); // orderly close
            size = 2;
        }
        else
            opcode = 0x1;
        // Create appropriate header (depends on buffer size)
        if (size <= 125) {
            buf[-2] = 0x80 | opcode; // FIN + op-code
            buf[-1] = (wsk_byte_t) size;
            ctx->tsfrag = buf  - 2;
            ctx->tslen  = size + 2;
        }
        else if (size < 65536) {
            buf[-4] = 0x80 | opcode;
            buf[-3] = 126;
            *((u_short*)&buf[-2]) = htons(size);
            ctx->tsfrag = buf  - 4;
            ctx->tslen  = size + 4;
        }
        else {
            buf[-10] = 0x80 | opcode;
            buf[ -9] = 127;
            (*(u_long*)&buf[-8]) = 0; // 4 most significant bytes: not used
            (*(u_long*)&buf[-4]) = htonl(size);
            ctx->tsfrag = buf  - 10;
            ctx->tslen  = size + 10;
        }
    }
    else
        assert(0);

    return 0; // ok
}

static void 
free_context(wsk_ctx_t *ctx) 
{
    if (ctx->outbuf) free(ctx->outbuf);
    if (ctx->stack) { sptl_dispose_stack(ctx->stack); ctx->stack = NULL; }
    free(ctx);
}

static wsk_ctx_t *
create_context(wsv_ctx_t *wsvctx)
{
    wsk_ctx_t *ctx;

    ctx = (wsk_ctx_t*) malloc(sizeof(struct _wsk_context));
    if (ctx == NULL) return NULL;
    
    ctx->wsvctx = wsvctx;
    ctx->outbuf = NULL;
    ctx->outbsize = 0;
    ctx->tsfrag = NULL;
    ctx->tslen = 0;
    // Stack
    ctx->stack = NULL;
    
    return ctx;
}

/* Generate the 16-byte MD5 code from the keys provided in the handshake
 * header.
 */
static int 
gen_md5(const char *handshake, char *target)
{
    unsigned int i, spaces1 = 0, spaces2 = 0;
    unsigned long num1 = 0, num2 = 0;
    unsigned char buf[17];
    char valbuf[128];
    const char *value;

    value = wsv_extract_header_field(handshake, "Sec-WebSocket-Key1", valbuf);
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

    value = wsv_extract_header_field(handshake, "Sec-WebSocket-Key2", valbuf);
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

    if (!wsv_extract_payload(handshake, valbuf)) return 0;
    memcpy(buf+8, value, 8);
    buf[16] = '\0';

    md5_buffer((char*)buf, 16, target);
    target[16] = '\0';

    return 1;
}

wsk_subprotocol_t
get_subprotocol(const char *header, char *buffer)
{
    if (wsv_extract_header_field(header, "Sec-WebSocket-Protocol", buffer)) {
        if (strcmp(buffer, "base64") == 0) 
            return WSKSP_BASE64;
        else
            return WSKSP_UNKNOWN;
    }
    else {
        LOG_DBG("No subprotocol");
        buffer[0] = '\0';
        return WSKSP_NONE;
    }
}

static int
gen_hybi_response(wsk_ctx_t *ctx, const char *header, const char *protocol,
    int use_ssl, char *response)
{
    char key[64+1], keynguid[1024+36+1], accept[30+1];
    SHA1Context sha;
    unsigned char hash[20+1];
    const char *subprot;
    char *p;
    unsigned long word;
    unsigned i;
    
    LOG_DBG("Generating HyBi response");
    
    if (!wsv_extract_header_field(header, "Sec-WebSocket-Key", key)) {
        LOG_ERR("Handshake (HyBi/IETF) lacks a \"Sec-WebSocket-Key\" field");
        return 0; }
    
    // Calculate SHA-1 digest of key + GUID concatenation
    strcpy(keynguid, key);
    strcat(keynguid, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    SHA1Reset(&sha);
    SHA1Input(&sha, (unsigned char*)keynguid, strlen(keynguid));
    SHA1Result(&sha);
    
    // Base64-encode SHA-1 hash
    for (i = 0; i < 5; i++) {
        word = htonl(sha.Message_Digest[i]);
        memcpy(hash+4*i, &word, sizeof(unsigned long));
    }
    if (b64_ntop(hash, 20, accept, 30) < 0) {
        LOG_ERR("Buffer too small trying to Base64-encode HyBi response hash");
        return -1; }

    // Assemble response
    p = response;
    p += sprintf(p, "HTTP/1.1 101 Switching Protocols\r\n");
    p += sprintf(p, "Upgrade: %s\r\n", protocol);
    p += sprintf(p, "Connection: Upgrade\r\n");
    p += sprintf(p, "Sec-WebSocket-Accept: %s\r\n", accept);
    if (ctx->subprot != WSKSP_NONE && ctx->subprot != WSKSP_BINARY) {
        switch (ctx->subprot) {
        case WSKSP_BASE64: subprot = "base64"; break;
        default: subprot = "binary";
        }
        p += sprintf(p, "Sec-WebSocket-Protocol: %s\r\n", subprot);
    }
    p += sprintf(p, "\r\n");

    return (p - response);
}

static int
gen_hixie_response(wsk_ctx_t *ctx, const char *header, const char *protocol,
                   const char *subprot, int use_ssl, char *response)
{
    const char *pre;
    char origin[64+1], host[256+1], location[256+1], trailer[17];
    char *p;
    
    LOG_DBG("Generating Hixie response");
    
    if (wsv_extract_payload(header, NULL)) {
        gen_md5(header, trailer);
        pre = "Sec-";
        LOG_MSG("using Hixie protocol version 76");
    } else {
        trailer[0] = '\0';
        pre = "";
        LOG_MSG("using Hixie protocol version 75");
    }
    if (!wsv_extract_header_field(header, "Origin", origin)) {
        LOG_ERR("Handshake (Hixie) lacks an \"Origin\" field"); 
        return 0; }
    if (!wsv_extract_header_field(header, "Host", host)) {
        LOG_ERR("Handshake (Hixie) lacks a \"Host\" field"); 
        return 0; }
    if (!wsv_extract_url(header, location)) {
        LOG_ERR("Failed to extract the URI, aborting");
        return 0; }
        
    p = response;
    p += sprintf(p, "HTTP/1.1 101 Web Socket Protocol Handshake\r\n");
    p += sprintf(p, "Upgrade: %s\r\n", protocol);
    p += sprintf(p, "Connection: Upgrade\r\n");
    p += sprintf(p, "%sWebSocket-Origin: %s\r\n", pre, origin);
    p += sprintf(p, "%sWebSocket-Location: %s://%s%s\r\n", pre, use_ssl ? "wss" : "ws", host, location);
    if (ctx->subprot != WSKSP_NONE) 
        p += sprintf(p, "%sWebSocket-Protocol: %s\r\n", pre, subprot);
    p += sprintf(p, "\r\n%s", trailer);
    
    return p - response;
}

static wsk_ctx_t *
do_handshake(wsv_ctx_t *wsvctx, const char *header, int use_ssl) 
{
    char response[4096];
    char buffer[64+1], protocol[64+1], subprot[32+1];
    wsk_ctx_t *ctx;
    size_t rlen, slen;

    ctx = NULL;
    
    if (strlen(header) == 0) {
        LOG_ERR("Empty handshake received, not upgrading");
        goto fail;
    } 
#ifdef NOT_DEFINED // TODO: re-implement at higher level ?
    else if (memcmp(header, "<policy-file-request/>", 22) == 0) {
        LOG_DBG("Sending flash policy response");
        wsv_send(wsvctx, policy_response, sizeof(policy_response));
        LOG_DBG("Waiting for the handshake (after the flash policy request)");
        len = wsv_recv(wsvctx, header, sizeof(header)-1); // TODO: test - will it wait for the response ?
        if (len < 0) {
            LOG_ERR("Error waiting for the handshake (after the flash policy request)");
            goto fail;
        }
        header[len] = '\0';
        LOG_DBG("Handshake after flash policy request:\n%s", header);
    }
#endif

    // Create the context
    ctx = create_context(wsvctx);

    // Protocol and subprotocol
    wsv_extract_header_field(header, "Upgrade", protocol);
    ctx->subprot = get_subprotocol(header, subprot);
    
    // Detect and store protocol version, generate appropriate response
    if (wsv_extract_header_field(header, "Sec-WebSocket-Version", buffer)) {
        // Check protocol version number
        ctx->protver = atoi(buffer);
        if (ctx->protver != 7) {
            LOG_ERR("Unsupported HyBi protocol version (%d, need 7)", ctx->protver); 
            goto fail; }
        ctx->protfamily = WSKPV_HYBI;
        // Generate the response
        rlen = gen_hybi_response(ctx, header, protocol, use_ssl, response);
        if (rlen < 0) {
            LOG_ERR("Failed to generate HyBi/IETF handshake response");
            goto fail; }
    }
    else if (wsv_extract_header_field(header, "Sec-WebSocket-Key1", buffer)) {
        ctx->protfamily = WSKPV_HIXIE;
        ctx->protver = 0;
        // Generate response
        rlen = gen_hixie_response(ctx, header, protocol, subprot, use_ssl, response);
        if ( rlen < 0) {
            LOG_ERR("Failed to generate Hixie handshake response");
            goto fail; }
    }
            
    LOG_MSG("-- Response ------:\n%s", response);
    LOG_MSG("------------------");
    
    slen = wsv_send(wsvctx, response, rlen);
    if (slen <= 0) {
        LOG_ERR("Error sending handshake response");
        goto fail;
    }

    return ctx;
    
fail:
    if (ctx) free_context(ctx);
    return NULL;
}

static int
build_stack(wsk_ctx_t *ctx)
{
    SPTL_Layer *layer;
    int err;

    assert(ctx->stack == NULL);
    err = WSKER_GENERIC;

    if ((ctx->stack = sptl_create_stack()) == NULL) {
        LOG_ERR("Out of memory trying to create SPTL stack");
        err = WSKER_OUT_OF_MEMORY; 
        goto fail; }

    if ((layer = sptlwsv_create_layer(ctx->wsvctx)) == NULL) {
        LOG_ERR("Out of memory trying to create WebServer layer for SPTL stack");
        err = WSKER_OUT_OF_MEMORY; 
        goto fail; }

    if (sptl_add_layer(ctx->stack, layer) != SPTLERR_OK) {
        LOG_ERR("Failed to add WebServer layer to SPTL stack");
        goto fail; }

    if (ctx->protfamily == WSKPV_HYBI) {
        if ((layer = sptlhybi_create_layer(ctx->protver)) == NULL) {
            LOG_ERR("Out of memory trying to create HyBi layer for SPTL stack");
            err = WSKER_OUT_OF_MEMORY; 
            goto fail; }
    }
    else if (ctx->protfamily == WSKPV_HIXIE) {
        if ((layer = sptlhixie_create_layer(ctx->protver)) == NULL) {
            LOG_ERR("Out of memory trying to create HyBi layer for SPTL stack");
            err = WSKER_OUT_OF_MEMORY; 
            goto fail; }
    }
    else {
        LOG_ERR("Unsupported/unknown protocol");
        goto fail; 
    }

    if (sptl_add_layer(ctx->stack, layer) != SPTLERR_OK) {
        LOG_ERR("Failed to add WebSocket protocol layer to SPTL stack");
        goto fail; }

    if (ctx->subprot == WSKSP_BASE64) {
        if ((layer = sptlbase64_create_layer()) == NULL) {
            LOG_ERR("Out of memory trying to create Base64 layer for SPTL stack");
            err = WSKER_OUT_OF_MEMORY; 
            goto fail; }
        if (sptl_add_layer(ctx->stack, layer) != SPTLERR_OK) {
            LOG_ERR("Failed to add Base64 layer to SPTL stack");
            goto fail; }
    }
    
    if (sptl_activate_stack(ctx->stack) != SPTLERR_OK) {
        LOG_ERR("Failed to activate the HyBi stack");
        goto fail; }

    return 0;

fail:
    if (ctx->stack) {
        sptl_dispose_stack(ctx->stack); ctx->stack = NULL;
    }
    return err;
}

static int
connection_handler(wsv_ctx_t *wsvctx, const char *header, void *userdata)
{
    wsk_ctx_t *ctx;
    char subprot[128], location[512];
    wsk_service_t *svc;
    int err;

    LOG_DBG("%s", __FUNCTION__);
    
    // Upgrade the connection
    ctx = do_handshake(wsvctx, header, 0);
    if (!ctx) {
        LOG_ERR("WebSocket handshake procedure failed");
        return -1; }
    LOG_MSG("Successfully upgraded the HTTP connection to WebSocket");

    // Extract information from the header
    wsv_extract_url(header, location);
    LOG_DBG("location=\"%s\"", location);
    wsv_extract_header_field(header, "Sec-WebSocket-Protocol", subprot);
    LOG_DBG("Subprotocol = \"%s\"", subprot[0] != '\0' ? subprot : "<none>");

    // Create the transmission stack
    if (build_stack(ctx) != 0) {
        LOG_ERR("Failed to build the SPTL stack");
        return -1; }

    // Call the handler
    assert(userdata);
    svc = userdata;
    err = svc->handler(ctx, location, svc->userdata);
    if (err != 0) LOG_ERR("WebSocket session handler returned a non-zero exit code");
    
    // Close the connection
    wsk_close(ctx);

    // TODO: free the context
    
    return 0;
}

//--- Public functions --------------------------------------------------------

wsk_service_t *
wsk_extend_webservice(wsv_settings_t *websvc, wsk_handler_t handler, void *userdata)
{
    wsk_service_t *svc;
    
    svc = malloc(sizeof(wsk_service_t));
    if (!svc) {
        LOG_ERR("Failed to allocated the WebSocket service structure");
        return NULL;
    }

    svc->handler = handler;
    svc->userdata = userdata;
    
    if (wsv_register_protocol(websvc, "WebSocket", connection_handler, svc) != 0) {
        LOG_ERR("Failed to register WebSocket protocol handler with web service");
        goto fail; }
    
    return svc;
    
fail:
    if (svc) free(svc);
    return NULL;
}

wsk_byte_t *
wsk_alloc_block(wsk_ctx_t *ctx, size_t size)
{
    wsk_byte_t *ptr;
    size_t frmlen, hdlen, trlen;

    frmlen = framing_sizes(ctx, &hdlen, &trlen);
    size += frmlen;
#ifdef DEBUG
    size += sizeof(unsigned short); // block "magic" marker
#endif

    ptr = (wsk_byte_t*) malloc(size);
#ifdef DEBUG
    *((unsigned short*)ptr) = BLOCKSTART_MAGIC;
#endif
    ptr += hdlen;
#ifdef DEBUG
    ptr += sizeof(unsigned short);
#endif

    return ptr;
}

void 
wsk_free_block(wsk_ctx_t *ctx, wsk_byte_t *block)
{
    size_t frmlen, hdlen, trlen;

    CHECK_BLOCK(ctx, block);    

    frmlen = framing_sizes(ctx, &hdlen, &trlen);
    block -= hdlen;
#ifdef DEBUG
    block -= sizeof(unsigned short);
#endif
    free(block);
}

ssize_t 
wsk_recv(wsk_ctx_t *ctx, wsk_byte_t *block, size_t len) 
{
    sptl_flags_t flags;
    int rlen;

    rlen = sptl_recv_copy(ctx->stack, block, len, &flags);
    if (rlen < 0) {
        if (rlen == SPTLERR_WAIT) 
            return WSKER_WAIT;
        else
            return WSKER_GENERIC;
    }

    return rlen;
}

int 
wsk_send(wsk_ctx_t *ctx, wsk_byte_t *data, size_t len)
{
    int err;

    CHECK_BLOCK(ctx, data);
    assert(len > 0);

    assert(ctx->tsfrag == NULL); // must not have any fragments left to send

    err = prep_block(ctx, data, len, 0);  // TODO: "partial" flag
    if (err) return err;

    return wsk_cont(ctx);
}

int 
wsk_cont(wsk_ctx_t *ctx)
{
    ssize_t sent;

    // Send, either through the SSL layer or directly through the socket
    sent = wsv_send(ctx->wsvctx, ctx->tsfrag, ctx->tslen);
    if (sent < 0) {
        LOG_ERR("%s: sending error, code: %d", __FUNCTION__, sent);
        return WSKER_TRANSMITTING; }

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

int
wsk_close(wsk_ctx_t *ctx)
{
    wsk_byte_t buffer[32]; // should be big enough for an empty packet, with any framing
    int err;
    
    LOG_DBG("%s", __FUNCTION__);
    
    assert(ctx->tsfrag == NULL); // must not have any fragments left to send

    // Prepare and send a closing packet
    err = prep_block(ctx, buffer+16, 0, 0);
    if (err) return err;
    (void) wsk_cont(ctx); // send it

    // TODO: consume any queued input

    return 0; // ok
}

int
wsk_sendall(wsk_ctx_t *ctx, wsk_byte_t *data, size_t len)
{
    int sent;
    sent = wsk_send(ctx, data, len);
    if (sent < 0) {
        LOG_ERR("%s %s: sending error", __FILE__, __FUNCTION__);
        return sent;
    }
    while (sent != 1) {
        usleep(1);
        sent = wsk_cont(ctx);
        if (sent < 0) return sent;
    }
    return 1;
}

int 
wsk_getsockfd(wsk_ctx_t *ctx)
{
    return wsv_getsockfd(ctx->wsvctx);
}
