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
//#include <base64.h>
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

#ifdef DEBUG

#define BLOCKSTART_MAGIC            (0xabcd)


#define CHECK_BLOCK(subprot, block) { \
        switch (subprot) { \
            case WSKSP_BASE64: \
            case WSKSP_NONE: \
                assert(*((unsigned short*)(block-1-sizeof(unsigned short))) == BLOCKSTART_MAGIC); \
                break; \
            default: \
                assert(0); \
        } \
    }
#else
#define BLOCK_MAGIC_SIZE    0
#define CHECK_BLOCK(prot, block)
#endif

// Data types, structs --------------------------------------------------------

/* Struct holding the data required to service a WebSocket connection.
 */
struct _wsk_context {
    wsv_ctx_t         *wsvctx;      // web servicing context
    wsk_subprotocol_t subprot;
    wsk_byte_t        *encbuf;      // buffer used for encoding/decoding  TODO: allocate/free
    size_t            encsize;      // number of bytes in encoding buffer
    wsk_byte_t        *tsfrag;      // "to send" fragment pointer
    size_t            tslen;        // length left to send
    //char              *location;
};

struct _wsk_service_struct {
    wsk_handler_t handler;                  // Session handler
    void *userdata;                         // User data for the handler
};

// Global constants -----------------------------------------------------------

#ifdef NOT_DEFINED

static const char server_handshake_hixie[] = "\
HTTP/1.1 101 Web Socket Protocol Handshake\r\n\
Upgrade: WebSocket\r\n\
Connection: Upgrade\r\n\
%sWebSocket-Origin: %s\r\n\
%sWebSocket-Location: %s://%s%s\r\n\
%sWebSocket-Protocol: %s\r\n\
\r\n%s";

#endif

static const char server_handshake_hybi[] = "\
HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: %s\r\n\
Sec-WebSocket-Protocol: %s\r\n\
\r\n\
";

const char policy_response[] = 
    "<cross-domain-policy>"
        "<allow-access-from domain=\"*\" to-ports=\"*\" />"
    "</cross-domain-policy>\n";

// TODO: replace with real logging mechanism
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

static size_t 
b64_buffer_size(size_t block_size)
{
    // Delimiters (00 and ff), 4/3 ratio, and rounding up to 4-byte groups
    return 1 + 4 * ((block_size*4 / 3 + 3) / 4) + 1;
}

/* Calculate the worst-case quantity of payload data that can be carried by a
   base64-encoded buffer of the specified size (reverse of b64_buffer_size()).
 */
static size_t 
b64_data_size(size_t buffer_size)
{
    return 3 * (buffer_size - 3 - 1 - 1) / 4;
}

/* May return an error code (inverted).
 */
static int 
encode_b64(u_char const *src, size_t srclength, u_char *target, size_t targsize) 
{
    int sz = 0, len = 0;
    target[sz++] = '\x00';
    len = b64_ntop(src, srclength, (char*)(target+sz), targsize-sz);
    if (len < 0) {
        LOG_ERR("Base64 encoding error");
        return len;
    }
    sz += len;
    target[sz++] = '\xff';
    return sz;
}

/* May return an error code (inverted).
 * TODO: framing should be handled separately from decoding
 */
static ssize_t 
decode_b64(char *src, size_t srclength, u_char *target, size_t targsize) 
{
    char *start, *end;
    int len, framecount = 0, retlen = 0;
    // Orderly "close" frame ?
    if (src[0] == '\xff' && src[srclength-1] == '\x00') {
        return 0;
    }
    else if ((src[0] != '\x00') || (src[srclength-1] != '\xff')) {
        LOG_ERR("WebSocket framing error");
        return -WSKE_FRAMING_ERROR;
    }
    start = src+1; // Skip '\x00' start
    do {
        /* We may have more than one frame */
        end = memchr(start, '\xff', srclength);
        *end = '\x00';
        len = b64_pton(start, target+retlen, targsize-retlen);
        if (len < 0) {
            LOG_ERR("Base64 decoding error");
            return -WSKE_DECODING_ERROR;
        }
        retlen += len;
        start = end + 2; // Skip '\xff' end and '\x00' start 
        framecount++;
    } while (end < (src+srclength-1));
    if (framecount > 1) {
        LOG_MSG("%d", framecount);
    }
    return retlen;
}

/* Ensures that the base64 encoding buffer is big enough to hold an encoded 
   data block of the specified size, and reallocate a big enough one if
   that is not the case.
   Returns 0 if successful, or a (positive) error code.
 */
/* TODO: provide some rounding up and padding so it won't reallocate too often.
 */
static int 
check_b64_buffer(wsk_ctx_t *ctx, size_t blocklen)
{
    size_t bsize;

    bsize = b64_buffer_size(blocklen);
    if (ctx->encsize < bsize) {
        free(ctx->encbuf);
        ctx->encbuf = malloc(bsize);
        if (ctx->encbuf == NULL) 
            return WSKE_OUT_OF_MEMORY;
        ctx->encsize = bsize;
    }

    return 0;
}

/* Prepares a data block for sending. What this means exactly depends on the
   protocol; for base64, it involves the base64 encoding proper, plus the 
   framing (delimiting between 00 and ff bytes). For None (UTF-8) and binary 
   (the latter is not implemented yet), it might mean enclosing the block in 
   framing bytes.
   Returns 0 if successful, otherwise a (positive) error code.
   
   Note: there is no guarantee that this function will leave the passed data
    block untouched. With the binary protocol for instance (not implemented
    yet), framing can be done without having to copy the data, provided that 
    the data block was allocated with ws_alloc_block(). 
 */
static int 
prep_block(wsk_ctx_t *ctx, wsk_byte_t *block, size_t len)
{
    int err;
    int size;

    CHECK_BLOCK(ctx->subprot, block);

    switch(ctx->subprot) {
    case WSKSP_BASE64:
        err = check_b64_buffer(ctx, len);
        if (err < 0) return err;
        size = encode_b64(block, len, ctx->encbuf, ctx->encsize);
        if (size < 0 || (size_t) size <= len) {
            err = WSKE_ENCODING_ERROR;
            return err;
        }
        ctx->tsfrag = ctx->encbuf;
        ctx->tslen = (size_t) size;
        break;
    case WSKSP_NONE:
        block[-1]  = '\x00';
        block[len] = '\xff';
        ctx->tsfrag = block -1;
        ctx->tslen  = len + 2;
        break;
    default:
        return WSKE_UNSUPPORTED_PROTOCOL;
    };

    return 0;
}

static void 
free_context(wsk_ctx_t *ctx) 
{
    //if (ctx->location) free(ctx->location);
    if (ctx->encbuf) free(ctx->encbuf);
    free(ctx);
}

static wsk_ctx_t *
create_context(wsv_ctx_t *wsvctx)
{
    wsk_ctx_t *ctx;

    ctx = malloc(sizeof(struct _wsk_context));
    if (ctx == NULL) return NULL;
    
    ctx->wsvctx = wsvctx;
    ctx->encbuf = NULL;
    ctx->encsize = 0;
    ctx->tsfrag = NULL;
    //ctx->location = NULL;
    
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
gen_hybi_response(wsk_ctx_t *ctx, const char *header, const char *subprot, int use_ssl, char *response)
{
    char key[64+1], keynguid[1024+36+1], accept[30+1];
    unsigned char hash[20+1];
    
    LOG_DBG("Generating HyBi response");
    
    if (!wsv_extract_header_field(header, "Sec-WebSocket-Key", key)) {
        LOG_ERR("Handshake (HyBi/IETF) lacks a \"Sec-WebSocket-Key\" field");
        return 0; }

    strcpy(keynguid, key);
    strcat(keynguid, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    
    SHA1((const unsigned char*)keynguid, strlen(keynguid), hash);
    
    b64_ntop(hash, 20, accept, sizeof(accept));
        
    return sprintf(response, server_handshake_hybi, accept, subprot);
}

static int
gen_hixie_response(wsk_ctx_t *ctx, const char *header, const char *subprot, int use_ssl, char *response)
{
    const char *pre;
    char origin[64+1], host[256+1], location[256+1], trailer[17];
    char *p;
    
    LOG_DBG("Generating Hixie response");
    
    if (wsv_extract_payload(header, NULL)) {
        gen_md5(header, trailer);
        pre = "Sec-";
        LOG_MSG("using protocol version 76");
    } else {
        trailer[0] = '\0';
        pre = "";
        LOG_MSG("using protocol version 75");
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
    p += sprintf(p, "Upgrade: WebSocket\r\n");
    p += sprintf(p, "Connection: Upgrade\r\n");
    p += sprintf(p, "%sWebSocket-Origin: %s\r\n", pre, origin);
    p += sprintf(p, "%sWebSocket-Location: %s://%s%s\r\n", pre, use_ssl ? "wss" : "ws", host, location);
    if (ctx->subprot != WSKSP_NONE) 
        p += sprintf(p, "%sWebSocket-Protocol: %s\r\n", pre, subprot);
    p += sprintf(p, "\r\n%s", trailer);
    
    return p - response;
}
    
static wsk_ctx_t *
do_handshake(wsv_ctx_t *wsvctx, int use_ssl) 
{
    char header[4096], *response;
    ssize_t len;
    char buffer[64+1], subprot[32+1];
    wsk_ctx_t *ctx;
    size_t rlen, slen;

    ctx = NULL;
    response = NULL;
    
    // Get the header data
    len = wsv_peek(wsvctx, header, sizeof(header)-1);
    header[len] = 0;
    LOG_DBG("%s: peeked %d bytes HTTP request", __FUNCTION__, len);
    LOG_DBG("-- Handshake: ---:\n%s", header);
    LOG_DBG("-----------------");

    if (strlen(header) == 0) {
        LOG_ERR("Empty handshake received, not upgrading");
        goto fail;
    } else if (memcmp(header, "<policy-file-request/>", 22) == 0) {
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

    // Now consume the header
    if (wsv_recv(wsvctx, header, len) != len) {
        LOG_ERR("Error consuming the (previously peeked) header");
        goto fail;
    }
    
    // Create the context
    ctx = create_context(wsvctx);
    
    // Subprotocol
    ctx->subprot = get_subprotocol(header, subprot);
    
    // Get a buffer
    response = (char*) wsk_alloc_block(ctx, 4096);
    if (!response) {
        LOG_ERR("Failed to allocate handshake response buffer");
        goto fail; }
        
        
    // Detect protocol version and generate appropriate response
    if (wsv_extract_header_field(header, "Sec-WebSocket-Version", buffer)) {
        rlen = gen_hybi_response(ctx, header, subprot, use_ssl, response);
        if ( rlen < 0) {
            LOG_ERR("Failed to generate HyBi/IETF handshake response");
            goto fail; }
    }
    else if (wsv_extract_header_field(header, "Sec-WebSocket-Key1", buffer)) {
        rlen = gen_hixie_response(ctx, header, subprot, use_ssl, response);
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
    if (response) wsk_free_block(ctx, (wsk_byte_t*) response);
    if (ctx) free_context(ctx);
    return NULL;
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
    ctx = do_handshake(wsvctx, 0);
    if (!ctx) {
        LOG_ERR("WebSocket handshake procedure failed");
        return -1;
    }
    LOG_MSG("Successfully upgraded the HTTP connection to WebSocket");

    // Extract information from the header
    wsv_extract_url(header, location);
    LOG_DBG("location=\"%s\"", location);
    wsv_extract_header_field(header, "Sec-WebSocket-Protocol", subprot);
    LOG_DBG("Subprotocol = \"%s\"", subprot[0] != '\0' ? subprot : "<none>");

    // Call the handler
    assert(userdata);
    svc = userdata;
    err = svc->handler(ctx, location, svc->userdata);
    if (err != 0) LOG_ERR("WebSocket session handler returned a non-zero exit code");
    
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

#ifdef NOT_DEFINED
// TODO: still needed ?
const char *
wsk_get_location(wsk_ctx_t *ctx)
{
    return ctx->location;
}
#endif

wsk_byte_t *
wsk_alloc_block(wsk_ctx_t *ctx, size_t size)
{
    wsk_byte_t *ptr;
    
    switch (ctx->subprot) {
    case WSKSP_BASE64: 
    case WSKSP_NONE:
        #ifdef DEBUG
        ptr = malloc(size + 2 + sizeof(unsigned short));
        *((unsigned short*)ptr) = BLOCKSTART_MAGIC;
        ptr += sizeof(unsigned short);
        #else
        ptr = malloc(size);
        #endif
        ptr += 1; // skip the start-of-frame delimiter byte
        return ptr;
    default: 
        LOG_ERR("%s: unsupported protocol", __FUNCTION__); 
        return NULL;
    }
}

void 
wsk_free_block(wsk_ctx_t *ctx, wsk_byte_t *block)
{
    CHECK_BLOCK(ctx->subprot, block);
    
    switch (ctx->subprot) {
    case WSKSP_BASE64:
    case WSKSP_NONE:
        #ifdef DEBUG
        block -= sizeof(unsigned short);
        #endif
        block -= 1; // move back to include the start-of-frame delimiter byte
        free(block);
        break;
    default:
        LOG_ERR("%s: unsupported protocol", __FUNCTION__);
    }
}

ssize_t 
wsk_recv(wsk_ctx_t *ctx, wsk_byte_t *data, size_t len) 
{
    int err;
    void *pbuf;
    size_t blen;
    ssize_t rlen;

    assert(ctx->tsfrag == NULL); // we must not be sending
    CHECK_BLOCK(ctx->subprot, data);

    // Get pointer to and length of reception buffer (protocol-dependent)
    switch (ctx->subprot) {
    case WSKSP_BASE64:
        err = check_b64_buffer(ctx, len);
        if (err < 0) return err;
        pbuf = ctx->encbuf;
        blen = ctx->encsize;
        break;
    case WSKSP_NONE:
        pbuf = ctx->encbuf -1;
        blen = ctx->encsize + 1;
        break;
    default:
        return -WSKE_UNSUPPORTED_PROTOCOL;
    }

    // Get the data, either through SSL or from a regular socket
    rlen = wsv_recv(ctx->wsvctx, pbuf, blen);
    if (rlen < 0) {
        LOG_ERR("WebSocket receiving error");
        return -WSKE_RECEIVING_ERROR;
    }
    else if (rlen == 0) {
        LOG_MSG("Connection abandoned by client");
        return -WSKE_ABANDONED;
    }

    // Decode / unframe the received data if necessary
    switch (ctx->subprot) {
    case WSKSP_BASE64:
        rlen = decode_b64(pbuf, rlen, data, len);
        if (rlen < 0) return rlen;
        return rlen;
    case WSKSP_NONE:
        return rlen -2;
    default:
        return -WSKE_UNSUPPORTED_PROTOCOL;
    }
}

int 
wsk_send(wsk_ctx_t *ctx, wsk_byte_t *data, size_t len)
{
    int err;

    assert(ctx->tsfrag == NULL); // must not have any fragments left to send
    CHECK_BLOCK(ctx->subprot, data);

    err = prep_block(ctx, data, len); 
    if (err) return err;

    return wsk_cont(ctx);
}

int 
wsk_cont(wsk_ctx_t *ctx)
{
    ssize_t sent;

    // Send, either through the SSL layer or directly through the socket
    sent = wsv_send(ctx->wsvctx, ctx->tsfrag, ctx->tslen);
    if (sent < 0) return -WSKE_TRANSMITTING_ERROR;

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
wsk_getsockfd(wsk_ctx_t *ctx)
{
    return wsv_getsockfd(ctx->wsvctx);
}
