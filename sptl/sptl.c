/* 
 * SPTL (Stackable Packet Transmission Layers) layer adapting the WebServer
 * library.
 *
 * Copyright 2011 Hans-Peter Gygax
 * Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
 */

#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>

#include "sptl_int.h"

#ifdef _WIN32
#define snprintf    sprintf_s
#endif

// Private constants ---------------------------------------------------------

static const char * const catstr[] = {
      /*SPTLLCAT_DEBUG*/   "DEBUG"
    , /*SPTLLCAT_INFO*/    "INFO"
    , /*SPTLLCAT_WARNING*/ "WARNING"
    , /*SPTLLCAT_ERROR*/   "ERROR"
};

// Data types ----------------------------------------------------------------

struct _SPTL_Stack {
    SPTL_Layer            *first;            // first layer in stack
    // TODO: move the following to "reassemble/copy" layer ?
    const sptl_byte_t     *pinblock;
    size_t                inbsize;
    size_t                inbused;
};

// Logging/tracing -----------------------------------------------------------
    
// TODO: implement as function
// TODO: make sure log messages are sent uninterrupted
#define __LOG(stream, ...) \
{ \
    fprintf(stream, __VA_ARGS__); \
    fprintf(stream, "\n" ); \
}

#define LOG_MSG(...) sptl_log(stdout, __VA_ARGS__);
#define LOG_ERR(...) __LOG(stderr, __VA_ARGS__);
#define LOG_DBG LOG_MSG

// Public routines ------------------------------------------------------------

SPTL_Stack *
sptl_create_stack()
{
    SPTL_Stack *stack;

    if ((stack = (SPTL_Stack*)malloc(sizeof(SPTL_Stack))) == NULL) {
        LOG_ERR("Out of memory trying to allocate SPTL stack control structure");
        return NULL; }

    stack->first = NULL;

    // TODO: move to "reassemble/copy" layer ?
    stack->pinblock = NULL;
    stack->inbsize = 0;
    stack->inbused = 0;

    return stack;
}

// TODO: error message if "shutdown" wasn't called ?
int
sptl_dispose_stack(SPTL_Stack *stack)
{
    SPTL_Layer *layer, *next;

    for (layer = stack->first; layer != NULL; layer = next) {
        next = layer->next;
        assert(layer->destroy != NULL);
        layer->destroy(layer);
        free(layer);
    }

    free(stack);

    return SPTLERR_OK;
}

// TODO: barf if already activated
int
sptl_add_layer(SPTL_Stack *stack, SPTL_Layer *layer)
{
    SPTL_Layer *succ;

    succ = stack->first;
    stack->first = layer;
    layer->next = succ;
    layer->stack = stack;

    return SPTLERR_OK;
}

// TODO: keep state variable ?
int
sptl_activate_stack(SPTL_Stack *stack)
{
    SPTL_Layer *layer;

    for (layer = stack->first; layer != NULL; layer = layer->next) {
        layer->activate(layer); // TODO: check for errors!
    }

    return SPTLERR_OK;
}

int 
sptl_fetch(SPTL_Stack *stack, const sptl_byte_t **pstart, size_t *plen, sptl_flags_t *flags)
{
    return sptli_fetch(stack->first, pstart, plen, flags);
}

int 
sptl_recv(SPTL_Stack *stack, sptl_byte_t *block, size_t len, sptl_flags_t *flags)
{
    size_t tlen;
    int exh;
    size_t chnksize;
    sptl_flags_t iflags;
    int err;

    tlen = 0;
    exh = 0;

    // Add data from following blocks, as necessary and available
    while (tlen < len && !exh) {
        // Need more data from lower layers ?
        if (stack->inbused >= stack->inbsize) {
            stack->inbused = 0;
            err = stack->first->fetch(stack->first, &stack->pinblock, &stack->inbsize, &iflags);
            if (err < 0) {
                if (err != SPTLERR_WAIT)
                    return err;
                exh = 1;
            }
        }
        if (!exh) {
            // Copy to output block, as much as needed or as will fit
            // TODO: set flags
            chnksize = len - tlen;
            if ((stack->inbsize - stack->inbused) < chnksize) chnksize = stack->inbsize - stack->inbused;
            memcpy(block + tlen, stack->pinblock, chnksize);
            stack->inbused += chnksize;
            tlen += chnksize;
        }
    }

    sptl_log_packet(SPTLLCAT_DEBUG, "Received and copied block of data: ", block, tlen);

    return tlen == 0 ? SPTLERR_WAIT : tlen;
}

int
sptl_log(sptl_logcat_t cat, const char *msg)
{
    static char buf[4096+2+1];
    unsigned offs;
    const char *p;
    char *q;

    offs = 0;
    offs += snprintf(buf+offs, 4096-offs, "[%-7.7s] ", catstr[cat]);
    for (p = msg, q = buf+offs; *p && q < (buf+4096); p++, q++)
        *q = *p;
    *q++ = '\n';
    *q = '\0';

    fputs(buf, stderr); // TODO: hooks ?

    return SPTLERR_OK;
}

int
sptl_log_format(sptl_logcat_t cat, const char *format, ...)
{
    static char buf[4096+1];
    unsigned offs;
    va_list al;
    
    va_start(al, format);

    offs = 0;
    offs += vsnprintf(buf+offs, 4096-offs, format, al);
    offs +=  snprintf(buf+offs, 4096-offs, "\n");

    va_end(al);

    return sptl_log(cat, buf);
}

// TODO: sptl_shutdown_stack()

int
sptl_log_packet(sptl_logcat_t cat, const char *header, const sptl_byte_t *pbuf, size_t blen)
{
    char outbuf[2048+1];
    unsigned offs;
    unsigned i, j;
    char c;

    offs = 0;
    offs += snprintf(outbuf+offs, 2048-offs, "%s\n", header);
    for (i = 0; offs < (2048-6-16*3-1-16) && i < blen; i += 16) {
        offs += snprintf(outbuf+offs, 2048-offs, "%4.4x: ", i);
        for (j = 0; j < 16; j ++) {
            if ((i + j) < blen)
                offs += snprintf(outbuf+offs, 2048-offs, "%2.2x ", ((unsigned char*)pbuf)[i+j]);
            else
                offs += snprintf(outbuf+offs, 2048-offs, "   ");
        }
        outbuf[offs++] = ' ';
        for (j = 0; j < 16 && (i + j) < blen; j ++) {
            c = ((const char*)pbuf)[i+j];
            outbuf[offs++] = (c >= 32 && c <= 127) ? c : '.';
        }
        offs += snprintf(outbuf+offs, 2048-offs, "\n");
    }

    sptl_log(SPTLLCAT_INFO, outbuf);

    return SPTLERR_OK;
}

