/* SPTL (Stackable Packet Transmission Layers) layer adapting the WebServer
 * library.
 *
 * Copyright 2011 Hans-Peter Gygax
 * Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
 */

#include <malloc.h>
#include <sptl/sptl_int.h>

#include "sptl_webserver.h"

//--- Constants ---------------------------------------------------------------

#define DEFAULT_RECEIVE_BUFFER_SIZE        (4096)

//--- Data types --------------------------------------------------------------

/* Control structure
 */
typedef struct {
    SPTL_Layer        layer;
    wsv_ctx_t        *wsvctx;        // WebServer context
    sptl_byte_t        *inbuf;            // incoming buffer
    size_t          inbsize;        // inbuf size
} LayerCS;

//--- Private routines --------------------------------------------------------

static int
activate(SPTL_Layer *layer)
{
    //LayerCS *cs = (LayerCS*) layer;
    return SPTLERR_OK;
}

static int
destroy(SPTL_Layer *layer)
{
    LayerCS *cs = (LayerCS*) layer;
    free(cs->inbuf);
    return SPTLERR_OK;
}

static int 
fetch(SPTL_Layer *self, const sptl_byte_t **pstart, size_t *plen, sptl_ushort_t *flags)
{
    LayerCS *cs;
    int len;

    sptl_log_format(SPTLLCAT_DEBUG, "%s receive()", __FILE__);
    
    cs = (LayerCS*)self;

    *pstart = cs->inbuf;
    *plen   = 0;
    *flags  = 0;

    len = wsv_recv(cs->wsvctx, cs->inbuf, cs->inbsize);
    if (len <= 0) {
        switch (len) {
        case WSVSR_CONNECTION_CLOSED: 
            return SPTLERR_CONNECTION_CLOSED;
        case WSVSR_WAIT: 
            return SPTLERR_WAIT;
        default: 
            return SPTLIERR_LOWER_LEVEL_RECEIVE_ERROR;
        }
    }

    *plen = len;

    return SPTLERR_OK;
}

//--- Public interface --------------------------------------------------------

SPTL_Layer *
sptlwsv_create_layer(wsv_ctx_t *ctx)
{
    LayerCS *cs;

    cs = (LayerCS*) sptli_create_layer(sizeof(LayerCS), "WebServer");
    if (cs == NULL) return NULL;

    cs->wsvctx = ctx;

    cs->layer.activate = activate;
    cs->layer.destroy  = destroy;
    cs->layer.fetch    = fetch;

    cs->inbsize = DEFAULT_RECEIVE_BUFFER_SIZE; // TODO: override default!
    cs->inbuf = (sptl_byte_t*) malloc(cs->inbsize);
    if (cs->inbuf == NULL) {
        sptl_log_format(SPTLLCAT_ERROR, "%s: Out of memory trying to allocate receive buffer (size: %u)", cs->layer.name, cs->inbsize);
        return NULL; }

    return &cs->layer;
}
