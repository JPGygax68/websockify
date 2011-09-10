/* SPTL (Stackable Packet Transmission Layers) layer for Base64 decoding.
 *
 * Copyright 2011 Hans-Peter Gygax
 * Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
 */

#ifdef _WIN32
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#include <sys/param.h>
#endif
#include <malloc.h>
#include <assert.h>

#include <sptl/sptl_int.h>

#include "sptl_base64.h"

// TODO: detect and support closing frame

//--- Constants ---------------------------------------------------------------

static const size_t DEFAULT_BUFFER_SIZE = 4*((4096+2)/3);

//static const char base64_chars[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
//--- Data types --------------------------------------------------------------

/* Control structure
 */
// TODO: separate input and output
typedef struct {
    SPTL_Layer      layer;
    sptl_byte_t     *buffer;
    size_t          bsize;
    char            group[4];   // 4-character group (encoding 3 bytes)
    unsigned        nchars;     // number of chars obtained so far
} Base64CS;

//--- Private routines --------------------------------------------------------

static int
activate(SPTL_Layer *layer)
{
    Base64CS *cs = (Base64CS*) layer;

    cs->nchars = 0;
    
	return SPTLERR_OK;
}

static int
destroy(SPTL_Layer *layer)
{
    Base64CS *cs = (Base64CS*) layer;
    if (cs->buffer) free(cs->buffer);
	return SPTLERR_OK;
}

static int 
receive(SPTL_Layer *self, sptl_byte_t **pstart, size_t *plen, sptl_flags_t *flags)
{
    Base64CS *cs;
    int err;
    unsigned i;
    char c;
    sptl_byte_t v;
    sptl_byte_t *p;
    unsigned n;

    cs = (Base64CS*)self;

    *pstart = cs->buffer;
    *plen = 0;
    
    // Fill up all available space
    while ((*plen + 3) < cs->bsize) {
        // Fill up the next group of 4 chars
        while (cs->nchars < 4) {
            //sptl_log(SPTLLCAT_DEBUG, "calling sptli_get_byte()");
            if ((err = sptli_get_byte(self, (sptl_byte_t*)&cs->group[cs->nchars])) < 0) {
				if (err == SPTLERR_WAIT) 
					return *plen > 0 ? SPTLERR_OK: SPTLERR_WAIT;
				else
					return err;
			}
            //sptl_log(SPTLLCAT_DEBUG, "sptli_get_byte() successful");
            cs->nchars ++;
        }
        // Decode: iterate over all 4 characters (abort at padding)
        p = *pstart + *plen;
        n = 0; // number of output bytes
        for (i = 0; i < 4; i++) {
            c = cs->group[i];
            // Get the value of the char
            if      (c == '=') v = 0;
            else if (c == '+') v = 62;
            else if (c == '/') v = 63;
            else if (c <= '9') v = (sptl_byte_t) (52 + (unsigned)(c - '0'));
            else if (c <= 'Z') v = (sptl_byte_t) ( 0 + (unsigned)(c - 'A'));
            else if (c <= 'z') v = (sptl_byte_t) (26 + (unsigned)(c - 'a'));
            // Now bit-shift it into the right position
            switch (i) {
            case 0:
                p[0]  = v << 2;
                n = 1;
                break;
            case 1:
                p[0] |= v >> 4;
                p[1]  = (v & 0x0f) << 4;
                n = 2;
                break;
            case 2:
                p[1] |= (v >> 2) & 0x0f;
                p[2]  = (v & 0x03) << 6;
                n = 3;
                break;
            case 3:
                p[2] |= v & 0x3f;
                break;
            }
        }
        *plen += n;
        cs->nchars = 0; // done with this group
    }
    
	return SPTLERR_OK;
}

//--- Public interface --------------------------------------------------------

SPTL_Layer *
sptlbase64_create_layer()
{
	Base64CS *cs;
    size_t bsize;
    
	cs = (Base64CS*) sptli_create_layer(sizeof(Base64CS), "Base64");
	if (cs == NULL) return NULL;

	cs->layer.activate = activate;
	cs->layer.destroy  = destroy;
	cs->layer.receive  = receive;
    
    bsize = DEFAULT_BUFFER_SIZE; // TODO: configurable ?
    cs->buffer = malloc(bsize);
    cs->bsize = bsize;

	return &cs->layer;
}
