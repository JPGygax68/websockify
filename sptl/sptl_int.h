#ifndef __SPTL_INT_H
#define __SPTL_INT_H

#include <stddef.h>

#include "sptl.h"

// Constants ------------------------------------------------------------------

/* Internal error codes.
 * (Made not to overlap with general error codes)
 */
#define SPTLIERR_LOWER_LEVEL_RECEIVE_ERROR      (-100)      // one of the lower levels has a problem
#define SPTLIERR_UNSUPPORTED_FEATURE            (-101)      // protocol is using feature we do not support
#define SPTLIERR_PROTOCOL_ERROR                 (-102)      // received data does not obey protocol

// Data types -----------------------------------------------------------------

typedef int (*sptl_layer_destroy_func)(SPTL_Layer *self);
typedef int (*sptl_layer_activate_func)(SPTL_Layer *self);
typedef int (*sptl_layer_receive_func)(SPTL_Layer *self, const sptl_byte_t **pstart, size_t *plen, sptl_flags_t *flags);

struct _SPTL_Layer {
    SPTL_Layer                  *next;      // Next-lower layer
    SPTL_Stack                  *stack;     // Owning SPiTtLe Stack
    const char                  *name;
    sptl_layer_destroy_func     destroy;    // deconstructs the layer
    sptl_layer_activate_func    activate;   // activate the layer for use
    sptl_layer_receive_func     receive;    // receive next chunk of data
    sptl_byte_t                 *block;     // data block obtained from lower level
    size_t                      blen;       // size of that data block;
    size_t                      boffs;      // current offset within data block or header field
};

// Functions ------------------------------------------------------------------

/* Allocate layer control struct and initialize common data.
 * Layer-specific data members must be initialized by caller.
 */
SPTL_Layer *
sptli_create_layer(size_t size, const char *name);

int
sptli_destroy_layer(SPTL_Layer *layer);

/* Pass-through to the packet processor.
 */
int
sptli_fetch(SPTL_Layer *layer, const sptl_byte_t **pstart, size_t *plen, sptl_ushort_t *flags);

/* Receive function could be called directly, but this allows for built-in
 * tracing/logging.
 */
int
sptli_fetch_from_lower(SPTL_Layer *self);

int
sptli_get_data(SPTL_Layer *self);

int
sptli_get_byte(SPTL_Layer *self, sptl_byte_t *byte);

#endif // __SPTL_INT_H
