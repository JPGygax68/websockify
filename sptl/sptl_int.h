#ifndef __SPTL_INT_H
#define __SPTL_INT_H

#include <stddef.h>

#include "sptl.h"

// Constants ------------------------------------------------------------------

/* Internal error codes.
 * (Made not to overlap with general error codes)
 */
#define SPTLIERR_LOWER_LEVEL_RECEIVE_ERROR	(-100)		// one of the lower levels has a problem
#define SPTLIERR_UNSUPPORTED_FEATURE		(-101)		// protocol is using feature we do not support

// Data types -----------------------------------------------------------------

typedef int (*sptl_layer_destroy_func)(SPTL_Layer *self);
typedef int (*sptl_layer_activate_func)(SPTL_Layer *self);
typedef int (*sptl_layer_receive_func)(SPTL_Layer *self, sptl_byte_t **pstart, size_t *plen, sptl_flags_t *flags);

struct _SPTL_Layer {
	SPTL_Layer					*next;			// Next-lower layer
	SPTL_Stack                  *stack;			// Owning SPiTtLe Stack
	const char                  *name;
	sptl_layer_destroy_func		destroy;		// deconstructs the layer
	sptl_layer_activate_func	activate;		// activate the layer for use
	sptl_layer_receive_func		receive;		// receive next chunk of data
};

// Functions ------------------------------------------------------------------

/* Allocate layer control struct and initialize common data.
 * Layer-specific data members must be initialized by caller.
 */
SPTL_Layer *
sptl_create_layer(size_t size, const char *name);

int
sptl_destroy_layer(SPTL_Layer *layer);

/* Receive function could be called directly, but this allows for built-in
 * tracing/logging.
 */
int
sptl_receive_from_lower(SPTL_Layer *self, sptl_byte_t **pstart, size_t *plen, sptl_flags_t *flags);

#endif // __SPTL_INT_H
