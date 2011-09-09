#include <stdio.h>
#include <malloc.h>
#include <assert.h>

#include "sptl_int.h"

//--- Private routines --------------------------------------------------------

#define LOG(layer, category, format, ...) { \
	if (layer != NULL) \
		fprintf(stderr, "SPTL Layer \"%s\" ", layer->name); \
	else \
		fprintf(stderr, "(no layer)"); \
	fprintf(stderr, catstr[category]); \
    fprintf(stderr, format, __VA_ARGS__); \
    fprintf(stderr, "\n" ); \
	fflush(stderr); }

static int
call_receive(SPTL_Layer *layer, sptl_byte_t **pstart, size_t *plen, sptl_ushort_t *flags)
{
	int err;
	err = layer->receive(layer, pstart, plen, flags);
	return err;
}

//--- Public routines ---------------------------------------------------------

SPTL_Layer * 
sptli_create_layer(size_t size, const char *name)
{
	SPTL_Layer *layer = (SPTL_Layer*) malloc(size);

	layer->next  = NULL;
	layer->stack = NULL;
	layer->name  = name;
    
    layer->blen  = 0;
    layer->boffs = 0;

	return layer;
}

int
sptli_destroy_layer(SPTL_Layer *layer)
{
	free(layer);

	return SPTLERR_OK;
}

int
sptli_receive_from_lower(SPTL_Layer *self, sptl_byte_t **pstart, size_t *plen, sptl_ushort_t *flags)
{
	SPTL_Layer *lower;
    lower = self->next;
	assert(lower != NULL);
	return call_receive(lower, pstart, plen, flags);
}

/* Returns the (remaining) size of the chunk, or an error code.
 */
int
sptli_get_data(SPTL_Layer *self)
{
	sptl_ushort_t flags;
	int err;

    // No more data available from the current block ?
	if (self->boffs >= self->blen) {
		self->boffs = 0;
		// Try to get a new one
		err = sptli_receive_from_lower(self, &self->block, &self->blen, &flags);
		if (err < 0) {
			if (err == SPTLERR_WAIT) return err;
			else return SPTLIERR_LOWER_LEVEL_RECEIVE_ERROR;
		}
	}

	return self->blen - self->boffs;
}

int
sptli_get_byte(SPTL_Layer *self, sptl_byte_t *byte)
{
	int chnksize;
	
	// Make sure we got a chunk of data available
	if ((chnksize = sptli_get_data(self)) < 0) return chnksize;

	// Consume and return one byte
	*byte = self->block[self->boffs++];

	return SPTLERR_OK;
}
