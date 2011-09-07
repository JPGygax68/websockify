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
	sptl_log_format(SPTLLCAT_DEBUG, "%s: receive() returned %u bytes", layer->name, *plen); // TODO: use separate category ?
	return err;
}

//--- Public routines ---------------------------------------------------------

SPTL_Layer * 
sptl_create_layer(size_t size, const char *name)
{
	SPTL_Layer *layer = (SPTL_Layer*) malloc(size);

	layer->next  = NULL;
	layer->stack = NULL;
	layer->name  = name;

	return layer;
}

int
sptl_destroy_layer(SPTL_Layer *layer)
{
	free(layer);

	return SPTLERR_OK;
}

int
sptl_receive_from_lower(SPTL_Layer *self, sptl_byte_t **pstart, size_t *plen, sptl_ushort_t *flags)
{
	SPTL_Layer *lower;
	lower = self->next;
	assert(lower != NULL);
	return call_receive(lower, pstart, plen, flags);
}
