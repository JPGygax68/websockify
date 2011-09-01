#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <memory.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>

#include "sptl_int.h"

#ifdef _WIN32
#define snprintf	sprintf_s
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
	SPTL_Layer			*first;			// first layer in stack
	// TODO: move the following to "reassemble/copy" layer ?
	sptl_byte_t			*pinblock;
	size_t				inbsize;
	size_t				inbused;
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
sptl_recv_copy(SPTL_Stack *stack, sptl_byte_t *block, size_t len, sptl_flags_t *flags)
{
	size_t chnksize;
	size_t tlen;
	sptl_flags_t iflags;
	int err;
	int wait;

	tlen = 0;
	wait = 0;

	// Add data from following blocks, as necessary and available
	while (tlen < len && !wait) {
		// Need more data from lower layers ?
		if (stack->inbused >= stack->inbsize) {
			stack->inbused = 0;
			err = stack->first->receive(stack->first, &stack->pinblock, &stack->inbsize, &iflags);
			if (err < 0) {
				if (err == SPTLERR_WAIT) 
					wait = 1;
				else
					return err;
			}
		}
		if (!wait) {
			// Copy to output block, as much as needed or as will fit
			// TODO: set flags
			if (stack->inbused < stack->inbsize) {
				chnksize = min(len, stack->inbsize - stack->inbused);
				memcpy(block, stack->pinblock, chnksize);
				stack->inbused += chnksize;
				tlen += chnksize;
			}
		}
	}

	sptl_log_packet(SPTLLCAT_DEBUG, block, tlen);

	return tlen;
}

int
sptl_log(sptl_logcat_t cat, const char *format, ...)
{
	static char buf[4096+1];
	unsigned offs;
	va_list al;
	
	va_start(al, format);

	offs = 0;
	offs +=  snprintf(buf+offs, 4096-offs, "[%-7.7s] ", catstr[cat]);
	offs += vsnprintf(buf+offs, 4096-offs, format, al);
	offs +=  snprintf(buf+offs, 4096-offs, "\n");

	va_end(al);

	fprintf(stderr, buf); // TODO: hooks ?

	return SPTLERR_OK;
}

// TODO: sptl_shutdown_stack()

int
sptl_log_packet(sptl_logcat_t cat, const sptl_byte_t *pbuf, size_t blen)
{
	char outbuf[2048+1];
	unsigned offs;
	unsigned i, j;
	char c;

	offs = 0;
	for (i = 0; offs < (2048-6-16*3-1-16) && i < blen; i += 16) {
		offs += snprintf(outbuf+offs, 2048-offs, "%4.4x: ", i);
		for (j = 0; j < 16 && (i + j) < blen; j ++)
			offs += snprintf(outbuf+offs, 2048-offs, "%2.2x ", ((unsigned char*)pbuf)[i+j]);
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

