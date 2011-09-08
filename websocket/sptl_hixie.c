#include <sptl/sptl_int.h>

#include "sptl_hixie.h"

//--- Data types -------------------------------------------------------------

typedef enum {
	NEUTRAL
	, DELIVERING
	, CLOSING						// got first byte of closing frame, expecting second
} receive_state_t;

/* Control structure
 */
// TODO: separate input and output
typedef struct {
	SPTL_Layer		layer;
	receive_state_t	recvstate;
	size_t			delivlen;
} HixieCS;

//--- Private routines --------------------------------------------------------

static void
enter_state(HixieCS *cs, receive_state_t state)
{
	switch (state) {
	case NEUTRAL:
		break;
	case DELIVERING:
		cs->delivlen = 0;
		break;
	}
	cs->recvstate = state;
}

static int
activate(SPTL_Layer *layer)
{
	HixieCS *cs = (HixieCS*) layer;

	enter_state(cs, NEUTRAL);

	return SPTLERR_OK;
}

static int
destroy(SPTL_Layer *layer)
{
	//HixieCS *cs = (HixieCS*) layer;
	return SPTLERR_OK;
}

static int 
receive(SPTL_Layer *self, sptl_byte_t **pstart, size_t *plen, sptl_ushort_t *flags)
{
	HixieCS *cs;
	int stop;
	sptl_byte_t byte;
	size_t flen;
	int err;

	cs = (HixieCS*)self;

	// Repeat until packet fragment is ready or no more data is available:
	stop = 0;
	while (! stop) {
		switch (cs->recvstate) {
		case NEUTRAL:
			if ((err = sptli_get_byte(self, &byte)) < 0) return err;
			if (byte == 0x00) {
				enter_state(cs, DELIVERING);
			}
			else if (byte == 0xff) {
				enter_state(cs, CLOSING);
			}
			else {
				sptl_log_format(SPTLLCAT_ERROR, "Hixie protocol error: expected framing byte, got $%2.2x", byte);
				return SPTLIERR_PROTOCOL_ERROR;
			}
			break;
		case DELIVERING:
			*pstart = self->block + self->boffs;
			for (flen = 0; self->boffs < self->blen; self->boffs++, flen++)
				if (self->block[self->boffs] == 0xff) {
					self->boffs ++;
					enter_state(cs, NEUTRAL);
					break;
				}
			*plen = flen;
			sptl_log_packet(SPTLLCAT_DEBUG, *pstart, *plen);
			stop = 1;
			break;
		case CLOSING:
			if ((err = sptli_get_byte(self, &byte)) < 0) return err;
			if (byte != 0x00) {
				sptl_log_format(SPTLLCAT_ERROR, "Hixie protocol error: expected second byte of closing frame, got $%2.2x", byte);
				return SPTLIERR_PROTOCOL_ERROR;
			}
		}
	}

	return SPTLERR_OK;
}

//--- Public interface --------------------------------------------------------

SPTL_Layer *
sptlhixie_create_layer(int version)
{
	HixieCS *cs;
	
	cs = (HixieCS*) sptli_create_layer(sizeof(HixieCS), "Hixie");
	if (cs == NULL) return NULL;

	cs->layer.activate = activate;
	cs->layer.destroy  = destroy;
	cs->layer.receive  = receive;

	return &cs->layer;
}
