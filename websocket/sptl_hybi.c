#ifdef _WIN32
#include <WinSock2.h>
#endif
#include <assert.h>

#include "sptl_hybi.h"

/* SPTL (Stackable Packet Transmission Layers) layer adapting the WebServer
 * library.
 *
 * Copyright 2010 Hans-Peter Gygax
 * Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
 */

#include <sptl/sptl_int.h>

#include "sptl_hybi.h"

//--- Constants ---------------------------------------------------------------

//--- Data types --------------------------------------------------------------

typedef enum {
	NEUTRAL							// between packets (or before first / after last)
	, OBTAINING_HEADER				// obtaining the header
	, DELIVERING_FRAGMENTS			// delivering packet fragments
} receive_state_t;

typedef enum {
	OPCODE
	, LENGTH1
	, LENGTH2
	, LENGTH8
	, MASK_KEY
} header_stage_t;

/* Control structure
 */
// TODO: separate input and output
typedef struct {
	SPTL_Layer		layer;
	receive_state_t recvstate;		// receive state (see above)
	sptl_byte_t     *block;			// data block obtained from lower level
	size_t          blen;			// size of that data block;
	unsigned		boffs;			// current offset within data block or header field
	header_stage_t  hdrstage;		// sub-state for header parsing
	unsigned		fldoffs;		// offset within current field
	sptl_byte_t		opcode;			// HyBi frame op-code
	short			masked;			// boolean: are frames masked ?
	sptl_byte_t		mask_key[4];	// XOR mask key
	size_t			frmlen;			// frame length (obtained from header)
	size_t			delivlen;		// length delivered so far
	sptl_byte_t		hdrbuf[8];
} HyBiCS;

//--- Private routines --------------------------------------------------------

/* Returns the (remaining) size of the chunk, or an error code.
 */
static int
check_for_chunk(HyBiCS *cs)
{
	sptl_ushort_t flags;
	int err;

	// No more data available from the current block ?
	if (cs->boffs >= cs->blen) {
		cs->boffs = 0;
		// Try to get a new one
		err = sptl_receive_from_lower(&cs->layer, &cs->block, &cs->blen, &flags);
		if (err < 0) return SPTLIERR_LOWER_LEVEL_RECEIVE_ERROR;
	}

	return cs->blen - cs->boffs;
}

static int
get_next_byte(HyBiCS *cs, sptl_byte_t *byte)
{
	int chnksize;
	
	// Make sure we got a chunk of data available
	if ((chnksize = check_for_chunk(cs)) < 0) return chnksize;

	// Consume and return one byte
	*byte = cs->block[cs->boffs++];

	return SPTLERR_OK;
}

static void
enter_header_stage(HyBiCS *cs, header_stage_t stage)
{
	switch (stage) {
	case OPCODE:
		break;
	case LENGTH1:
		break;
	case LENGTH2:
		cs->fldoffs = 0;
		break;
	case LENGTH8:
		cs->fldoffs = 0;
		break;
	case MASK_KEY:
		cs->fldoffs = 0;
		break;
	}
	cs->hdrstage = stage;
}

static void 
enter_state(HyBiCS *cs, receive_state_t state)
{
	switch (state) {
	case NEUTRAL:
		cs->blen = 0;
		cs->boffs = 0;
		break;
	case OBTAINING_HEADER:
		enter_header_stage(cs, OPCODE);
		break;
	case DELIVERING_FRAGMENTS:
		cs->delivlen = 0;
		break;
	}

	cs->recvstate = state;
}

static int
do_neutral(HyBiCS *cs, sptl_ushort_t *flags)
{
	int chnksize;

	// Get next chunk of data
	if ((chnksize = check_for_chunk(cs)) <= 0) return chnksize;

	// If successful, switch to "obtaining header" mode (do not forget to init state variables!)
	enter_state(cs, OBTAINING_HEADER);

	return SPTLERR_OK;
}

static int
do_obtain_header(HyBiCS *cs, sptl_ushort_t *flags)
{
	sptl_byte_t byte;

	// Get and analyze header bytes until header is complete or data exhausted
	while (cs->recvstate == OBTAINING_HEADER && get_next_byte(cs, &byte) == SPTLERR_OK) {
		switch (cs->hdrstage) {
		case OPCODE:	
			cs->opcode = byte & 0x0f;
			enter_header_stage(cs, LENGTH1);
			break;
		case LENGTH1:
			cs->masked = (byte & 0x80) != 0;
			cs->frmlen = byte & 0x7f;
			if (cs->frmlen < 126)
				enter_header_stage(cs, MASK_KEY);
			else
				enter_header_stage(cs, cs->frmlen == 126 ? LENGTH2 : LENGTH8);
			break;
		case LENGTH2:
			cs->hdrbuf[cs->fldoffs++] = byte;
			if (cs->fldoffs == 2) {
				cs->frmlen = ntohs( *((unsigned short*)&cs->hdrbuf[0]) );
				enter_header_stage(cs, MASK_KEY);
			}
			break;
		case LENGTH8:
			cs->hdrbuf[cs->fldoffs++] = byte;
			if (cs->fldoffs == 8) {
				assert(cs->frmlen == 127);
				if (*((unsigned long*)&cs->hdrbuf[0]) != 0) {
					sptl_log(SPTLLCAT_ERROR, "%s: encountered super-long (>32-bit length) frame, abandoning", cs->layer.name);
					return SPTLIERR_UNSUPPORTED_FEATURE; }
				cs->frmlen = ntohl(*((unsigned long*)&cs->hdrbuf[4]));
				enter_header_stage(cs, MASK_KEY);
			}
			break;
		case MASK_KEY:
			if (!cs->masked) {
				enter_state(cs, DELIVERING_FRAGMENTS);
			}
			else {
				cs->mask_key[cs->fldoffs++] = byte;
				if (cs->fldoffs == 4) {
					enter_state(cs, DELIVERING_FRAGMENTS);
				}
			}
		}
	}

	return SPTLERR_OK;
}

static int 
do_deliver_fragment(HyBiCS *cs, sptl_byte_t **pstart, size_t *plen, sptl_ushort_t *flags)
{
	int chnksize;
	size_t fragsize;
	unsigned i;

	*flags = 0;

	// Get either the full packet payload or as big a fragment of it as is available
	if ((chnksize = check_for_chunk(cs)) < 0) return chnksize;

	// Deliver the fragment (keep track of partial payload delivered so far)
	fragsize = (size_t) min((cs->frmlen - cs->delivlen), (size_t) chnksize);
	*pstart = cs->block + cs->boffs, *plen = fragsize;

	sptl_log_packet(SPTLLCAT_INFO, *pstart, *plen);

	// Apply masking
	if (cs->masked) {
		for (i = 0; i < fragsize; i ++) 
			cs->block[cs->boffs+i] = cs->block[cs->boffs+i] ^ cs->mask_key[(cs->delivlen+i)%4];
	}

	sptl_log_packet(SPTLLCAT_INFO, *pstart, *plen);

	// If the packet is complete, go back to "neutral" mode
	// TODO: flags!
	cs->delivlen += fragsize;
	if (cs->delivlen >= cs->frmlen) {
		enter_state(cs, NEUTRAL);
	}

	return SPTLERR_OK;
}

static int
activate(SPTL_Layer *layer)
{
	HyBiCS *cs = (HyBiCS*) layer;

	enter_state(cs, NEUTRAL);

	return SPTLERR_OK;
}

static int
destroy(SPTL_Layer *layer)
{
	//HyBiCS *cs = (HyBiCS*) layer;
	return SPTLERR_OK;
}

static int 
receive(SPTL_Layer *self, sptl_byte_t **pstart, size_t *plen, sptl_ushort_t *flags)
{
	HyBiCS *cs;
	int stop;
	int err;

	cs = (HyBiCS*)self;

	// Repeat until packet fragment is ready or no more data is available:
	stop = 0;
	while (! stop) {

		switch (cs->recvstate) {
		case NEUTRAL:
			if ((err = do_neutral(cs, flags)) < 0) return err;
			stop = err != 0;
			break;
		case OBTAINING_HEADER:
			if ((err = do_obtain_header(cs, flags)) < 0) return err;
			stop = err != 0;
			break;
		case DELIVERING_FRAGMENTS:
			if ((err = do_deliver_fragment(cs, pstart, plen, flags)) < 0) return err;
			stop = err != 0;
			break;
		}
	}

	return SPTLERR_OK;
}

//--- Public interface --------------------------------------------------------

SPTL_Layer *
sptlhybi_create_layer(int version)
{
	HyBiCS *cs;
	
	cs = (HyBiCS*) sptl_create_layer(sizeof(HyBiCS), "WebServer");
	if (cs == NULL) return NULL;

	cs->layer.activate = activate;
	cs->layer.destroy  = destroy;
	cs->layer.receive  = receive;

	return &cs->layer;
}
