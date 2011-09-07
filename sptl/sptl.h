#ifndef __SPTL_H
#define __SPTL_H

/*---------------------------------------------------------------------------
 * sptl.h
 *
 * Copyright 2010 Hans-Peter Gygax (gygax@practicomp.ch)
 * Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)

 * Stackable Packet Transmission Layers.
 *
 * This is a framework allowing to organize packet processors in layers.
 *---------------------------------------------------------------------------*/

/* TODO: stack-wide settings that layers must follow to guarantee certain
  things like minimal supported packet size ? */

#include <stddef.h>

// Constants -----------------------------------------------------------------

/* Error codes
 * (For both external and internal use.)
 */
#define SPTLERR_OK							(0)
#define SPTLERR_WAIT						(-1)
#define SPTLERR_CONNECTION_CLOSED			(-2)
#define SPTLERR_OUT_OF_MEMORY				(-3)

/* Receive flags
 */
#define SPTLRF_PARTIAL_PACKET				(1 << 0)	// (optional) the returned data was just a fragment of a packet

// Data Types -----------------------------------------------------------------

typedef unsigned char	sptl_byte_t;
typedef unsigned short	sptl_ushort_t;
typedef sptl_ushort_t	sptl_flags_t;

/* Opaque struct representing a Spittle stack
 */
struct _SPTL_Stack;
typedef struct _SPTL_Stack SPTL_Stack;

/* Opaque struct representing a stack layer.
 */
struct _SPTL_Layer;
typedef struct _SPTL_Layer SPTL_Layer;

/* Log categories.
 */
typedef enum {
	  SPTLLCAT_DEBUG
	, SPTLLCAT_INFO
	, SPTLLCAT_WARNING
	, SPTLLCAT_ERROR
} sptl_logcat_t;

// Functions ------------------------------------------------------------------

/* Create a stack of packet processors.
 */
SPTL_Stack *
sptl_create_stack();

/* Destroy a stack, releasing all associated memory.
 */
int
sptl_dispose_stack(SPTL_Stack *stack);

/* Add a layer to a stack.
 */
// TODO: mechanism to prevent adding after a "terminal" layer ?
int
sptl_add_layer(SPTL_Stack *stack, SPTL_Layer *layer);

/* Activate the stack.
 * If this is successful, the stack will be ready to send & receive packets.
 * Once activated, the composition of a stack can no longer be modified.
 * TODO: guard against the above with assert()
 */
int
sptl_activate_stack(SPTL_Stack *stack);

/* Receive available incoming data, copying it to the specified buffer.
 * Returns error code (negative) or number of bytes that could be obtained.
 */
int 
sptl_recv_copy(SPTL_Stack *stack, sptl_byte_t *block, size_t len, sptl_flags_t *flags);

int
sptl_log(sptl_logcat_t cat, const char *msg);

int
sptl_log_format(sptl_logcat_t cat, const char *format, ...);

int
sptl_log_packet(sptl_logcat_t cat, const sptl_byte_t *block, size_t len);

#endif // __SPTL_H
