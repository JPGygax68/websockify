/*
 * A WebSocket to TCP socket proxy with support for "wss://" encryption.
 * Copyright 2010 Joel Martin
 * Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
 *
 * You can make a cert/key with openssl using:
 * openssl req -new -x509 -days 365 -nodes -out self.pem -keyout self.pem
 * as taken from http://docs.python.org/dev/library/ssl.html#certificates
 *
 * 2011-06-12 gygax@practicomp.ch   separated out "websockification" from pure
 *      websocket functionality; tested under Windows (Vista)
 */

#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>
#ifdef _WIN32
    #include <Windows.h>
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <sys/select.h>
    #include <fcntl.h>
#endif
#include <sys/stat.h>

#include "wsproxy.h"

/* Adaptation to platform specifics */

#ifndef _WIN32
#define closesocket close
#endif

static int daemonized = 0; // TODO

#define __LOG(stream, ...) \
    if (! daemonized) { \
        fprintf(stream, "  "); \
        fprintf(stream, __VA_ARGS__); \
        fprintf(stream, "\n" ); \
    }

#define LOG_MSG(...) __LOG(stdout, __VA_ARGS__);
#define LOG_ERR(...) __LOG(stderr, __VA_ARGS__);
#define LOG_DBG LOG_MSG

#ifdef _DEBUG

static void dump_buffer( char *buffer, size_t size, const char *title )
{
	char line[4096];
	unsigned i;
	int ch;
	unsigned cu;
	assert( size < 4096 );
	for ( i = 0; i < size; i ++ ) {
		line[i] = buffer[i] >= 32 && buffer[i] <= 126 ? buffer[i] : ' ';
	}
	line[i] = 0;
	printf( "%s, %u bytes: \"%s\"", title, (unsigned) size, line );
	for ( i = 0; i < size; i ++ ) {
		if ( i % 8 == 0 ) printf("\n"); else printf("  ");
		ch = buffer[i];
		cu = (ch < 0 ? 65536 + ch : *((unsigned*)&ch)) & 0xff;
		ch =  ch >= 32 && ch <= 126 ? ch : ' ';
		printf( "'%c' ($%2.2x) (%3.3u)", ch, cu, cu );
	}
	if ( i % 8 != 0 ) printf("\n");
}

#else
#define dump_buffer( b, s, t )
#endif

/* This is the main routine. It receives and forwards data blocks both ways 
 * between the websocket client and the TCP/SSL target.
 */
static void do_proxy(ws_ctx_t *ctx, int target) 
{
    fd_set rlist, wlist, elist;
    struct timeval tv;
    int maxfd, client;
    char *tbuf, *cbuf; // target and client buffers
    unsigned int bufsize; //, dbufsize;
    unsigned int tstart, tend;
    unsigned int clen; // length of to-client data block
    ssize_t len, bytes;
    int csending; // > 0 = we are sending to the client
    int ret;

    /* Initialize buffers */
    bufsize = 40*1024;
    /* base64 is 4 bytes for every 3; - 20 for WS '\x00' / '\xff' and good measure  */
    //dbufsize = (bufsize * 3)/4 - 20;
    if (! (tbuf = ws_alloc_block(ctx, bufsize)) )
            { LOG_ERR("malloc()"); return; }
    if (! (cbuf = ws_alloc_block(ctx, bufsize)) )
            { LOG_ERR("malloc()"); return; }

    client = ws_getsockfd(ctx);

    tstart = tend = 0;
    clen = 0;
    csending = 0;

    maxfd = client > target ? client+1 : target+1;

    while (1) {
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        FD_ZERO(&rlist);
        FD_ZERO(&wlist);
        FD_ZERO(&elist);

        FD_SET(client, &elist);
        FD_SET(target, &elist);

        if (tend == tstart) {
            // Nothing queued for target, so read from client
            FD_SET(client, &rlist);
        } else {
            // Data queued for target, so write to it
            FD_SET(target, &wlist);
        }
        if (!csending && clen == 0) {
            // Nothing queued for client, so read from target
            FD_SET(target, &rlist);
        } else {
            // Data queued for client, so write to it
            FD_SET(client, &wlist);
        }

        // Wait until something happens...
        ret = select(maxfd, &rlist, &wlist, &elist, &tv);
        //if (pipe_error) { break; }

        // Something bad happened...
        if (FD_ISSET(target, &elist)) {
            LOG_ERR("target exception");
            break;
        }
        if (FD_ISSET(client, &elist)) {
            LOG_ERR("client exception");
            break;
        }

        // Something else happened, also bad...
        if (ret == -1) {
            LOG_ERR("select(): %s", strerror(errno));
            break;
        } else if (ret == 0) {
            LOG_DBG("Timeout on select()");
            continue;
        }

        // Target ready for writing ?
        if (FD_ISSET(target, &wlist)) {
            len = tend-tstart;
			      //dump_buffer( tbuf+tstart, len, "Sending to target" );
            bytes = send(target, tbuf + tstart, len, 0);
            //if (pipe_error) { break; }
            if (bytes < 0) {
                LOG_ERR("target connection error: %s\n", strerror(errno));
                break;
            }
            tstart += bytes;
            if (tstart >= tend) {
                tstart = tend = 0;
                LOG_MSG(">"); // TODO: formerly traffic()
            } else {
                LOG_MSG(">."); // TODO: formerly traffic()
            }
        }

        // Client ready for writing ?
        if (FD_ISSET(client, &wlist)) {
            // Got unfinished block ?
            if (csending) {
                ret = ws_cont(ctx);
            }
            else {
                assert(clen > 0);
                // Start sending new data
			    //dump_buffer(cbuf, clen, "Sending to client" );
                ret = ws_send(ctx, cbuf, clen);
            }
            if (ret < 0) {
                LOG_ERR("Error while sending to client"); // TODO: translate error to string
                break;
            }
            else if (ret > 0) {
                clen = 0; // we are done with this data block
                LOG_MSG("<"); // TODO: formerly traffic()
            }
            else {
                LOG_MSG("<."); // TODO: formerly traffic()
            }
        }

        // Data coming in from the target ?
        if (FD_ISSET(target, &rlist)) {
            // Get the data into the client buffer
            bytes = recv(target, cbuf, bufsize , 0);
			      //dump_buffer(cbuf, bytes, "Received from target");
            if (bytes < 0) { 
                LOG_ERR("Error receiving from target"); // TODO: error string
                break;
            } 
            else if (bytes == 0) {
				LOG_MSG("Target closed connection");
                break;
            }
            clen = bytes;
            LOG_MSG("{"); // TODO: formerly traffic()
        }

        // Data coming in from the client ?
        if (FD_ISSET(client, &rlist)) {
            // Get the data into the target buffer
            bytes = ws_recv(ctx, tbuf, bufsize);
            if (bytes <= 0) {
                if (bytes == 0) {
                    LOG_MSG("Client closed connection with orderly close frame");
                }
                else {
                    LOG_ERR("Error receiving from client"); // TODO: error string
                }
                break;
            }
            //dump_buffer(tbuf, bytes, "Received from client");
            LOG_MSG("}"); // TODO: formerly traffic()
            tstart = 0;
            tend = bytes;
        }
    }

    ws_free_block(ctx, cbuf);
    ws_free_block(ctx, tbuf);
}

/* This is the callback for ws_start_server().
 */
void wsp_connection_handler(ws_ctx_t *ctx, ws_listener_t *settings) 
{
    int tsock = 0;
    struct sockaddr_in taddr;
    wsp_target_t *target;

    target = settings->userdata;

    LOG_MSG("connecting to: %s:%d, location=\"%s\"", target->host, target->port, ws_get_location(ctx));

    tsock = socket(AF_INET, SOCK_STREAM, 0);
    if (tsock < 0) {
        LOG_ERR("Could not create target socket: %s", strerror(errno));
        return;
    }
    memset((char *) &taddr, 0, sizeof(taddr));
    taddr.sin_family = AF_INET;
    taddr.sin_port = htons(target->port);

    /* Resolve target address */
    if (ws_resolve_host(&taddr.sin_addr, target->host) < -1) {
        LOG_ERR("Could not resolve target address: %s\n", strerror(errno));
    }

    if (connect(tsock, (struct sockaddr *) &taddr, sizeof(taddr)) < 0) {
        LOG_ERR("Could not connect to target: %s\n", strerror(errno));
        close(tsock);
        return;
    }

    /* if ((settings.verbose) && (! settings.daemon)) {
        printf("%s", traffic_legend);
    } */

    do_proxy(ctx, tsock);

	closesocket(tsock);
}
