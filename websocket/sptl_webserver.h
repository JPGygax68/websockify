#ifndef __SPTL_WEBSERVER_H
#define __SPTL_WEBSERVER_H

#include <sptl/sptl.h>
#include <webserver/webserver.h>

SPTL_Layer *
sptlwsv_create_layer(wsv_ctx_t *ctx);

#endif // __SPTL_WEBSERVER_H