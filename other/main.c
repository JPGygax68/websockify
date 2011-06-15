/*
 * A WebSocket to TCP socket proxy with support for "wss://" encryption.
 * Copyright 2010 Joel Martin
 * Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
 *
 * You can make a cert/key with openssl using:
 * openssl req -new -x509 -days 365 -nodes -out self.pem -keyout self.pem
 * as taken from http://docs.python.org/dev/library/ssl.html#certificates
 */
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>
#include <ctype.h>
#include <assert.h>
#ifdef _WIN32
#include <Windows.h>
#include <realpath.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/select.h>
#include <fcntl.h>
#endif
#include <signal.h>
#include <sys/stat.h>

#include <websockify/websockify.h>

char traffic_legend[] = "\n\
Traffic Legend:\n\
    }  - Client receive\n\
    }. - Client receive partial\n\
    {  - Target receive\n\
\n\
    >  - Target send\n\
    >. - Target send partial\n\
    <  - Client send\n\
    <. - Client send partial\n\
";

char USAGE[] = "Usage: [options] " \
               "[source_addr:]source_port target_addr:target_port\n\n" \
               "  --verbose|-v       verbose messages and per frame traffic\n" \
               "  --daemon|-D        become a daemon (background process)\n" \
               "  --cert CERT        SSL certificate file\n" \
               "  --key KEY          SSL key file (if separate from cert)\n" \
               "  --ssl-only         disallow non-encrypted connections";

#define usage(fmt, ...) \
    fprintf(stderr, "%s\n\n", USAGE); \
    fprintf(stderr, fmt , ## __VA_ARGS__); \
    exit(1);

static void signal_handler(sig) {
    switch (sig) {
		// TODO: Windows equivalents ?
        //case SIGHUP: break; // ignore for now			
        //case SIGPIPE: pipe_error = 1; break; // handle inline
		//---
        case SIGTERM: exit(0); break;
    }
}

int main(int argc, char *argv[])
{
    int c, option_index = 0;
    static int ssl_only = 0, daemon = 0, verbose = 0;
    char *found;
    static struct option long_options[] = {
        {"verbose",    no_argument,       &verbose,    'v'},
        {"ssl-only",   no_argument,       &ssl_only,    1 },
        {"daemon",     no_argument,       &daemon,     'D'},
        /* ---- */
        {"cert",       required_argument, 0,           'c'},
        {"key",        required_argument, 0,           'k'},
        {0, 0, 0, 0}
    };
    ws_listener_t settings;
    wsf_target_t target;

	settings.certfile = realpath("self.pem", NULL);
    if (!settings.certfile) {
        /* Make sure it's always set to something */
        settings.certfile = "self.pem";
    }
    settings.keyfile = "";
    settings.userdata = &target;

    while (1) {
        c = getopt_long (argc, argv, "vDc:k:",
                         long_options, &option_index);

        /* Detect the end */
        if (c == -1) { break; }

        switch (c) {
            case 0:
                break; // ignore
            case 1:
                break; // ignore
            case 'v':
                verbose = 1;
                break;
            case 'D':
                daemon = 1;
                break;
            case 'c':
                settings.certfile = realpath(optarg, NULL);
                if (! settings.certfile) {
                    usage("No cert file at %s\n", optarg);
                }
                break;
            case 'k':
                settings.keyfile = realpath(optarg, NULL);
                if (! settings.keyfile) {
                    usage("No key file at %s\n", optarg);
                }
                break;
            default:
                usage("");
        }
    }
    settings.verbose      = verbose;
    settings.ssl_only     = ssl_only;
    //settings.daemon       = daemon;

    if ((argc-optind) != 2) {
        usage("Invalid number of arguments\n");
    }

    found = strstr(argv[optind], ":");
    if (found) {
        memcpy(settings.listen_host, argv[optind], found-argv[optind]);
        settings.listen_port = strtol(found+1, NULL, 10);
    } else {
        settings.listen_host[0] = '\0';
        settings.listen_port = strtol(argv[optind], NULL, 10);
    }
    optind++;
    if (settings.listen_port == 0) {
        usage("Could not parse listen_port\n");
    }

    found = strstr(argv[optind], ":");
    if (found) {
        strncpy(target.host, argv[optind], found-argv[optind]);
        target.host[found-argv[optind]] = '\0';
        target.port = strtol(found+1, NULL, 10);
    } else {
        usage("Target argument must be host:port\n");
    }
    if (target.port == 0) {
        usage("Could not parse target port\n");
    }

    if (ssl_only) {
        if (!access(settings.certfile, 0)) {
            usage("SSL only and cert file '%s' not found\n", settings.certfile);
        }
    } else if (access(settings.certfile, 0) != 0) {
        fprintf(stderr, "Warning: '%s' not found\n", settings.certfile);
    }

    //printf("  verbose: %d\n",   settings.verbose);
    //printf("  ssl_only: %d\n",  settings.ssl_only);
    //printf("  daemon: %d\n",    settings.daemon);
    //printf("  cert: %s\n",      settings.cert);
    //printf("  key: %s\n",       settings.key);

    settings.handler = proxy_handler; 
    ws_start_server(&settings);
}
