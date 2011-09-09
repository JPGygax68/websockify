#
# websocket library makefile
# gygax@practicomp.ch
#

CFLAGS += -Wall -fPIC -I ../ -DHAVE_MEMCPY -DSTDC_HEADERS -DDEBUG
LDFLAGS += -shared

SRC = websocket.c md5.c sha1.c sptl_webserver.c sptl_hybi.c sptl_hixie.c sptl_base64.c

OBJ = $(SRC:.c=.o)

all: shared static

install: install_static install_shared

install_static:
	install libwebsocket.a /usr/local/lib/

install_shared:
	install libwebsocket.so /usr/local/lib/
	ldconfig

static: libwebsocket.a

libwebsocket.a: $(OBJ)
	ar rcs libwebsocket.a $(OBJ)

shared: libwebsocket.so

libwebsocket.so: $(OBJ)
	$(CC) $(LDFLAGS) $^ -lsptl -lssl -lcrypto -lresolv -o $@

.SUFFIXES: .c

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
    
websocket.o: websocket.c websocket.h md5.h sha1.c sha1.h

sptl_webserver.o: sptl_webserver.c sptl_webserver.h

sptl_hybi.o: sptl_hybi.c sptl_hybi.h

sptl_hixie.o: sptl_hixie.c sptl_hixie.h

sptl_base64.o: sptl_base64.c sptl_base64.h

md5.o: md5.c md5.h
	$(CC) -c $(CFLAGS) -o $@ $*.c

sha1.o: sha1.c sha1.h
	$(CC) -c $(CFLAGS) -o $@ $*.c

clean:
	rm -f *.so *.a *.o
