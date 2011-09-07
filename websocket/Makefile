#
# websocket library makefile
# gygax@practicomp.ch
#

CFLAGS += -Wall -fPIC -I ../ -DHAVE_MEMCPY -DSTDC_HEADERS -DDEBUG
LDFLAGS += -shared

SRC = websocket.c md5.c sha1.c

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
	$(CC) $(LDFLAGS) $^ -lssl -lcrypto -lresolv -o $@

.SUFFIXES: .c

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
    
websocket.o: websocket.c websocket.h md5.h sha1.c sha1.h

md5.o: md5.c md5.h
	$(CC) -c $(CFLAGS) -o $@ $*.c

sha1.o: sha1.c sha1.h
	$(CC) -c $(CFLAGS) -o $@ $*.c

clean:
	rm -f *.so *.a *.o
