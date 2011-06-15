#
# libwebsockify makefile
#

CFLAGS += -fPIC -I .. -DHAVE_MEMCPY -DSTDC_HEADERS
LDFLAGS += -shared -L../websocket/

SRC = websockify.c

OBJ = $(SRC:.c=.o)

.SUFFIXES: .c

all: shared static

install: install_shared install_static

install_shared:
	install libwebsockify.so /usr/local/lib/
	
install_static:
	install libwebsockify.a /usr/local/lib/
	
shared: libwebsockify.so

static: libwebsockify.a

libwebsockify.so: $(OBJ)
	$(CC) $(LDFLAGS) $^ -lwebsocket -lssl -lcrypto -lresolv -o $@

libwebsockify.a: $(OBJ)
	ar rcs libwebsockify.a $(OBJ)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
    
websockify.o: websockify.c websockify.h

#wswrapper.so: wswrapper.o md5.o
#	$(CC) $(LDFLAGS) $^ -shared -fPIC -ldl -lresolv -o $@

#wswrapper.o: wswrapper.c
#	$(CC) -c $(CFLAGS) -o $@ $*.c

clean:
	rm -f *.a *.so *.o
