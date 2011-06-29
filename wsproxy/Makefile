#
# wsproxy library makefile
#

CFLAGS += -Wall -fPIC -I .. -DHAVE_MEMCPY -DSTDC_HEADERS
LDFLAGS += -shared -L../websocket/

SRC = wsproxy.c

OBJ = $(SRC:.c=.o)

.SUFFIXES: .c

all: shared static

install: install_shared install_static

install_shared:
	install libwsproxy.so /usr/local/lib/
	ldconfig /usr/local/lib/
	
install_static:
	install libwsproxy.a /usr/local/lib/
	
shared: libwsproxy.so

static: libwsproxy.a

libwsproxy.so: $(OBJ)
	$(CC) $(LDFLAGS) $^ -lwebsocket -lssl -lcrypto -lresolv -o $@

libwsproxy.a: $(OBJ)
	ar rcs libwsproxy.a $(OBJ)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
    
wsproxy.o: wsproxy.c wsproxy.h

#wswrapper.so: wswrapper.o md5.o
#	$(CC) $(LDFLAGS) $^ -shared -fPIC -ldl -lresolv -o $@

#wswrapper.o: wswrapper.c
#	$(CC) -c $(CFLAGS) -o $@ $*.c

clean:
	rm -f *.a *.so *.o
