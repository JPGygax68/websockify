#
# webserver library makefile
# gygax@practicomp.ch
#

CFLAGS += -fPIC -I ../ -DHAVE_MEMCPY -DSTDC_HEADERS
LDFLAGS += -shared

SRC = webserver.c

OBJ = $(SRC:.c=.o)

all: shared static

install: install_static install_shared

install_static: static
	install libwebserver.a /usr/local/lib/
	
install_shared: shared
	install libwebserver.so /usr/local/lib/
	ldconfig
	
static: libwebserver.a

libwebserver.a: $(OBJ)
	ar rcs libwebserver.a $(OBJ)
	
shared: libwebserver.so

libwebserver.so: $(OBJ)
	$(CC) $(LDFLAGS) $^ -lssl -lcrypto -lresolv -o $@

.SUFFIXES: .c

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
    
webserver.o: webserver.c webserver.h

clean:
	rm -f *.so *.a *.o
