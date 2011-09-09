#
# SPTL (Stackable Packet Transport Layers) library makefile
# gygax@practicomp.ch
#

CFLAGS += -Wall -fPIC -I ../ -DHAVE_MEMCPY -DSTDC_HEADERS -DDEBUG
LDFLAGS += -shared

SRC = sptl.c layers.c

OBJ = $(SRC:.c=.o)

all: shared static

install: install_static install_shared

install_static:
	install libsptl.a /usr/local/lib/

install_shared:
	install libsptl.so /usr/local/lib/
	ldconfig

static: libsptl.a

libsptl.a: $(OBJ)
	ar rcs libsptl.a $(OBJ)

shared: libsptl.so

libsptl.so: $(OBJ)
	$(CC) $(LDFLAGS) $^ -o $@

.SUFFIXES: .c

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
    
sptl.o: sptl.c sptl.h

layers.o: layers.c sptl.h sptl_int.h

clean:
	rm -f *.so *.a *.o
