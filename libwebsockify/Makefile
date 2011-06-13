CFLAGS += -fPIC -I . -DHAVE_MEMCPY -DSTDC_HEADERS

SRC = src/websockify.c src/websocket.c src/md5.c

OBJ = $(SRC:.c=.o)

OUT = ../lib/libwebsockify.a

all: $(SRC)

$(OUT): $(OBJ)
	ar rcs $(OUT) $(OBJ)
    
.SUFFIXES: .c

all: $(OUT)

libwebsockify: websockify.o websocket.o md5.o
	$(CC) $(LDFLAGS) $^ -lssl -lcrypto -lresolv -o $@

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
    
websocket.o: websocket.c websocket.h md5.h

websockify.o: websockify.c websocket.h

md5.o: md5.c md5.h
	$(CC) -c $(CFLAGS) -o $@ $*.c

wswrapper.o: wswrapper.h
wswrapper.so: wswrapper.o md5.o
	$(CC) $(LDFLAGS) $^ -shared -fPIC -ldl -lresolv -o $@

wswrapper.o: wswrapper.c
	$(CC) -c $(CFLAGS) -o $@ $*.c

clean:
	rm -f websockify wswrapper.so *.o

