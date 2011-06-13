TARGETS=websockify #wswrapper.so
CFLAGS += -fPIC -I../libwebsockify/
LDFLAGS += -L../lib/

all: $(TARGETS)

websockify: main.o
	$(CC) $(CCFLAGS) $(LDFLAGS) $^ -lwebsockify -lssl -lcrypto -lresolv -o $@

clean:
	rm -f websockify wswrapper.so *.o

