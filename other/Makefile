TARGETS=websockify #wswrapper.so
CFLAGS += -fPIC -I../libwebsockify/
LDFLAGS += -L../libwebsockify/

all: $(TARGETS)

websockify: main.o
	$(CC) $(CCFLAGS) $(LDFLAGS) $^ -lwebsockify -lssl -lcrypto -lresolv -o $@

clean:
	rm -f websockify wswrapper.so *.o

