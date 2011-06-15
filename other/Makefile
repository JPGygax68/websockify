TARGETS=websockify
CFLAGS += -I../
LDFLAGS += -L../wsproxy/ -L../websocket/

all: $(TARGETS)

websockify: websockify.o
	$(CC) $(CCFLAGS) $(LDFLAGS) $^ -lwsproxy -lwebsocket -o $@

clean:
	rm -f $(TARGETS) *.o

