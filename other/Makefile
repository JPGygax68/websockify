TARGETS=websockify
CFLAGS += -I../
LDFLAGS += -L../websockify/ -L../websocket/

all: $(TARGETS)

websockify: main.o
	$(CC) $(CCFLAGS) $(LDFLAGS) $^ -lwebsockify -lwebsocket -o $@

clean:
	rm -f $(TARGETS) *.o

