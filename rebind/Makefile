TARGETS=rebind.so
CFLAGS += -fPIC

all: $(TARGETS)

install:
	install $(TARGETS) /usr/local/lib/
	
rebind.so: rebind.o
	$(CC) $(LDFLAGS) $^ -shared -fPIC -ldl -o $@

clean:
	rm -f rebind.o rebind.so
