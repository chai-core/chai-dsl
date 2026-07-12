# Build the C client sample. Needs libcurl (curl-config on PATH).
CFLAGS += -Wall -Wextra -std=c11 $(shell curl-config --cflags)
LDLIBS += $(shell curl-config --libs)

chai_c_demo: example.c chai_client.c chai_client.h
	$(CC) $(CFLAGS) example.c chai_client.c $(LDLIBS) -o $@

.PHONY: run clean
run: chai_c_demo
	./chai_c_demo

clean:
	rm -f chai_c_demo
