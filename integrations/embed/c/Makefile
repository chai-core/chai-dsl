# Build the in-process C sample. Needs the cdylib:
#   (from repo root) cargo build --release --features capi
LIBDIR := ../../../target/release
CFLAGS += -Wall -Wextra -std=c11 -I..

inproc: inproc.c ../chai.h
	$(CC) $(CFLAGS) inproc.c -L$(LIBDIR) -lchai_dsl -Wl,-rpath,$(LIBDIR) -o $@

.PHONY: run clean
run: inproc
	./inproc

clean:
	rm -f inproc
