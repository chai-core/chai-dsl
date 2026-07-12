# Build the in-process C++ sample. Needs the cdylib:
#   (from repo root) cargo build --release --features capi
LIBDIR := ../../../target/release
CXXFLAGS += -Wall -Wextra -std=c++17 -I..

inproc: inproc.cpp ../chai.h
	$(CXX) $(CXXFLAGS) inproc.cpp -L$(LIBDIR) -lchai_dsl -Wl,-rpath,$(LIBDIR) -o $@

.PHONY: run clean
run: inproc
	./inproc

clean:
	rm -f inproc
