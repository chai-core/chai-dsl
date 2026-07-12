# Build the C++ client sample. Needs libcurl (curl-config on PATH).
CXXFLAGS += -Wall -Wextra -std=c++17 $(shell curl-config --cflags)
LDLIBS += $(shell curl-config --libs)

chai_cpp_demo: example.cpp chai_client.hpp
	$(CXX) $(CXXFLAGS) example.cpp $(LDLIBS) -o $@

.PHONY: run clean
run: chai_cpp_demo
	./chai_cpp_demo

clean:
	rm -f chai_cpp_demo
