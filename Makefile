PROJECT=router
SOURCES=lib/queue.c lib/list.c lib/lib.c
LIBRARY=nope
INCPATHS=include
LIBPATHS=.
LDFLAGS=
CFLAGS=-c -Wall -Werror -Wno-error=unused-variable
CC=gcc
CPPFILES=router.cpp
CPPFLAGS=-std=c++17

# Automatic generation of object files
OBJECTS=$(SOURCES:.c=.o) router.o
INCFLAGS=$(foreach TMP,$(INCPATHS),-I$(TMP))
LIBFLAGS=$(foreach TMP,$(LIBPATHS),-L$(TMP))

# Binary output
BINARY=$(PROJECT)

all: $(BINARY)

$(BINARY): $(OBJECTS)
	g++ $(LIBFLAGS) $(OBJECTS) $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $(INCFLAGS) $(CFLAGS) -fPIC $< -o $@

%.o: %.cpp
	g++ $(CPPFLAGS) $(INCFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJECTS) $(BINARY) hosts_output router_*

run_router0: all
	./router rtable0.txt rr-0-1 r-0 r-1

run_router1: all
	./router rtable1.txt rr-0-1 r-0 r-1

