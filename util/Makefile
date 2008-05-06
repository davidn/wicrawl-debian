BINDIR=/usr/local/bin

CFLAGS = -g -Wall -I../include -I.

OBJS = errlib.o util.o

LDFLAGS = -g

SOURCES = errlib.c util.c

all: .deps libutil.a

# Calculate source dependencies.  We include the resulting file at the end.
.deps: ../include/wicrawl.h
	gcc $(CFLAGS) -MM *.c > .deps

libutil.a: $(OBJS)
	ar r libutil.a $(OBJS)

clean:
	rm -f libutil.a $(OBJS) ~* .deps

.PHONY: clean install uninstall

include .deps
