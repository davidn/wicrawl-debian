PLATFORM := $(shell uname)

BINDIR=/usr/local/bin

CFLAGS = -g -Wall -I../include -I.

OBJS = base64.o discovery.o version.o hash.o parse2.o ../util/libutil.a

LDFLAGS = -g

LDLIBS = -lpcap -lpthread -lm

SOURCES = base64.c discovery.c version.c

ifeq ($(PLATFORM), Linux)
        OBJS += linux.o
endif

ifeq ($(PLATFORM), FreeBSD)
        OBJS += freebsd.o
endif

ifeq ($(PLATFORM), Darwin)
        OBJS += darwin.o
endif

all: .deps apcore hashtest

platformcheck:
	@echo PLATFORM = $(PLATFORM)

# Calculate source dependencies.  We include the resulting file at the end.
.deps: *.c
	gcc $(CFLAGS) -MM *.c > .deps

hashtest: hashtest.o

apcore: $(OBJS)
	gcc $(LDFLAGS) $(OBJS) $(LDLIBS) -o apcore

install:
	sudo cp -a apcore $(BINDIR)/

uninstall:
	sudo rm $(BINDIR)/apcore

clean:
	rm -f apcore $(OBJS) ~* .deps hashtest

.PHONY: clean install uninstall

include .deps
