CC = gcc
CFLAGS = -Wall -O2 -funroll-loops
LDFLAGS =

all: picod picoc listflash

picod: libpicod.o picod.o
	$(CC) $(CFLAGS) -o picod libpicod.o picod.o $(LDFLAGS)

picoc: libpicoc.o picoc.o
	$(CC) $(CFLAGS) -o picoc libpicoc.o picoc.o $(LDFLAGS)

listflash: libpicod.o listflash.o
	$(CC) $(CFLAGS) -o listflash libpicod.o listflash.o $(LDFLAGS)


clean:
	rm -f *.o *.core picod picoc listflash
