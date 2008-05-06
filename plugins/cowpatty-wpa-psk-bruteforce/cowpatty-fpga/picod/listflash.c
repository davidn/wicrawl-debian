#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "libpicoc.h"

int
main(int argc, char *argv[])
{
	int i, card;
	unsigned char buf[256], *p;

	if(argc < 2) {
		fprintf(stderr, "usage: %s <card>\n", argv[0]);
		exit(1);
	}
	card = strtoul(argv[1], NULL, 0);

	picoinit(NULL);
	for(i = 0; i < (1 << 26); i += 0x2000) {
		picomemread(card, i, buf, 2);

		if(memcmp(buf, "Bi", 2) != 0)
			continue;

		picomemread(card, i + 9, buf, 64);

		if((p = (unsigned char *)strchr((char *)buf, '(')) == NULL)
			continue;

		*p = '\0';
		printf("%lx %s\n", i / 0x2000, buf);
	}

	return 0;
}
