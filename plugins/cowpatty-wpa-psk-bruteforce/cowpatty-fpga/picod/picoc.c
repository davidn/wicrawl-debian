#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "picod.h"
#include "libpicoc.h"

void
hexdump(unsigned char *buf, int len)
{
	int i;

	for(i = 0; i < len; i++)
		printf("%02x ", buf[i]);
}

char
hex2dec(unsigned char a)
{
	a |= 0x20;
	if(a >= '0' && a <= '9') return(a - '0');
	if(a >= 'a' && a <= 'f') return((a - 'a') + 10);
	return -1;
}

int
parsehex(unsigned char *str, unsigned char *buf)
{
	int a, alt, len;
	unsigned char *p, *q;

	for(p = str, q = buf, alt = len = 0; *p != '\0'; p++) {
		if((a = hex2dec(*p)) < 0) continue;
		if(++alt & 1)
			*q = a << 4;
		else {
			*q |= a;
			len++; q++;
		}
	}

	return len;
}

void
usage(char *progname)
{
	fprintf(stderr, "usage: %s <ip,ip,...> <n|r|w|l|u|b><a|m|i><num> [<addr> <len|data>]\n", progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	int i = 0, len, card;
	unsigned long addr;
	char *p, *lp, *pa[256];
	unsigned char buf[1024];

	if(argc < 3)
		usage(argv[0]);

	lp = p = argv[1];
	while(1) {
		p = strchr(lp, ',');
		if(p != NULL) *p = '\0';
		pa[i++] = lp;
		if(p == NULL) break;
		lp = p + 1;
	}
	pa[i] = NULL;

	picoinit(pa);

	switch(argv[2][0]) {
	case 'n':
		printf("[*] %d cards\n", piconumcards());
		break;
	case 'r':
		if(argc < 4) usage(argv[0]);
		card = strtoul(argv[2] + 2, NULL, 0);
		addr = strtoul(argv[3], NULL, 0);
		len = strtoul(argv[4], NULL, 0);
		switch(argv[2][1]) {
		case 'a':
			picoattribread(card, addr, buf, len);
			break;
		case 'm':
			picomemread(card, addr, buf, len);
			break;
		case 'i':
			picoioread(card, addr, buf, len);
			break;
		}
		printf("[*] Read %d bytes from 0x%x: ", len, (unsigned int)addr);
		hexdump(buf, len);
		printf("\n");
		break;
	case 'w':
		if(argc < 4) usage(argv[0]);
		card = strtoul(argv[2] + 2, NULL, 0);
		addr = strtoul(argv[3], NULL, 0);
		len = parsehex((unsigned char *)argv[4], buf);
		switch(argv[2][1]) {
		case 'a':
			picoattribwrite(card, addr, buf, len);
			break;
		case 'm':
			picomemwrite(card, addr, buf, len);
			break;
		case 'i':
			picoiowrite(card, addr, buf, len);
			break;
		}
		printf("[*] Wrote %d bytes to 0x%x: ", len, (unsigned int)addr);
		hexdump(buf, len);
		printf("\n");
		break;
	case 'l':
		card = strtoul(argv[2] + 1, NULL, 0);
		printf("[*] Try lock on card %d returned: %d\n", card,
		    picotrylock(card));
		break;
	case 'u':
		card = strtoul(argv[2] + 1, NULL, 0);
		printf("[*] Unlock on card %d returned: %d\n", card,
		    picounlock(card));
		break;
	case 'b':
		card = strtoul(argv[2] + 1, NULL, 0);
		printf("[*] Reboot on card %d image %s returned: %d\n",
		    card, argv[3], picoreboot(card, argv[3]));
		break;
	}

	return 0;
}
