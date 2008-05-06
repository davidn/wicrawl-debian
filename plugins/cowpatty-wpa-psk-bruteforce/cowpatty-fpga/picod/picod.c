#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libpicod.h"
#include "picod.h"

int verbose = 0;

char device[1024];

void
hexdump(unsigned char *buf, int len)
{
	int i;

	for(i = 0; i < len; i++)
		printf("%02x ", buf[i]);
}

void
handleclient(int c)
{
	int len;
	struct picod_proto_s p;

	while((len = read(c, &p, 8)) >= 8) {
		if(verbose)
			printf("[*] Got cmd: cmd:%02x, addr:%08x, len:%02x\n",
			    p.cmd, (unsigned int)p.addr, p.len);

		switch(p.cmd & 0xf) {
		case PICOD_CMD_NUMCARDS:
			p.num = piconumcards();
			write(c, &p, 8);
			break;
		case PICOD_CMD_READ:
			_picoread(p.cmd & ~0xf, p.num, p.addr, p.buf, p.len);
			write(c, &p, p.len + 8);
			if(verbose) {
				printf("[*] Reading data: ");
				hexdump(p.buf, p.len);
				printf("\n");
			}
			break;
		case PICOD_CMD_WRITE:
			if(read(c, p.buf, p.len) < p.len)
				return;
			if(verbose) {
				printf("[*] Writing data: ");
				hexdump(p.buf, p.len);
				printf("\n");
			}
			_picowrite(p.cmd & ~0xf, p.num, p.addr, p.buf, p.len);
			break;
		case PICOD_CMD_TRYLOCK:
			if(verbose)
				printf("[*] Lock card %d\n", p.num);
			p.buf[0] = picotrylock(p.num);
			p.len = 1;
			write(c, &p, p.len + 8);
			break;
		case PICOD_CMD_UNLOCK:
			if(verbose)
				printf("[*] Unlock card %d\n", p.num);
			p.buf[0] = picounlock(p.num);
			p.len = 1;
			write(c, &p, p.len + 8);
			break;
		case PICOD_CMD_REBOOT:
			if(read(c, p.buf, p.len) < p.len)
				return;
			p.buf[p.len] = 0;
			if(verbose)
				printf("[*] Reboot image %s\n", p.buf);
			p.buf[0] = picoreboot(p.num, (char *)p.buf);
			p.len = 1;
			write(c, &p, p.len + 8);
			break;
		}
	}
}

void
startserver(void)
{
	int s, c;
	struct sockaddr_in sin, cin;
	socklen_t slen;

	if((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("unable to create socket!");
		exit(1);
	}

	sin.sin_port = htons(PICOD_PORT);
	sin.sin_addr.s_addr = INADDR_ANY;
	slen = sizeof(struct sockaddr_in);
	if(bind(s, (struct sockaddr *)&sin, slen) < 0) {
		perror("unable to bind to socket");
		exit(1);
	}

	if(listen(s, 4) < 0) {
		perror("unable to listen on socket");
		exit(1);
	}

	printf("[*] Server started, waiting for connections\n");

	while(1) {
		if((c = accept(s, (struct sockaddr *)&cin, &slen)) < 0) {
			perror("accept failed");
			exit(1);
		}

		printf("[*] Accepted connection from %s:%d\n",
		    inet_ntoa(cin.sin_addr), ntohs(cin.sin_port));
		handleclient(c);
		printf("[*] Connection closed from %s:%d\n",
		    inet_ntoa(cin.sin_addr), ntohs(cin.sin_port));
		close(c);
	}
}

int
main(int argc, char *argv[])
{
	int c;

	while((c = getopt(argc, argv, "v")) > 0) {
		switch(c) {
		case 'v':
			verbose = 1;
			break;
		}
	}

	picoinit(NULL);
	startserver();

	return 0;
}
