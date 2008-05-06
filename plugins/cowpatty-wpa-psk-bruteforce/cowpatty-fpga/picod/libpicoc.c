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

#define MAX_CARDS 256
int m_socklen = 0;
int m_sock[MAX_CARDS];
int m_nums[MAX_CARDS];

int
picoparsenode(struct in_addr *inp, int *num)
{
        int s;
        struct sockaddr_in sin;
        socklen_t slen;
        struct picod_proto_s p;

        if((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                perror("unable to create socket!");
                exit(1);
        }

        sin.sin_family = AF_INET;
        sin.sin_port = htons(PICOD_PORT);
        sin.sin_addr = *inp;
        slen = sizeof(struct sockaddr_in);
        if(connect(s, (struct sockaddr *)&sin, slen) < 0) {
                perror("unable to connect");
                exit(1);
        }

        p.cmd = p.len = p.addr = 0;
        write(s, &p, 8);
        read(s, &p, 8);

        *num = p.num;
        return s;
}

#define BUF_LEN 256
int
picoinit(char *ips[])
{
	char *ip, *_ips[256], buf[BUF_LEN];
	struct in_addr inp;
	int i, s, num, count = 0;
	FILE *fh;

	for(i = 0; i < MAX_CARDS; i++) {
		m_sock[i] = 0;
		m_nums[i] = 0;
	}
	m_socklen = 0;

	if(ips == NULL) {
		ips = _ips;
		if((fh = fopen("/etc/picod.conf", "r")) == NULL) {
			perror("unable to open /etc/picod.conf file");
			exit(1);
		}

		for(i = 0; fgets(buf, BUF_LEN, fh) != NULL; i++)
			ips[i] = buf;
		ips[i] = NULL;
	}

	for(; *ips != NULL; ips++) {
		ip = *ips;
		if(!inet_aton(ip, &inp)) {
			perror("unable to parse ip address");
			exit(1);
		}
		s = picoparsenode(&inp, &num);
		for(i = 0; i < num; i++) {
                        m_sock[m_socklen] = s;
                        m_nums[m_socklen] = i;
                        m_socklen++;
		}
                count++;
	}

	return m_socklen;
}

int
piconumcards(void)
{
	return m_socklen;
}

int
_picoread(int io, int card, unsigned long addr, unsigned char *buf, int len)
{
	struct picod_proto_s p;
	p.cmd = PICOD_CMD_READ | io;
	p.len = len;
	p.addr = addr;
	p.num = m_nums[card];
	write(m_sock[card], &p, 8);
	read(m_sock[card], &p, p.len + 8);
	memcpy(buf, p.buf, p.len);
	return p.len;
}

int
picomemread(int card, unsigned long addr, void *buf, int len)
{
	return _picoread(PICOD_CMD_MEM, card, addr, buf, len);
}

int
picoattribread(int card, unsigned long addr, void *buf, int len)
{
	return _picoread(PICOD_CMD_ATTR, card, addr, buf, len);
}

int
picoioread(int card, unsigned long addr, void *buf, int len)
{
	return _picoread(PICOD_CMD_IO, card, addr, buf, len);
}

int
_picowrite(int io, int card, unsigned long addr, unsigned char *buf, int len)
{
	struct picod_proto_s p;
	p.cmd = PICOD_CMD_WRITE | io;
	p.len = len;
	p.addr = addr;
	p.num = m_nums[card];
	memcpy(p.buf, buf, p.len);
	write(m_sock[card], &p, p.len + 8);
	return p.len;
}

int
picomemwrite(int card, unsigned long addr, void *buf, int len)
{
	return _picowrite(PICOD_CMD_MEM, card, addr, buf, len);
}

int
picoattribwrite(int card, unsigned long addr, void *buf, int len)
{
	return _picowrite(PICOD_CMD_ATTR, card, addr, buf, len);
}

int
picoiowrite(int card, unsigned long addr, void *buf, int len)
{
	return _picowrite(PICOD_CMD_IO, card, addr, buf, len);
}

int
_picolock(int cmd, int card)
{
	struct picod_proto_s p;
	p.cmd = cmd;
	p.len = 0;
	p.addr = 0;
	p.num = m_nums[card];
	write(m_sock[card], &p, 8);
	read(m_sock[card], &p, 9);
	return p.buf[0];
}

int
picotrylock(int card)
{
	return _picolock(PICOD_CMD_TRYLOCK, card);
}

int
picounlock(int card)
{
	return _picolock(PICOD_CMD_UNLOCK, card);
}

int
picoreboot(int card, char *fname)
{
	struct picod_proto_s p;
	p.cmd = PICOD_CMD_REBOOT | PICOD_CMD_MEM;
	p.len = strlen(fname);
	p.addr = 0;
	p.num = m_nums[card];
	memcpy(p.buf, fname, p.len);
	write(m_sock[card], &p, p.len + 8);
	read(m_sock[card], &p, 9);
	return p.buf[0];
}
