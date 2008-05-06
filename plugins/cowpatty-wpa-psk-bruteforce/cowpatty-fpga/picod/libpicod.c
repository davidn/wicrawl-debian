#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#include "picod.h"
#include "libpicoc.h"

#define WINDOW_OFFSET_0         0x216
#define WINDOW_OFFSET_1         0x218
#define WINDOW_OFFSET_2         0x21a
#define IMGSELECT_OFFSET	0x410

#define MAX_CARDS 256
int m_socklen = 0;
int m_sockc[MAX_CARDS];
int m_socka[MAX_CARDS];
int m_locked[MAX_CARDS];
unsigned long m_curwin[MAX_CARDS];
struct flock f;
int uselock = 0;

#define BUF_LEN 1024
int
piconumcards(void)
{
	int i;
	char buf[BUF_LEN];
	struct stat sb;

	for(i = 0; i < 32; i++) {
		snprintf(buf, BUF_LEN - 1, "/dev/mem%dc", i);
		if(stat(buf, &sb) == -1)
			break;
	}

	return i;
}

int
picoinit(char *ips[])
{
	int i;
	for(i = 0; i < MAX_CARDS; i++) {
		m_sockc[i] = -1;
		m_socka[i] = -1;
		m_curwin[i] = 0xffffffff;
	}
	f.l_type = F_WRLCK;
	f.l_start = 0;
	f.l_whence = SEEK_SET;
	f.l_len = 0;
	f.l_pid = getpid();
	return piconumcards();
}

int
_picoopen(int card)
{
	char buf[BUF_LEN];

	if(m_sockc[card] != -1)
		return 1;

	sprintf(buf, "/dev/mem%dc", card);
	if((m_sockc[card] = open(buf, O_RDWR)) < 0) {
		perror("unable to open device");
		exit(2);
	}

	sprintf(buf, "/dev/mem%da", card);
	if((m_socka[card] = open(buf, O_RDWR)) < 0) {
		perror("unable to open device");
		exit(2);
	}

	return 0;
}

void
_picosetoff(int io, int card, unsigned long off)
{
	unsigned long t0, t;

	if(io != PICOD_CMD_MEM) {
		lseek(m_socka[card], off, SEEK_SET);
		return;
	} else
		lseek(m_sockc[card], off & ((1<<11)-1), SEEK_SET);

	t = (off >> 11) & 0xffffffff;
	if(m_curwin[card] == t)
		return;

	t0 = t & 0xff;
	t0 |= (t0 << 8);
	lseek(m_socka[card], WINDOW_OFFSET_0, SEEK_SET);
	write(m_socka[card], &t0, 2);

	t0 = (t >> 8) & 0xff;
	t0 |= (t0 << 8);
	lseek(m_socka[card], WINDOW_OFFSET_1, SEEK_SET);
	write(m_socka[card], &t0, 2);

	t0 = (t >> 16) & 0xff;
	t0 |= (t0 << 8);
	lseek(m_socka[card], WINDOW_OFFSET_2, SEEK_SET);
	write(m_socka[card], &t0, 2);

	m_curwin[card] = t;
}

int
_picoread(int io, int card, unsigned long addr, unsigned char *buf, int len)
{
	_picoopen(card);

	if(io == PICOD_CMD_MEM)
		read(m_sockc[card], buf, 2);

	_picosetoff(io, card, addr);

	return read(io == PICOD_CMD_MEM ? m_sockc[card] : m_socka[card],
	    buf, len);
}

int
picomemread(int card, unsigned long addr, void *buf, int len)
{
	return _picoread(PICOD_CMD_MEM, card, addr, (unsigned char *)buf, len);
}

int
picoattribread(int card, unsigned long addr, void *buf, int len)
{
	return _picoread(PICOD_CMD_ATTR, card, addr, (unsigned char *)buf, len);
}

int
picoioread(int card, unsigned long addr, void *buf, int len)
{
	return _picoread(PICOD_CMD_IO, card, addr, (unsigned char *)buf, len);
}

int
_picowrite(int io, int card, unsigned long addr, unsigned char *buf, int len)
{
	_picoopen(card);
	_picosetoff(io, card, addr);
	return write(io == PICOD_CMD_MEM ? m_sockc[card] : m_socka[card],
	    buf, len);
}

int
picomemwrite(int card, unsigned long addr, void *buf, int len)
{
	return _picowrite(PICOD_CMD_MEM, card, addr, (unsigned char *)buf, len);
}

int
picoattribwrite(int card, unsigned long addr, void *buf, int len)
{
	return _picowrite(PICOD_CMD_ATTR, card, addr, (unsigned char *)buf, len);
}

int
picoiowrite(int card, unsigned long addr, void *buf, int len)
{
	return _picowrite(PICOD_CMD_IO, card, addr, (unsigned char *)buf, len);
}

/* returns 1 if locked, 0 if unlocked */
int
picotrylock(int cardno)
{
	uselock = 1;
	f.l_type = F_WRLCK;
	fcntl(m_socka[cardno], F_SETLKW, &f);
	if(m_locked[cardno]) return 1;
	m_locked[cardno] = 1;
	return 0;
}

/* returns 1 if wasn't locked, returns 0 if unlocked */
int
picounlock(int cardno)
{
	uselock = 1;
	f.l_type = F_UNLCK;
	fcntl(m_socka[cardno], F_SETLKW, &f);
	if(!m_locked[cardno]) return 1;
	m_locked[cardno] = 0;
	return 0;
}

int
picoreboot(int card, char *fname)
{
	int i;
	unsigned short ad = 0xadad;
	unsigned char buf[256];

	for(i = 0; i < (1 << 26); i += 0x2000) {
		picomemread(card, i, buf, 2);
		if(memcmp(buf, "Bi", 2) != 0) continue;
		picomemread(card, i + 9, buf, strlen(fname));
		buf[strlen(fname)] = '\0';
		if(memcmp(fname, buf, strlen(fname)) != 0) continue;
		picoattribwrite(card, IMGSELECT_OFFSET, &ad, 2);
		usleep(100000);
		_picosetoff(PICOD_CMD_MEM, card, i);
		read(m_sockc[card], &ad, 2);
		usleep(100000);
		return 1;
	}
	printf("unable to find bit file!\n");
	exit(0);
	return 0;
}
