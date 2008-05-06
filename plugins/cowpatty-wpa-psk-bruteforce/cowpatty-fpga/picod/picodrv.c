#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include "picodrv.h"

#define E14_WINDOW_OFFSET	0x4
#define WINDOW_OFFSET_0         0x216
#define WINDOW_OFFSET_1         0x218
#define WINDOW_OFFSET_2         0x21a
#define IMGSELECT_OFFSET	0x410

extern char *picodev;
extern int piconum;
int e14 = 0;
static int fdi = -1, fdm = -1;
static unsigned long curwin = 0xffffffff;
#define MAX_CARDS 256
int locked[MAX_CARDS];

void
picoinit(void)
{
	int i;
	for(i = 0; i < MAX_CARDS; i++)
		locked[i] = 0;
}

int
picotrylock(int cardno)
{
	if(locked[cardno]) return 1;
	locked[cardno] = 1;
	return 0;
}

int
picounlock(int cardno)
{
	if(!locked[cardno]) return 1;
	locked[cardno] = 0;
	return 0;
}

void
picosetoff(unsigned long off)
{
	unsigned long t0, t;

	if(fdi < 0) {
		lseek(fdm, off, SEEK_SET);
		return;
	} else {
		if(e14)
			lseek(fdm, off & ((1<<16)-1), SEEK_SET);
		else
			lseek(fdm, off & ((1<<11)-1), SEEK_SET);
	}

	if(e14) {
		t = (off >> 16) & 0xffffffff;
		if(curwin == t)
			return;

		t0 = (t << 16) | t;
		lseek(fdi, E14_WINDOW_OFFSET, SEEK_SET);
		write(fdi, &t0, 4);
	} else {
		t = (off >> 11) & 0xffffffff;
		if(curwin == t)
			return;

		t0 = t & 0xff;
		t0 |= (t0 << 8);
		lseek(fdi, WINDOW_OFFSET_0, SEEK_SET);
		write(fdi, &t0, 2);

		t0 = (t >> 8) & 0xff;
		t0 |= (t0 << 8);
		lseek(fdi, WINDOW_OFFSET_1, SEEK_SET);
		write(fdi, &t0, 2);

		t0 = (t >> 16) & 0xff;
		t0 |= (t0 << 8);
		lseek(fdi, WINDOW_OFFSET_2, SEEK_SET);
		write(fdi, &t0, 2);
	}

	curwin = t;
}

int
picoreboot(char *fname)
{
	int i;
	unsigned short ad = 0xadad;
	unsigned char buf[256];

	for(i = 0; i < (1 << 26); i += 0x2000) {
		picoread(i, buf, 2);
		if(memcmp(buf, "Bi", 2) != 0) continue;
		picoread(i + 9, buf, strlen(fname));
		buf[strlen(fname)] = '\0';
		if(memcmp(fname, buf, strlen(fname)) != 0) continue;
		lseek(fdi, IMGSELECT_OFFSET, SEEK_SET);
		write(fdi, &ad, 2);
		usleep(500000);
		picosetoff(i);
		picoread(i, &ad, 2);
		usleep(500000);
		return 1;
	}
	return 0;
}

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

	if(i)
		return i;

	for(i = 0; i < 32; i++) {
		snprintf(buf, BUF_LEN - 1, "/dev/cbmem%ds0", i);
		if(stat(buf, &sb) == -1)
			break;
	}

	if(i) e14 = 1;

	return i;
}

void
picoopen(void)
{
	char str[64];
	unsigned long word = 0;

	if(fdi >= 0 && fdm >= 0)
		return;
	if(picodev == NULL) {
		if(piconum >= 0) {
			snprintf(str, 64, "/dev/pico%dc", piconum);
			if((fdm = open(str, O_RDWR)) < 0) {
				perror("unable to open device");
				exit(2);
			}
			picoread(0, &word, 4);
			if(word == 0xff0e19de) {
//				printf("E-14 detected\n");
				e14 = 1;
			} else
//				printf("E-12 detected\n");
			close(fdm);
			snprintf(str, 64, "/dev/pico%dm", piconum);
			if((fdm = open(str, O_RDWR)) < 0) {
				perror("unable to open device");
				exit(2);
			}
			if(e14)
				snprintf(str, 64, "/dev/pico%di", piconum);
			else
				snprintf(str, 64, "/dev/pico%dc", piconum);
			if((fdi = open(str, O_RDWR)) < 0) {
				perror("unable to open device");
				exit(2);
			}
		}
	} else
		fdm = open(picodev, O_RDWR, 0644);
}

void
picoclose(void)
{
	if(fdi >= 0) {
		close(fdi);
		fdi = -1;
	}
	if(fdm >= 0) {
		close(fdm);
		fdm = -1;
	}
}

int
picoread(unsigned long off, void *buf_, unsigned long len)
{
	unsigned long i;
	unsigned char *buf = (unsigned char *)buf_;

	read(fdm, buf, 2);
	picosetoff(off);
	i = read(fdm, buf, len);
/*
	for(i = 0; i < len; i++) {
		picosetoff(off + i);
		if((i + 2) <= len) {
			read(fdm, buf + i, 2);
			i++;
		} else
			read(fdm, buf + i, 1);
	}
*/
	return i;
}

int
picowrite(unsigned long off, void *buf_, unsigned long len)
{
	unsigned long i;
	unsigned char *buf = (unsigned char *)buf_;

	picosetoff(off);
	i = write(fdm, buf, len);
	return i;
}
