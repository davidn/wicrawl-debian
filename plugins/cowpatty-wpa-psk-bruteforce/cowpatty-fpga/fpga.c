#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include "common.h"
#include "sha1.h"
#include "picod/libpicod.h"

#define FPGA_MAX   256
#define FPGA_CORES 8
#define FPGA_BITS  8
#define CORE_OFF   0x12340000

#define FPGA_DIFF  (FPGA_BITS - (FPGA_CORES - 1))

struct fpga_s {
	int set;
	char passphrase[64];
	unsigned char mac0[20];
} fpga[FPGA_MAX];

int usefpga = 0;
int fpga_read = 0;
extern int sig;
extern int piconum;

int dictfile_found(unsigned char *, char *);

void
initfpga(void)
{
	int i;
	unsigned long t, addr;

	for(i = 0; i < FPGA_MAX; i++) {
		fpga[i].set = 0;
		memset(fpga[i].passphrase, 0, 64);
	}

	picoinit(NULL);
	picoreboot(piconum, "E12LX-CoWPAtty.bit");

	/* reset */
	t = 2;
	picomemwrite(piconum, CORE_OFF | 0x5000, &t, 4);

	t = 0;
	for(i = 0, addr = CORE_OFF | 0x38; i < FPGA_MAX; i++, addr += 0x40) {
		picomemwrite(piconum, addr, &t, 4);
	}

	/* ~reset */
	t = 0;
	picomemwrite(piconum, CORE_OFF | 0x5000, &t, 4);
}

int
swapbytes(unsigned char *to, unsigned char *from, int len)
{
	int i, j;

	for(i = 0; i < len; i += 4) {
		for(j = 0; j < 4; j++)
			to[i + j] = from[i + (3 - j)];
	}

	return len;
}

void
getreg(int idx)
{
	unsigned char mac[20];
	unsigned char pmk[32];

	if(!(idx & 1)) {
		picomemread(piconum, CORE_OFF | (idx << 6) | 0x28, mac, 20);
		memcpy(fpga[idx].mac0, mac, 20);
	} else {
		picomemread(piconum, CORE_OFF | (idx << 6) | 0x28, mac, 20);
		swapbytes(pmk, fpga[idx ^ 1].mac0, 20);
		swapbytes(pmk + 20, mac, 12);
		dictfile_found(pmk, fpga[idx].passphrase);
	}

//	for(i = 0; i < 20; i++)
//		printf("%02x ", mac[i]);
//	printf("\n");

	fpga[idx].set = 0;
}

void
startfpga(void)
{
	unsigned long ctrl, addr = CORE_OFF | 0x5000;

	printf("starting fpga...\n");

	/* reset */
	ctrl = 2;
	picomemwrite(piconum, addr, &ctrl, 4);
	ctrl = 0;
	picomemwrite(piconum, addr, &ctrl, 4);

	/* start */
	ctrl = 1;
	picomemwrite(piconum, addr, &ctrl, 4);
}

int
processing(void)
{
	int i, count = 0;

	for(i = 0; i < FPGA_MAX; i++) {
		if(fpga[i].set)
			count++;
	}

	return count;
}

int
findreg(int idx)
{
	unsigned long t, count = 0;

	if(!fpga_read)
		return idx;

	if(sig)
		return -1;

	while(!sig) {
		picomemread(piconum, CORE_OFF | (idx << 6) | 0x3c, &t, 4);

		if(t != 0xDEADD00D) {
			if((t == 0xCAFEBABE) && fpga_read) {
				getreg(idx);
				break;
			}
			if(!fpga[idx].set)
				break;
		} else
			count++;
		usleep(100);
	}

	return idx;
}

void
finishreg(void)
{
	int idx = 0;

	if(!fpga_read) {
		startfpga();
		fpga_read = 1;
	}

	while(((idx = findreg(idx)) >= 0) && processing()) {
		if(idx == (FPGA_MAX - FPGA_DIFF)) {
			printf("."); fflush(stdout);
			idx = 0;
		} else
			idx++;
	}
}

void
addreg(SHA1_CACHE *cache, unsigned char *digest, char *passphrase)
{
	unsigned long addr;
	SHA1_CTX *ictx, *octx;
	char mac[20];
	static int fpga_idx = 0;

	ictx = (SHA1_CTX *)cache->k_ipad;
	octx = (SHA1_CTX *)cache->k_opad;
	swapbytes((unsigned char *)mac, digest, 20);

	fpga_idx = findreg(fpga_idx);
	if(fpga_idx == -1) {
		printf("fpga_idx == -1\n");
		exit(0);
	}
	addr = CORE_OFF | (fpga_idx << 6);
	addr += picomemwrite(piconum, addr, &ictx->h0, 20);
	addr += picomemwrite(piconum, addr, &octx->h0, 20);
	addr += picomemwrite(piconum, addr, mac, 20);

	memcpy(fpga[fpga_idx].passphrase, passphrase, 64);
	fpga[fpga_idx].set = 1;

	if(fpga_idx == (FPGA_MAX - FPGA_DIFF)) {
		if(!fpga_read) {
			startfpga();
			fpga_read = 1;
		}
		fpga_idx = 0;
	} else if((fpga_idx % FPGA_BITS) == (FPGA_CORES - 1))
		fpga_idx += FPGA_DIFF;
	else	
		fpga_idx++;
}
