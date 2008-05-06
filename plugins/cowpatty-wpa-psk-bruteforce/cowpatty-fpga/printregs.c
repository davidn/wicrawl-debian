#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"
#include "sha1.h"

static FILE *sfh = NULL;
char *fpgafile1, *fpgafile2;
int info = 0;

int
openstate(void)
{
	if(sfh == NULL) {
		if((sfh = fopen(fpgafile1, "w")) == NULL) {
			perror("unable to open fpga file");
			exit(1);
		}
		return 1;
	}

	return 0;
}

void
printinfo(char *passphrase, char *ssid)
{
	if(openstate())
		fprintf(sfh, "%s\n", ssid);
	fprintf(sfh, "%s\n", passphrase);
	fflush(sfh);
	info = 1;
}

void
printstate(SHA1_CACHE *cache, unsigned long count, unsigned char *digest)
{
	SHA1_CTX *ictx, *octx, *dctx;
	openstate();
	ictx = (SHA1_CTX *)cache->k_ipad;
	octx = (SHA1_CTX *)cache->k_opad;
	dctx = (SHA1_CTX *)digest;
	if(info == 1) {
		fprintf(sfh, "%08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
		    ictx->h0, ictx->h1, ictx->h2, ictx->h3, ictx->h4,
		    octx->h0, octx->h1, octx->h2, octx->h3, octx->h4);
		info = 0;
	}
	fprintf(sfh, "%ld %08x %08x %08x %08x %08x\n", count,
	    dctx->h0, dctx->h1, dctx->h2, dctx->h3, dctx->h4);
	fflush(sfh);
}
