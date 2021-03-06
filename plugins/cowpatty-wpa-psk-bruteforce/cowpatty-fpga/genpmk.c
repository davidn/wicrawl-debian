/*
 * genpmk - Generate a file with precomputed PMK's and words
 *
 * Copyright (c) 2005, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: genpmk.c,v 1.1 2007-08-04 07:26:09 sith Exp $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * coWPAtty is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pcap.h>
#include <signal.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

#include "cowpatty.h"
#include "common.h"
#include "utils.h"
#include "sha1.h"

#define PROGNAME "genpmk"
#define VER "1.0"

#ifdef FPGA
extern int usefpga;
char *picodev;
int piconum;
void finishreg(void);
void initfpga(void);
#endif

/* Globals */
int sig = 0;			/* Used for handling signals */
char *words;

/* Prototypes */
void usage(char *message);
int nextword(char *word, FILE * fp);

void usage(char *message)
{

	if (strlen(message) > 0) {
		printf("%s: %s\n", PROGNAME, message);
	}

	printf("Usage: %s [options]\n", PROGNAME);
	printf("\n"
	       "\t-f \tDictionary file\n"
	       "\t-d \tOutput hash file\n"
	       "\t-s \tNetwork SSID\n"
#ifdef FPGA
	       "\t-F card\tUse FPGA acceleration\n"
#endif
	       "\t-h \tPrint this help information and exit\n"
	       "\t-v \tPrint verbose information (more -v for more verbosity)\n"
	       "\t-V \tPrint program version and exit\n" "\n");
	printf("After precomputing the hash file, run cowpatty with the -d "
		"argument.\n");
}

void cleanup()
{
	/* lame-o-meter++ */
	sig = 1;
}


int nextword(char *word, FILE * fp)
{

	if (fgets(word, MAXPASSLEN + 1, fp) == NULL) {
		return (-1);
	}

	/* Remove newline */
	word[strlen(word) - 1] = '\0';

	if(word[strlen(word) - 1] == '\x0d')
		word[strlen(word) - 1] = '\0';

	if (feof(fp)) {
		return (-1);
	}

	return (strlen(word));
}

#ifdef FPGA
struct user_opt *opt_g;
FILE *fpout_g;
#endif

int main(int argc, char **argv)
{
	int fret = 0, c, ret;
	unsigned long int wordstested=0;
	float elapsed = 0;
	char passphrase[MAXPASSLEN + 1];
	struct user_opt opt;
	struct hashdb_head hf_header;
	struct hashdb_rec  rec;
	struct stat teststat;
	FILE *fpin = NULL, *fpout = NULL;
	struct timeval start, end;
	u8 pmk[32];

	printf("%s %s - WPA-PSK precomputation attack. <jwright@hasborg.com>\n",
	       PROGNAME, VER);

	memset(&opt, 0, sizeof(opt));
	memset(&hf_header, 0, sizeof(hf_header));

	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);
	signal(SIGQUIT, cleanup);

	/* Collect and test command-line arguments */
#ifdef FPGA
	while ((c = getopt(argc, argv, "f:d:s:F:hvV")) != EOF) {
#else
	while ((c = getopt(argc, argv, "f:d:s:hvV")) != EOF) {
#endif
		switch(c) {
		case 'f':
			strncpy(opt.dictfile, optarg, sizeof(opt.dictfile));
			break;
		case 'd':
			strncpy(opt.hashfile, optarg, sizeof(opt.hashfile));
			break;
		case 's':
			strncpy(opt.ssid, optarg, sizeof(opt.ssid));
			break;
#ifdef FPGA
		case 'F':
			usefpga = 1;
			picodev = NULL;
			piconum = atoi(optarg);
			break;
#endif
		case 'h':
			usage("");
			exit(0);
		case 'v':
			opt.verbose++;
			break;
		case 'V':
			printf("$Id: genpmk.c,v 1.1 2007-08-04 07:26:09 sith Exp $\n");
			exit(0);
		}
	}

	if (IsBlank(opt.dictfile)) {
		usage("Must specify a dictionary file with -f");
		exit(1);
	}

	if (IsBlank(opt.hashfile)) {
		usage("Must specify an output hasfile with -d");
		exit(1);
	}

	if (IsBlank(opt.ssid)) {
		usage("Must specify a SSID with -s");
		exit(1);
	}

	/* Open the dictionary file */
	if (*opt.dictfile == '-') {
		printf("Using STDIN for words.\n");
		fpin = stdin;
	} else {
		fpin = fopen(opt.dictfile, "r");
		if (fpin == NULL) {
			perror("fopen");
			exit(-1);
		}
	}


	/* stat the hashfile, if it exists, print a message and check to
	   ensure specified SSID matches header information.  If so, append
	   new words to the end of the hashdb file.
	   If the file does not exist, populate the hashdb_head record and
	   create the file. */
	ret = stat(opt.hashfile, &teststat);
	if (errno == ENOENT || teststat.st_size == 0) {
		/* File does not exist or is empty, populate header and 
		   create */
		printf("File %s does not exist, creating.\n", opt.hashfile);
		memcpy(hf_header.ssid, opt.ssid, strlen(opt.ssid));
		hf_header.ssidlen = strlen(opt.ssid);
		hf_header.magic = GENPMKMAGIC;

		fpout = fopen(opt.hashfile, "wb");
		if (fpout == NULL) {
			perror("fopen");
			exit(-1);
		}

		if (fwrite(&hf_header, sizeof(hf_header), 1, fpout) != 1) {
			perror("fwrite");
			exit(-1);
		}

	} else {

		/* File does exist, append to EOF after matching SSID */
		fpout = fopen(opt.hashfile, "r+b");
		if (fpout == NULL) {
			perror("fopen");
			exit(-1);
		}

		if (fread(&hf_header, sizeof(hf_header), 1, fpout) != 1) {
			perror("fread");
			exit(-1);
		}

		fclose(fpout);

		if (memcmp(opt.ssid, hf_header.ssid, hf_header.ssidlen) != 0) {
			fprintf(stderr, "Specified SSID \"%s\" and the SSID in "
				"the output file (\"%s\") do not match.\nCreate"
				" a new file, or change SSID to match.\n",
				opt.ssid, hf_header.ssid);
			exit(-1);
		}
		
		printf("File %s exists, appending new data.\n", opt.hashfile);
		fopen(opt.hashfile, "ab");
		if (fopen == NULL) {
			perror("fopen");
			exit(-1);
		}
	}



	/* Populate capdata struct */

	gettimeofday(&start, 0);

#ifdef FPGA
	opt_g = &opt;
	fpout_g = fpout;
	if(usefpga)
		initfpga();
#endif

	while (feof(fpin) == 0 && sig == 0) {

		/* Populate "passphrase" with the next word */
		fret = nextword(passphrase, fpin);
		if (fret < 0) {
			break;
		}

		if (opt.verbose > 1) {
			printf("Testing passphrase: %s\n", passphrase);
		}

		/*
		 * Test length of word.  IEEE 802.11i indicates the passphrase must be
		 * at least 8 characters in length, and no more than 63 characters in
		 * length. 
		 */
		if (fret < 8 || fret > 63) {
			if (opt.verbose) {
				printf("Invalid passphrase length: %s (%d).\n",
				       passphrase, strlen(passphrase));
			}
			continue;
		} else {
			/* This word is good, increment the words tested counter */
			wordstested++;
		}

		/* Status display */
#ifdef FPGA
		if ((wordstested % 100) == 0) {
#else
		if ((wordstested % 1000) == 0) {
#endif
			printf("key no. %ld: %s\n", wordstested, passphrase);
			fflush(stdout);
		}

		if (opt.verbose > 1) {
			printf("Calculating PMK for \"%s\".\n", passphrase);
		}
		pbkdf2_sha1(passphrase, opt.ssid, strlen(opt.ssid), 4096,
			    pmk, sizeof(pmk), USECACHED);
#ifdef FPGA
		if(!usefpga) {
#endif
		if (opt.verbose > 2) {
			printf("PMK is");
			lamont_hdump(pmk, sizeof(pmk));
		}

		/* Populate record with PMK and record length */
		memcpy(rec.pmk, pmk, sizeof(pmk));
		rec.rec_size = (strlen(passphrase) + sizeof(rec.rec_size) +
			sizeof(rec.pmk));

		/* Write the record contents to the file */
		fwrite(&rec.rec_size, sizeof(rec.rec_size), 1, fpout);
		fwrite(passphrase, strlen(passphrase), 1, fpout);
		fwrite(rec.pmk, sizeof(rec.pmk), 1, fpout);
#ifdef FPGA
	}
#endif
	}

#ifdef FPGA
	if(usefpga) {
		printf("waiting..."); fflush(stdout);
		finishreg();
		printf("\ndone\n");
	}
#endif

	fclose(fpin);
	fclose(fpout);

	gettimeofday(&end, 0);

	/* print time elapsed */
	if (end.tv_usec < start.tv_usec) {
		end.tv_sec -= 1;
		end.tv_usec += 1000000;
	}
	end.tv_sec -= start.tv_sec;
	end.tv_usec -= start.tv_usec;
	elapsed = end.tv_sec + end.tv_usec / 1000000.0;

	printf("\n%lu passphrases tested in %.2f seconds:  %.2f passphrases/"
		"second\n", wordstested, elapsed, wordstested / elapsed);

	return (0);
}

#ifdef FPGA
int
dictfile_found(unsigned char *pmk, char *passphrase)
{
	struct hashdb_rec  rec;

	if (opt_g->verbose > 2) {
		printf("PMK is");
		lamont_hdump(pmk, sizeof(pmk));
	}

	/* Populate record with PMK and record length */
	memcpy(rec.pmk, pmk, sizeof(rec.pmk));
	rec.rec_size = (strlen(passphrase) + sizeof(rec.rec_size) +
	    sizeof(rec.pmk));

	/* Write the record contents to the file */
	fwrite(&rec.rec_size, sizeof(rec.rec_size), 1, fpout_g);
	fwrite(passphrase, strlen(passphrase), 1, fpout_g);
	fwrite(rec.pmk, sizeof(rec.pmk), 1, fpout_g);

	return 1;
}
#endif
