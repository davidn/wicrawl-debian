/*

	weplab - Wep Key Cracker

	Copyright (C) 2004 Jose Ignacio Sanchez Martin - Topo[LB]

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2, or (at your option)
	any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software Foundation,
	Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  

	---------

	main.c: application entry point.

*/


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#define _GNU_SOURCE
#include <getopt.h>

#include <pcap.h>
#include "globals.h"
#include "debug.h"
#include "dictionary.h"
#include "bruteforce.h"
#include "heuristics.h"
#include "analpfile.h"
#include "capture.h"
#include "attack.h"

void ShowVersion(void){
	printf("\n%s\n\n",PROGRAM_VERSION);
	exit(0);
}

void ShowBanner(void){
        printf("%s Wep Key Cracker (%s).\n%s\n\n",PROGRAM_NAME, PROGRAM_VERSION, PROGRAM_AUTHOR);
}

void SimpleUsageMsg(char *programName){
	ShowBanner();
	printf("Usage: %s [-a|-b|-r|-y|-c] [-k <keylength>] [extended options] <pcap file>\n", programName);
	printf("  Modes:\n");
  printf("    -a	analyze pcap file and show information\n");
  printf("    -y	uses words (from stdin or wordfile) as wep keys\n");
  printf("    -b	brute forces wep keys\n");
  printf("    -r	uses statistical attacks to break the key\n");
  printf("    -c	capture encrypted data packets from a wireless interface\n");
  printf("    -k [64|128]	specifies 128 or 64 bits (default) key\n");
	printf("    -h, --help	display help about extended options\n");
	printf("\n");
	exit(1);
}

void UsageMsg(char *programName){
	ShowBanner();
	printf("Usage: %s [OPTIONS]... FILE\n", programName);
	printf("  Options:\n");
    printf("    --debug	<debuglevel>	prints debug information\n");
    printf("    -v, --verbose	print more information\n");
    printf("    -y, --dictionary <file>	uses words (from stdin) as wep keys\n");
    printf("    -k, --key [64|128]	specifies 128 or 64 bits (default) key\n");
    printf("    -b, --bruteforce <file>	brute forces wep keys\n");
    printf("    -c, --capture 	capture encrypted data packets\n");
    printf("    -i, --interface 	for capturing packets with --capture \n");
    printf("    -r, --heuristics file	uses weak keys and intelligent bruteforce\n");
    printf("    -a, --analysis 	analyze file and get lite statistics\n");
    printf("    -m, --multiprocess <number> Assume <number> of processes. Number must be between 1-64. Default 1.\n");
    printf("    --caplen <length>	maximun length of captured packets with --capture (default 80) \n");
    printf("    --fcs	assume all captured frames has the FCS field\n");
    printf("    --keyid <id>	just analyze specific id Wep packets. Only for 64 bits keys. (default 0)\n");
    printf("    --prismheader	assume all captured frames has the Prism header\n");
    printf("    --allow_dups	do not control packets with duplicated IVs\n");
    printf("    --perc <number>	uses this minimun percentage of succeed when using FMS cracking\n");
    printf("    --wordfile <file>	instead of reading words from stdin it uses this text file as wordfile for the dictionary attack\n");
    printf("    --ascii	just use bytes 0x00-0x7F for bruteforce wep key with --bruteforce\n");
    printf("    --alpha	just use bytes 0x41-0x7A for bruteforce wep key with --bruteforce\n");
    printf("    --alnum	just use bytes 0x30-0x7A for bruteforce wep key with --bruteforce\n");
    printf("    --stability	selects level of stability. Another way to specify which attacks, depending on their stability level, will be launched\n");
    printf("    --debugkey <key>	Gives the real wep key to weplab to gather information about a crack. <key> must be in the form of AA:BB:CC:DD... and may be incomplete.\n");
    printf("    --attacks <number1,number2,...> 	allows you to select which attacks will be used for heuristic mode.\n");
    printf("    --bssid <MAC> 	does only process those packets that belongs to specified BSSID\n");        
	printf("    -h, --help		display this help and exit\n");
	printf("    -V, --version	output version information and exit\n");
	printf("\n");
	exit(1);
}

void ShowHelp(void){
	char programName[2048];
	sprintf(programName,"%s %s",PROGRAM_NAME, PROGRAM_VERSION);
	UsageMsg(programName);
}

void QuitParameterError(char *error){
	printf("\n ERROR:");
	printf(error);
	printf("\n\n Maybe you should take a look at the extended options (--help), read the manual (README) or visit the website http://weplab.sourceforge.net\n\n\n");
	exit(1);	
}


int hex2int(char buffer){
	if (buffer=='0') return 0;
	else  if (buffer=='1') return 1;
	else  if (buffer=='2') return 2;
	else  if (buffer=='3') return 3;
	else  if (buffer=='4') return 4;
	else  if (buffer=='5') return 5;
	else  if (buffer=='6') return 6;
	else  if (buffer=='7') return 7;
	else  if (buffer=='8') return 8;
	else  if (buffer=='9') return 9;
	else  if (buffer=='A' || buffer=='a') return 10;
	else  if (buffer=='B' || buffer=='b') return 11;
	else  if (buffer=='C' || buffer=='c') return 12;
	else  if (buffer=='D' || buffer=='d') return 13;
	else  if (buffer=='E' || buffer=='e') return 14;
	else  if (buffer=='F' || buffer=='f') return 15;
	else return 20;	
}

int ReadHexByteArray(unsigned char *asciiByteArray, unsigned char *destination, int asciiByteArrayMaxSize){
	int i,j;
	int total=0;
	unsigned char h1, h2;
	for (i=0; asciiByteArray[i]!=0 && asciiByteArray[i+1]!=0 && i<asciiByteArrayMaxSize; i+=3){
		total++;
		h1=hex2int(asciiByteArray[i]);
		h2=hex2int(asciiByteArray[i+1]);
		if (h1==20 || h2==20) return 0;
		destination[total-1]=(h1<<4)|(h2);
		if (asciiByteArray[i+2]!=':' && optarg[i+2]!=0) return 0;
		if (asciiByteArray[i+2]==0) break;
		if (asciiByteArray[i+3]==0) break;
	}
	destination[total]=0;
	return total;
	
}

int main(int argc, char **argv){
	int optionSelected=1; // 2 words, 3 heuristics, 4 bruteforce
	int opt;
	int keySize=64;
	int i,j;
	int sizeaux;
	unsigned char *saux;
	int tmp[6];
	
	struct option long_options[]={
		{"version",0,NULL,'V'},
		{"help",0,NULL,'h'},
		{"debug",1,NULL,'d'},
		{"verbose",0,NULL,'v'},
		{"dictionary",0,NULL,'y'},
		{"capture",0,NULL,'c'},
		{"key",1,NULL,'k'},
		{"interface",1,NULL,'i'},
		{"stability",1,NULL,'s'},
		{"fcs",0,NULL,0},
		{"allow_dups",0,NULL,0},
		{"caplen",1,NULL,0},
		{"keyid",1,NULL,0},		
		{"perc",1,NULL,0},				
		{"multiprocess",1,NULL,'m'},				
		{"prismheader",0,NULL,0},
		{"heuristics",2,NULL,'r'},
		{"ascii",0,NULL,0},
		{"alpha",0,NULL,0},
		{"wordfile",1,NULL,0},
		{"alnum",0,NULL,0},
		{"bruteforce",0,NULL,'b'},
		{"analysis",0,NULL,'a'},
		{"debugkey",1,NULL,0},
		{"attacks",1,NULL,0},
		{"bssid",1,NULL,0},
		{NULL,0,NULL,0}
	};
	int option_index=0;
	int totalArgvParameters=1;
	int h1, h2;

	if (argc<2) SimpleUsageMsg(argv[0]);


	while ((opt = getopt_long(argc, argv,"fpcVvhyabm:s:i:d:k:r::", long_options, &option_index)) != EOF) {
		switch (opt) {
			case 'V':
				totalArgvParameters+=1;
				ShowVersion();
		    	break;
			case 'v':
				totalArgvParameters+=1;
				global_v.verbose=1;	
				break;
			case 'h':
				totalArgvParameters+=1;
				ShowHelp();
				break;
			case 'd':
		 	   totalArgvParameters+=2;
		 	   if (!optarg || optarg[0]=='-' || totalArgvParameters == argc) QuitParameterError("Debug level must be specified as a positive number");
				global_v.debug=atoi(optarg);	
				break;
			case 'a':
				optionSelected*=0;
				totalArgvParameters+=1;	
				break;
			case 'y':
				totalArgvParameters+=1;			
				optionSelected*=2;	
				break;
			case 'r':
				optionSelected*=3;	
				totalArgvParameters+=1;
		 	   if (optarg) {
		 	   	//if (totalArgvParameters < argc-1){
		 	   		strncpy(global_v.weakPcapFilename, optarg, 200);
		 	   		printf("%s\n\n",optarg);
		 	   		//totalArgvParameters+=1;
		 	   	//}
		 	   }	
				break;
			case 'b':
				optionSelected*=4;
				totalArgvParameters+=1;	
				break;
			case 'c':
				optionSelected*=5;
				totalArgvParameters+=1;	
				break;
			case 'k':
				totalArgvParameters+=2;
		 	   if (!optarg || optarg[0]=='-' || totalArgvParameters == argc) QuitParameterError("key length must be either 64 or 128");
				keySize=atoi(optarg);	
				break;
			case 's':
				totalArgvParameters+=2;
		 	  if (!optarg || optarg[0]=='-' || totalArgvParameters == argc) QuitParameterError("stability level must be a positive number from 1 to 5");
		 	  global_v.stability=atoi(optarg)-1;
		 	  	
				break;
			case 'm':
				totalArgvParameters+=2;
		 	   if (!optarg || optarg[0]=='-' || totalArgvParameters == argc) QuitParameterError("number of processes must be defined as a positive number");
				global_v.processes=atoi(optarg);	
				break;
			case 'i':
				totalArgvParameters+=2;
		 	   if (!optarg || optarg[0]=='-' || totalArgvParameters == argc) QuitParameterError("you must specify the interface name");
				strncpy(global_v.device,optarg,20);	
				break;
			case 0:
				if (!strncmp(long_options[option_index].name,"prismheader",50))
				{
					totalArgvParameters+=1;
					global_v.prismHeaderPresent=1;	
				}else if (!strncmp(long_options[option_index].name,"fcs",50)){
					totalArgvParameters+=1;
					global_v.fcsPresent=1;						
				}else if (!strncmp(long_options[option_index].name,"allow_dups",50)){
					totalArgvParameters+=1;
					global_v.allowdups=1;					
				}else if (!strncmp(long_options[option_index].name,"ascii",50)){
					totalArgvParameters+=1;
					global_v.ascii=1;					
				}else if (!strncmp(long_options[option_index].name,"alnum",50)){
					totalArgvParameters+=1;
					global_v.alnum=1;					
				}else if (!strncmp(long_options[option_index].name,"alpha",50)){
					totalArgvParameters+=1;
					global_v.alpha=1;					
				}else if (!strncmp(long_options[option_index].name,"caplen",50)){
					totalArgvParameters+=2;
					if (!optarg || optarg[0]=='-' || totalArgvParameters == argc) QuitParameterError("maximun packet lenght must be defined");
					global_v.caplen=atoi(optarg);
				}else if (!strncmp(long_options[option_index].name,"perc",50)){
					totalArgvParameters+=2;
					if (!optarg || optarg[0]=='-' || totalArgvParameters == argc) QuitParameterError("minimun percentaje of succeed mut be defined as a positive number from 1 to 100");
					global_v.percSucceed=atoi(optarg);
				}else if (!strncmp(long_options[option_index].name,"attacks",50)){
					totalArgvParameters+=2;
					if (!optarg || optarg[0]=='-' || totalArgvParameters == argc) QuitParameterError("you must define which attacks will be launched");
					for (i=0; i<NUMBER_ATTACKS; i++) defaultAttacks[STABILITY_LEVELS][i]=0;
					global_v.totalAttacksSelected=0;
					sizeaux=strlen(optarg);
					if (sizeaux<1) QuitParameterError("you must define which attacks will be launched");
					saux=optarg;
					for (i=1; i<sizeaux+1; i++) if (optarg[i]==',' || optarg[i]==0){
						optarg[i]=0;
						global_v.totalAttacksSelected++;
						if (atoi(saux)>NUMBER_ATTACKS || !atoi(saux)) QuitParameterError("attacks to be launched must be defined as positive numbers from 1 to 5 splitted by commas and no spaces");
						defaultAttacks[STABILITY_LEVELS][atoi(saux)-1]=1;
						global_v.stability=0;
						saux=(&optarg[i])+1;
					}
				}else if (!strncmp(long_options[option_index].name,"keyid",50)){
					totalArgvParameters+=2;
					if (!optarg || optarg[0]=='-' || totalArgvParameters == argc) QuitParameterError("keyid must be a positive number from 1 to 4");
					global_v.keyid=atoi(optarg);
				}else if (!strncmp(long_options[option_index].name,"wordfile",50)){
					totalArgvParameters+=2;
					if (!optarg || optarg[0]=='-' || totalArgvParameters == argc) QuitParameterError("you must specify a file to be used as wordfile");
					strncpy(global_v.wordfile,optarg,255);
				}else if (!strncmp(long_options[option_index].name,"bssid",50)){
					totalArgvParameters+=2;
					if (!optarg || optarg[0]=='-' || totalArgvParameters == argc) QuitParameterError("BSSID must be specified");
					if (sscanf(optarg, "%x:%x:%x:%x:%x:%x", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]) < 6) {
						printf("unable to parse bssid\n");
						exit(2);
					}
					for(i = 0; i < 6; i++) {
						global_v.target_bssid[i] = tmp[i] & 0xff;
					}
					global_v.target_bssid_selected = 1;
				}else if (!strncmp(long_options[option_index].name,"debugkey",50)){
					totalArgvParameters+=2;
					if (!optarg || optarg[0]=='-' || totalArgvParameters == argc) QuitParameterError("debug key must be specified");
					global_v.useDebugKey=ReadHexByteArray(optarg,global_v.debugKey,strlen(optarg)+1);
					if (global_v.useDebugKey==0){
						printf("ERROR: you have to specify the key like AA:BB:CC:DD:EE \n");
						exit (1);	
					}
				}
			
				break;

			default:
				QuitParameterError("ERROR: unknown option.\n\n");
		}
	}
//debug("%u %u %u",option_index,argc,totalArgvParameters);
	if (totalArgvParameters != argc-1){
		QuitParameterError("Take a look at the command line options help.\nPerhaps you have selected two pcap files instead of one.\n\n");
	}

	strncpy(global_v.packetsFilename,argv[totalArgvParameters],200);
	
	if (!strcmp(global_v.weakPcapFilename,"")) strncpy(global_v.weakPcapFilename, global_v.packetsFilename, 200);

	
	
	if (optionSelected==1){
		QuitParameterError("You must select 1 attack: dictionary, heuristics, brute force.\n\n");
	}
	if (optionSelected>5){
		QuitParameterError("You can just select 1 attack: dictionary, heuristics, brute force; or packets capture mode\n\n");
	}
	if (keySize==128) global_v.key_len=13;
	else if (keySize!=64) {
		QuitParameterError("You must specify the key size. Sizes supported in this version: 64, 128\n\n");
	}
	
	if (global_v.stability<0 || global_v.stability>STABILITY_LEVELS-1){
		QuitParameterError("stability level must be between 1 and 5\n\n");
	}
	
	if (global_v.processes<1 && global_v.processes>64){
		QuitParameterError("Number of processors must be between 1 and 64.\n\n");
	}

	ShowBanner();
	#ifdef _DEBUG
	debug("Debug mode initialized");
	debug("Using pcap version %s",pcap_lib_version());
	#endif

	// Initializing S for KSA of rc4
    for(i = 0; i < 256; i++) S_InitialBackup[i] = i;


	if (optionSelected==2) dictionary();
	else if (optionSelected==3) heuristics();
	else if (optionSelected==4) bruteforce();
	else if (optionSelected==5) captureWeakPackets();
	else if (optionSelected==0) AnalyzePcapFile();
	
	#ifdef _DEBUG
	debug("Finishing the program...");
	#endif


	return 0;
}
