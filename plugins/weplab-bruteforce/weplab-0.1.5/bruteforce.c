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

	bruteforce.c: dictionary based wep crack.
*/

#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "globals.h"
#include "debug.h"
#include "bruteforce.h"
#include "wep.h"

unsigned long int totalTests=0;
short nTotalTests=0;
t_bruteforceKey key;
time_t initialTime;
time_t lastTime;
time_t actualTime;

pid_t arrayProcesses[64];
int currentProcessNumber=0;

unsigned char finalByte=0xFF;
unsigned char initByte=0x00;

short IncrementKey(t_bruteforceKey *key){
	int i;
	for (i=0; i<global_v.key_len; i++) {
		if (key->logicalStatus[i]==key->keyspace[i].total-1){
			key->logicalStatus[i]=0;
			key->key[i]=key->keyspace[i].values[key->logicalStatus[i]];
		}else{
			key->logicalStatus[i]++;
			key->key[i]=key->keyspace[i].values[key->logicalStatus[i]];
			break;
		}
	}
	//for (i=0; i<global_v.key_len; i++) key->key[i]=key->keyspace[i].values[key->logicalStatus[i]];
	if (i==global_v.key_len && key->logicalStatus[i]==0) return 1;
	return 0;
}

inline void IncrementKeyOptimized(t_bruteforceKey *key){
	register int i;
	for (i=0; i<global_v.key_len; i++) {
		if (!i && key->byte0IntValue+global_v.processes>finalByte){  
			key->key[i]=initByte+currentProcessNumber;
			key->byte0IntValue=key->key[i];
		}else if (i && key->key[i]==finalByte){
			key->key[i]=initByte;
		  if (i==(global_v.key_len-1)) {
		    /* We have already covered the whole keyspace so we can show statistics and quit */
	           	printf(" => Process %u finished!\n",currentProcessNumber); 
			kill(getpid(), SIGUSR1);
		    //exit(1);
		  }			
		}else{
			if (!i){
				//key->key[i]+=global_v.processes;
				key->byte0IntValue+=global_v.processes;
			 	key->key[i]=key->byte0IntValue;	
				break;
			}else{
				if (!key->key[i]) {
					if (!initByte) key->key[i]=initByte+1;
					else key->key[i]=initByte;
				}else key->key[i]++;
				break;
			}
		}
	}
//printf("Process %u: ",currentProcessNumber);
//ViewKey (key->key,global_v.key_len);
}


void catch_int(int sig_num){
	int i;
	if (!currentProcessNumber) for (i=1; i<global_v.processes; i++) kill(arrayProcesses[i],SIGUSR1);
	signal(SIGUSR1, catch_int);
	actualTime=time(NULL);
	printf("Process number: %u ===>",currentProcessNumber);
	if (!nTotalTests) printf(" %lu keys tested [",totalTests);
	else printf(" %d * %lu keys tested [",nTotalTests, totalTests);
	if (actualTime-lastTime) printf("%lu c/s] >>> ",(unsigned long int)totalTests/(actualTime-lastTime));
	ViewKey (key.key,global_v.key_len);
	
}

void bruteforce (void){
	t_storedPacket *packets[10];
	pcap_t *file;
	pid_t mpid;
	int i;
	int j;
	int c;
	int totalPackets;
	//unsigned char key2[13]="\x3e\x9a\xa0\xa4\xc6\x2e\xad\x59\x5a\x07\xa1\x80\x1f";
	int trues;
	int totalTemp=0;
	
	#ifdef _DEBUG
	debug("Starting bruteforce based cracking.");
	#endif
	
	file=OpenPcapFile(global_v.packetsFilename);	

	signal(SIGUSR1, SIG_IGN);
	
	for (i=0; i<10; i++) {
		packets[i]=malloc(sizeof(t_storedPacket));
		packets[i]->packet=NULL;
	}

	totalPackets=GetLessSizedPackets(file, packets);
	DebugView10Packets(packets, totalPackets);
	ClosePcapFile(file);

	initByte=0;
	if (global_v.ascii) {
		finalByte=0x7F; 
		printf(" => Ascii mode selected. Only values from 0x00 to 0x7F will be tested\n\n");
	}
	else finalByte=0xFF;
	if (global_v.alpha) {
		finalByte=0x7A; 
		printf(" => Alpha mode selected. Only values from 0x41 to 0x7A will be tested\n\n");
		initByte=0x41;	
	}

	if (global_v.alnum) {
		finalByte=0x7A;
		initByte=0x30;
		printf(" => Alphanumeric mode selected. Only values from 0x30 to 0x7A will be tested\n\n");
	}


	for (i=0; i<global_v.key_len; i++) key.key[i]=0;

	currentProcessNumber=0;		
	
	// Here I start creating processes
	for (i=0; i<global_v.processes-1 && mpid; i++){
		mpid=fork();		
		currentProcessNumber++;		
		if (mpid) arrayProcesses[currentProcessNumber]=mpid;		
	}
	
	if (mpid) currentProcessNumber=0;

	debug("Launched process number %u",currentProcessNumber);

	
	for (i=0; i<global_v.key_len-1; i++){
		for (j=initByte; j<=finalByte-initByte; j++) key.keyspace[i].values[j]=j;
		key.keyspace[i].total=finalByte-initByte;
		key.logicalStatus[i]=0;
	}
	
	//Ahora relleno de acorde con el proceso actual
	for (j=0; j<=finalByte-initByte; j++){
		if (j%global_v.processes==currentProcessNumber){
			key.keyspace[global_v.key_len-1].values[totalTemp]=j;
			totalTemp++;		
		}	
	}
	key.keyspace[global_v.key_len-1].total=totalTemp;
	key.logicalStatus[global_v.key_len-1]=0;
	//key.key[global_v.key_len-1]=key.keyspace[global_v.key_len-1].values[0];

	key.byte0IntValue=initByte+currentProcessNumber-global_v.processes;
	key.key[0]=key.byte0IntValue;

// TEST
	initialTime=time(NULL);
	lastTime=time(NULL);
	if (!currentProcessNumber) mpid=fork();
	else mpid=0;
	if (!(mpid)){	
		signal(SIGUSR1, catch_int);
		printf("Bruteforce started! Please hit enter to get statistics.\n");
		fflush(stdout);
		while (1){
			IncrementKeyOptimized(&key);		
			// IncrementKey(&key);		
			
			if (!++totalTests){
				lastTime=time(NULL);
				nTotalTests++;	
			}
			if (VerifyPacketWithKey(packets[0],key.key)){
				printf("It seems that the first control data packet verifies the key! Let's test it with others....\n");
				if (Verify10PacketsWithKey(packets, key.key)>2){
					printf("Right KEY found!!\n");
					ViewKey(key.key,global_v.key_len);	
					fflush(stdout);
					exit(1);
				}
			}
		}
	}else{
		arrayProcesses[0]=mpid;		
		while (!waitpid(0,NULL,WNOHANG)) {
			c=getchar();
			if (c=='\n') kill(mpid,SIGUSR1);
		}	
		
	}
// END TEST


	trues=Verify10PacketsWithKey(packets, key.key);
	if (trues) printf("HURRA! %d packets verified the key!",trues);
	fflush(stdout);	
	
}



