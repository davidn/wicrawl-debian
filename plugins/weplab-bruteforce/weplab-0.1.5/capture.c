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

	capture.c: wep capture packets
*/

#include <pcap.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "globals.h"
#include "capture.h"
#include "wep.h"
#include "debug.h"

unsigned long countCapturedWeakPackets = 0;
unsigned long countCapturedUniqWeakPackets = 0;
#define MIN_PKT_LEN	60
unsigned char *capturedWeakPacketsTable;
unsigned long countCapturedPackets = 0;
time_t lastTime;
time_t actualTime;

/* callback function that is passed to pcap_loop(..) and called each time 
 * a packet is recieved                                                    */
void callbackWeakPackets(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	static t_wi_frame *wi_h; 
	unsigned char *iv;
	unsigned int tmp;
	unsigned char *pkt;
	
	countCapturedPackets++;
	
	pkt=(unsigned char *) pkt_data;
	
	if (global_v.prismHeaderPresent) pkt+=144;
	wi_h=(t_wi_frame *)pkt;
	
	if (header->caplen<MIN_PKT_LEN){
		if (global_v.debug>1) debug("Packet %u (%u size) is smaller than %u\n",countCapturedPackets, header->caplen, MIN_PKT_LEN);
	}else if(!(wi_h->wi_frame_ctl_1&0x08)){
		if (global_v.debug>1) debug("Packet %u is not a DATA type packet",countCapturedPackets);	
	}else
	{
		if (((*(((unsigned char *)wi_h)+1))&0xC0)==0xC0) iv=pkt+sizeof(t_wi_frame)+6;
		else iv=pkt+sizeof(t_wi_frame);

		if (global_v.debug>1){ 
			debug("Packet %u",countCapturedPackets);
			debug("---------------------------------------------");
			DebugViewPacketHeaders(pkt);
			debug("Key ID: %u",(unsigned int)iv[3]);			
			debug("Pcap Len: %u",header->caplen);			
			debug("---------------------------------------------\n");
		}
		countCapturedWeakPackets++;

		if (((*(((unsigned char *)wi_h)+1))&0xC0)==0xC0) iv=pkt+sizeof(t_wi_frame)+6;
		else iv=pkt+sizeof(t_wi_frame);

		if (global_v.debug>1) DebugViewKey(iv,3);			

		tmp=((unsigned int)(((unsigned int) iv[0]) | (((unsigned int) iv[1]) << 8) | (((unsigned int) iv[2]) << 16)));

		if (!capturedWeakPacketsTable[tmp]){
			capturedWeakPacketsTable[tmp]=0xFF;
			pcap_dump(dumpfile, header, pkt_data);			
			countCapturedUniqWeakPackets++;
		}

	}    

}

void catch_intCaptureWeakPackets(int sig_num){
	signal(SIGUSR1, catch_intCaptureWeakPackets);
	actualTime=time(NULL);
	printf("%lu total packets captured\n",countCapturedPackets);
	printf("%lu wep data packets captured\n",countCapturedWeakPackets);
	printf("%lu unique IV wep data packets captured\n",countCapturedUniqWeakPackets);
	printf("%f%% from total IV space\n",((int) countCapturedUniqWeakPackets)/16777.216);	
	if (actualTime-lastTime) printf("%lu packets/s\n",(unsigned long int)countCapturedWeakPackets/(actualTime-lastTime));
}

#define HUGE_MEM_WEAKPACKETS_SIZE	104000000


void captureWeakPackets(void){
	char errbuf[PCAP_ERRBUF_SIZE]; 
	pcap_t *handle;   
	pid_t mpid;
	pcap_dumper_t *dumpfile;

	capturedWeakPacketsTable=malloc(HUGE_MEM_WEAKPACKETS_SIZE);
	if (!capturedWeakPacketsTable) {
		printf("Error: not enough memmory to allocate %u",HUGE_MEM_WEAKPACKETS_SIZE);	
		exit (-1);
	}

	debug ("Setting the memmory to 0s");
	memset(capturedWeakPacketsTable,0,HUGE_MEM_WEAKPACKETS_SIZE);

	signal(SIGUSR1,SIG_IGN);

	handle = pcap_open_live(global_v.device, global_v.caplen, 1, 0, errbuf);
	if(handle == NULL)
  { 
  	printf("pcap_open_live(): %s\n",errbuf); 
  	exit(1); 
  }

	if (pcap_datalink(handle)!=DLT_IEEE802_11 && pcap_datalink(handle)!=DLT_PRISM_HEADER){
		printf("ERROR: datalink type is not DLT_IEEE802.11 or PRISM_HEADER. Maybe you need to configure monitor mode in your wireless card\n");
		exit(1);
	}
	
	if (pcap_datalink(handle)==DLT_PRISM_HEADER){
		printf("Prismheader detected. Remember to use --prismheader when using this capture file\n");
	}

	dumpfile = pcap_dump_open(handle, global_v.packetsFilename);
  if(dumpfile==NULL){
  	fprintf(stderr,"\nError opening output file %s\n",global_v.packetsFilename);
      exit(1);
  }
  
	printf("\nPacket capture started! Please hit enter to get statistics.\n");
	fflush(stdout);


	lastTime=time(NULL);
	if (!(mpid=fork())){	
		signal(SIGUSR1, catch_intCaptureWeakPackets);
	
		pcap_loop(handle,-1,callbackWeakPackets,(unsigned char *)dumpfile);

		pcap_dump_flush(dumpfile);	
		pcap_dump_close(dumpfile);
		printf("Shuting down sniffer...\n");
		
	}else{
		printf("\n => Press 'q' to stop sniffing\n\n");
		while (!waitpid(0,NULL,WNOHANG)) {
			if (getchar()=='q') break;
			kill(mpid,SIGUSR1);
		}		
		pcap_dump_flush(dumpfile);	
		pcap_dump_close(dumpfile);
		printf("Shuting down sniffer...\n");
	}
pcap_close(handle);
}

void captureWepDataPackets(void){


	printf("Shuting down sniffer...\n");
	
}
