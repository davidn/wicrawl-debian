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

	analpfile.c: dictionary based wep crack.
*/

#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "wep.h"
#include "globals.h"
#include "debug.h"
#include "analpfile.h"
#include "heuristics.h"


#define HUGE_MEM_WEAKPACKETS_SIZE	104000000

#define HASHARRAY_SIZE	4096

void AnalyzePcapFile(void){
	t_StoredPacketsIV packetsIV;
	pcap_t *file;
	int i;
	int indexArray=0;

	unsigned long int fileSize=0;
	unsigned long int actualFilePosition;

	unsigned long int perc;
	unsigned long int lastFilePosition=0;
	unsigned char * pkt;
	struct pcap_pkthdr h;
	t_wi_frame *wi_h; 
	unsigned char *iv;
	unsigned long lastProgressPerc=0;

	bssidStat bssidStatArray[HASHARRAY_SIZE];
	unsigned char bssidOriginal[HASHARRAY_SIZE][7];

	unsigned int p_len;
	char bssid[6];

	unsigned char *actual_iv;
	FILE * fileDescriptor;

	// Initialize all array members to 0
	memset(bssidStatArray,0,HASHARRAY_SIZE*sizeof(bssidStat));	
	memset(bssidOriginal,0,HASHARRAY_SIZE*7);

	#ifdef _DEBUG
	debug("Starting pcap file analysis.");
	#endif

	packetsIV.iv=malloc(HUGE_MEM_WEAKPACKETS_SIZE);
	packetsIV.len=0;
	if (!packetsIV.iv) {
		printf("Error: not enough memmory to allocate %u",HUGE_MEM_WEAKPACKETS_SIZE);	
		exit (-1);
	}

	debug ("Setting the memmory to 0s");
	memset(packetsIV.iv,0,HUGE_MEM_WEAKPACKETS_SIZE);
	
	debug ("Opening packet file for reading sample encrypted packets");
	file=OpenPcapFile(global_v.packetsFilename);	

	fileDescriptor=pcap_file(file);
	actualFilePosition=ftell(fileDescriptor);
	fseek(fileDescriptor,0,SEEK_END);
	fileSize=ftell(fileDescriptor);
	fseek(fileDescriptor,actualFilePosition,SEEK_SET);


	perc=fileSize/100;

	while(1)
	{
	if ((pkt = (unsigned char *) pcap_next(file, &h)) == NULL) break;

	if (global_v.prismHeaderPresent){
		if (GetPacketBssid(pkt+144,bssid)){
			indexArray=(unsigned int) ((bssid[0]^bssid[1]+bssid[2]^bssid[3]+bssid[4]^bssid[5])&0x00000FFF);
			if (!bssidOriginal[indexArray][6]){
				bssidOriginal[indexArray][6]=1;
				memcpy(bssidOriginal[indexArray],bssid,6);
			}
		}
		else indexArray=0;
	}else{
		if (GetPacketBssid(pkt,bssid)){
			indexArray=(unsigned char) ((bssid[0]^bssid[1]+bssid[2]^bssid[3]+bssid[4]^bssid[5])&0x00000FFF);
			if (!bssidOriginal[indexArray][6]){
				bssidOriginal[indexArray][6]=1;
				memcpy(bssidOriginal[indexArray],bssid,6);
			}
		}
		else indexArray=0;
	} 

	bssidStatArray[indexArray].totalPackets++;


	actualFilePosition=ftell(fileDescriptor);
	if (actualFilePosition-lastFilePosition>perc) {
		printf("\r %lu %% read",lastProgressPerc++);
		fflush(stdout);
		lastFilePosition=actualFilePosition;
	}

	if (global_v.prismHeaderPresent) {
		if (h.len<144+sizeof(t_wi_frame)) {
			if (global_v.debug>2) debug("Packet %u has negative size with prismheader!! Perhaps you dont need --prismheader");
			bssidStatArray[indexArray].totalPacketsNegativePrismheader++;
			continue;
		}
		p_len=h.len-144;
		pkt+=144;
	} else p_len=h.len;
	
    wi_h=(t_wi_frame *)pkt;

// Here do some sanity checks with the 802.11 header
  
  if (h.len!=h.caplen) bssidStatArray[indexArray].totalPacketsTruncated++;

	if (h.len<144+sizeof(t_wi_frame)) bssidStatArray[indexArray].totalPacketsNegativePrismheader++; 
	
	if(!(wi_h->wi_frame_ctl_1&0x08)) bssidStatArray[indexArray].totalPacketsNonData++;
	else
	{
		//p_len=h.caplen;
		if (((*(((unsigned char *)wi_h)+1))&0xC0)==0xC0) iv=pkt+sizeof(t_wi_frame)+6;
		else iv=pkt+sizeof(t_wi_frame);

		if (global_v.debug>1){ 
			debug("Packet %u",bssidStatArray[0].totalPackets);
			debug("---------------------------------------------");
			DebugViewPacketHeaders(pkt);
			debug("Pcap Len: %u",h.len);
			debug("Key ID: %u",(unsigned int)iv[3]);			
			debug("---------------------------------------------\n");
		}
		bssidStatArray[indexArray].totalValidPackets++;


		if (global_v.debug>1) DebugViewKey(iv,3);			
		actual_iv=packetsIV.iv+((unsigned int)(((unsigned int) iv[0]) | (((unsigned int) iv[1]) << 8) | (((unsigned int) iv[2]) << 16)));
				if (!actual_iv[0]){
					bssidStatArray[indexArray].totalUniqIV++;
				}
		
		if (global_v.fcsPresent) if (iv[p_len-4-1]==0xFF &&iv[p_len-4]==0xFF &&iv[p_len-4+1]==0xFF &&iv[p_len-4+2]==0xFF) bssidStatArray[indexArray].totalPacketsChecksumFF++;
		
		if (!global_v.fcsPresent) if (iv[p_len-1]==0xFF &&iv[p_len]==0xFF &&iv[p_len+1]==0xFF &&iv[p_len+2]==0xFF) bssidStatArray[indexArray].totalPacketsChecksumFF++;
	}

	}
printf("\r                                   \n");



for (i=1; i<256; i++) if (bssidStatArray[i].totalPackets){
	indexArray=(unsigned int) ((bssid[0]^bssid[1]+bssid[2]^bssid[3]+bssid[4]^bssid[5])&0x00000FFF);

	printf(" Statistics for packets that belong to [%02X:%02X:%02X:%02X:%02X:%02X]\n", TOMAC(bssidOriginal[i]));	
	printf("  - Total valid packets read: %lu\n",bssidStatArray[i].totalValidPackets);
	printf("  - Total packets read: %lu\n",bssidStatArray[i].totalPackets);
	printf("  - Total unique IV read: %lu\n",bssidStatArray[i].totalUniqIV);
	printf("  - Total truncated packets read: %lu\n",bssidStatArray[i].totalPacketsTruncated);
	printf("  - Total non-data packets read: %lu\n",bssidStatArray[i].totalPacketsNonData);
	printf("  - Total FF checksum packets read: %lu\n",bssidStatArray[i].totalPacketsChecksumFF);

	if (bssidStatArray[i].totalPacketsNegativePrismheader>1) printf("PRISMHEADER SHOULD --NOT-- BE USED as there are %lu packets smaller than this header\n",bssidStatArray[i].totalPacketsNegativePrismheader);
}

if (bssidStatArray[0].totalPackets){
	printf(" Statistics for packets that do not belong to any BSSID (BSSID field was not detected)\n");	
	printf("  - Total valid packets read: %lu\n",bssidStatArray[0].totalValidPackets);
	printf("  - Total packets read: %lu\n",bssidStatArray[0].totalPackets);
	printf("  - Total unique IV read: %lu\n",bssidStatArray[0].totalUniqIV);
	printf("  - Total truncated packets read: %lu\n",bssidStatArray[0].totalPacketsTruncated);
	printf("  - Total non-data packets read: %lu\n",bssidStatArray[0].totalPacketsNonData);
	printf("  - Total FF checksum packets read: %lu\n",bssidStatArray[0].totalPacketsChecksumFF);

}

fflush(stdout);	
	
ClosePcapFile(file);
	
}
