// TODO
// Sanity checks on captured packets and command line parameters suggestions



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

	wep.c: wep generic functions
*/


#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "debug.h"
#include "globals.h"
#include "wep.h"


static u_int32_t crc_table[256] = {
  0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
  0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
  0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
  0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
  0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
  0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
  0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
  0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
  0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
  0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
  0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
  0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
  0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
  0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
  0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
  0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
  0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
  0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
  0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
  0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
  0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
  0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
  0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
  0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
  0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
  0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
  0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
  0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
  0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
  0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
  0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
  0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
  0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
  0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
  0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
  0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
  0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
  0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
  0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
  0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
  0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
  0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
  0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

u_int32_t CalculateCrc(unsigned char *buffer, int len)
{
  u_int32_t value;
  value = ~0U;

  while(len--)
  {
    value = crc_table[(value ^ *buffer) & 0xff] ^ (value >> 8);
    buffer++;
  }

  return value^ ~0U;
}


inline static void SwapByte(unsigned char *a, unsigned char *b){
	register unsigned char swapByte;
	swapByte=*a;
	*a=*b;
	*b=swapByte;	
}

void InitKey(unsigned char *key_data_ptr, int key_data_len, rc4_key *key){
	register unsigned char index1;
	register unsigned char index2;
	unsigned char *state;
	register short i;
	
	state=&key->state[0];
	//for (i=0; i<256; i++) state[i]=i;
	memcpy(state,S_InitialBackup,256);

	key->x=0;
	key->y=0;
	index1=0;
	index2=0;
	for (i=0; i<256;i++){
		index2=(key_data_ptr[index1]+state[i]+index2)%256;
		SwapByte(&state[i], &state[index2]);
		index1=(index1+1)%key_data_len;	
	}	
}

void Rc4(unsigned char *buffer_ptr, int buffer_len, unsigned char *buffer_out, rc4_key *key){
	register unsigned char x;
	register unsigned char y;
	unsigned char *state;
	//unsigned char xorIndex;
	short i;
	
	x=key->x;
	y=key->y;
	
	state=&key->state[0];
	for (i=0; i<buffer_len; i++){
//debug("%u",i);
		x=(x+1)%256;
		y=(state[x]+y)%256;
		SwapByte(&state[x], &state[y]);
//		xorIndex=(state[x] + state[y])%256;
//		buffer_out[i]=buffer_ptr[i]^state[xorIndex];	
			buffer_out[i]=buffer_ptr[i]^state[(state[x] + state[y])%256];	
	}
	key->x=x;
	key->y=y;
}

// parameters:
//	pkt: pointer to the raw encrypted 802.11b packet
//	key: pointer to the key used to try
//	key_len: length of the key in bytes
//	pkt_len: length of th raw encrypted packet
short VerifyKey(unsigned char *pkt, unsigned char *key, int key_len, int pkt_len){
	unsigned char seed[LEN_KEY];
	unsigned char pkt_out[MAX_PKT_LEN];
	rc4_key k;
	unsigned int pkt_crc, calculated_crc;
	unsigned char *crcbytes;

	memcpy(seed,pkt,LEN_IV);
//	DebugViewKey(seed,3);
	//seed[0]=pkt[2];
	//seed[1]=pkt[1];
	//seed[2]=pkt[0];
	memcpy(seed+LEN_IV,key,key_len);

	InitKey(seed,key_len+LEN_IV,&k);

	//DebugViewKey(key,14);


	if (((k.state[(k.state[1]+k.state[k.state[1]])&0xFF]^(pkt+LEN_IV+LEN_ID)[0])!=0xAA) &&
	((k.state[(k.state[1]+k.state[k.state[1]])&0xFF]^(pkt+LEN_IV+LEN_ID)[0])!=0xE0)) return 0;	// Ultra fast pre-verification based on 1st byte decryption

	// Let's go for the other byte!
	//if (((k.state[(k.state[2]+k.state[(k.state[2]+k.state[1])&0xFF])&0xFF]^(pkt+LEN_IV+LEN_ID)[1])!=0xAA) &&
	//((k.state[(k.state[2]+k.state[(k.state[2]+k.state[1])&0xFF])&0xFF]^(pkt+LEN_IV+LEN_ID)[1])!=0xE0)) return 0;	// Ultra fast pre-verification based on 1st byte decryption


	Rc4(pkt+LEN_IV+LEN_ID,pkt_len-LEN_IV-LEN_ID,pkt_out,&k);
	
	//if (pkt_out[0]!=0xaa) return 0;
	if (pkt_out[1]!=0xAA && pkt_out[1]!=0xE0) return 0;
	
	//DebugViewKey(pkt_out,60);

	/* calculate checksum and see if it checks out */
	//crcbytes = pkt_out + pkt_len - LEN_IV - LEN_ID - 4;
	crcbytes = pkt_out + pkt_len - LEN_IV - LEN_ID - 4;
//DebugViewKey(crcbytes-2,10);
	pkt_crc = ((unsigned int) crcbytes[0]) | (((unsigned int) crcbytes[1]) << 8) | (((unsigned int) crcbytes[2]) << 16) | (((unsigned int) crcbytes[3]) << 24);

	calculated_crc = CalculateCrc(pkt_out, pkt_len - LEN_IV - LEN_ID - 4);

	if(pkt_crc == calculated_crc) return 1;
	else return 0;	
	
}

pcap_t *OpenPcapFile(char *file){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *p;
	if((p = pcap_open_offline(file, errbuf)) == NULL)
	{
		fprintf(stderr, "Error: unable to open pcap output file: %s\n", errbuf);
		exit(2);
	}	
	return p;
}

void ClosePcapFile(pcap_t *file){
	pcap_close(file);	
	
}

int GetLessSizedPackets(pcap_t *pfile, t_storedPacket **packets){
	FILE * fileDescriptor;
	unsigned long int fileSize=0;
	unsigned long int actualFilePosition;
	unsigned long int lastProgressPerc=0;

	unsigned long int perc;
	unsigned long int lastFilePosition=0;

	unsigned char * pkt;
	struct pcap_pkthdr h;
	t_wi_frame *wi_h; 
	unsigned long int totalPackets=0;

	int max=MAX_PKT_SIZE;
	int totalPackets10=0;
	int totalValidPackets=0;
	int min=0;
	int i,j;
	t_storedPacket *tmpPacket;
	int m_pkt=0;
	unsigned int p_len;
	unsigned char *iv;

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


	if (global_v.prismHeaderPresent) pkt+=144;
    wi_h=(t_wi_frame *)pkt;
   // pkt+=IV_OFFSET;
  if (h.len!=h.caplen){
		if (global_v.debug>2) debug("Packet %u has different real length (%u) than captured length (%u)",totalPackets,h.len, h.caplen);
	}else if(!(wi_h->wi_frame_ctl_1&0x08)){
		if (global_v.prismHeaderPresent) {
			if (h.len<144+sizeof(t_wi_frame)) {
				if (global_v.debug>2) debug("Packet %u has negative size with prismheader!! Perhaps you dont need --prismheader");
			}
		}
		if (global_v.debug>2) debug("Packet %u is not a DATA type packet",totalPackets);	
	}else
	//if (!(wi_h->wi_status & WI_STAT_BADCRC) && (wi_h->wi_frame_ctl & WI_FCTL_FTYPE) == WI_FTYPE_DATA)
	//if  ( (!(ntohs(wi_h->wi_status) & WI_STAT_BADCRC) && (ntohs(wi_h->wi_frame_ctl) & WI_FCTL_FTYPE) == WI_FTYPE_DATA)   )
	//&&(ntohs(wi_h->wi_dat_len) < MAX_PKT_SIZE && ntohs(wi_h->wi_dat_len) > MIN_PKT_SIZE) )
	{

		// First let's check the BSSID if selected
		if (global_v.target_bssid_selected){
			if (target_bssid(pkt)) {
				if (global_v.debug>2) debug("Packet %u belongs to a different BSSID",totalPackets);
				continue;
			}
		}else{
			if (GetPacketBssid(pkt,global_v.target_bssid)){
				printf("Not BSSID specified.\n Detected one packet with BSSID: [%02X:%02X:%02X:%02X:%02X:%02X]\n", TOMAC(global_v.target_bssid));
				debug("Only packets belongs to that BSSID will be processed.\nIf -a option reveals other BSSIDs you can specify one with --bssid.\n");
				global_v.target_bssid_selected=1;
			}			
		}

		if (global_v.prismHeaderPresent) {
			if (h.len<144+sizeof(t_wi_frame)) {
				if (global_v.debug>2) debug("Packet %u has negative size with prismheader!! Perhaps you dont need --prismheader");
				continue;
			}
			p_len=h.len-144;			
		}
		else p_len=h.len;

		if (((*(((unsigned char *)wi_h)+1))&0xC0)==0xC0) iv=pkt+sizeof(t_wi_frame)+6;
		else iv=pkt+sizeof(t_wi_frame);

		if (global_v.key_len==5 && iv[3]!=global_v.keyid) continue;	// Si no es la key correcta para 64 bits la ignoro
		
		// If total lenght < 802.11 header plus CRC then DATA=0 and packet should be ignored.
		if (p_len <= sizeof(t_wi_frame)+4) continue;

		if (global_v.debug>2){
			debug("Packet %u",totalPackets);
			debug("---------------------------------------------");
			DebugViewPacketHeaders(pkt);
			debug("Pcap Len: %u",h.len);			
			debug("Real Len (minus prismheader): %u", p_len);
			debug("---------------------------------------------\n");
		}
		if (totalPackets10<10) totalPackets10++; 
		totalValidPackets++;
		if (p_len<max || totalPackets10<11){
			max=0;
			for (i=0; i<totalPackets10; i++) if (packets[i]->packet) if (packets[i]->len>max){
				max=packets[i]->len;
				m_pkt=i;
			}
			if (totalPackets10<11) m_pkt=totalPackets10-1;
			if (packets[m_pkt]->packet) free(packets[m_pkt]->packet);
			packets[m_pkt]->packet=malloc(p_len);
			memcpy(packets[m_pkt]->packet, pkt, p_len);
			packets[m_pkt]->len=p_len;

			max=0;
			for (i=0; i<totalPackets10; i++) if (packets[i]->len>max) max=packets[i]->len;

		}
	}

	for (i=0; i<totalPackets10; i++) {
		min=packets[0]->len;
		for (j=i+1; j<totalPackets10; j++){
			if (min>=packets[j]->len){
				tmpPacket=packets[i];
				packets[i]=packets[j];
				packets[j]=tmpPacket;
				min=packets[j]->len;	
			}
		}	
	}
	}
printf("\r                                   \n");
printf("Total valid packets read: %u\n",totalValidPackets);
printf("Total packets read: %u\n",totalPackets);

return totalPackets10;
}

void DebugView10Packets(t_storedPacket **packets, int totalPackets){
	int i;
	debug("%u packets selected.",totalPackets);
	for (i=0; i<totalPackets; i++){
			debug("Packet %u --> %u total lenght, %u data lenght (just encrypted data)",i,packets[i]->len,packets[i]->len-sizeof(t_wi_frame)-LEN_IV-LEN_ID);
			if (global_v.debug>1) DebugViewPacketHeaders(packets[i]->packet);
//			debug ("Len EXcluding headers (%d 802.11, %d IV+ID): %d",sizeof(t_wi_frame),LEN_IV+LEN_ID,packets[i]->len-sizeof(t_wi_frame)-LEN_IV-LEN_ID);
	}
}

void DebugViewKey(unsigned char *key, int len){
	char buffer[1024];
	char buffer_aux[1024];
	int i;

	strcpy(buffer,"Key: ");
	for (i=0; i<len-1; i++) {
		sprintf(buffer_aux,"%02x:",key[i]);
		strcat(buffer,buffer_aux);
	}
	if (len) {
		sprintf(buffer_aux,"%02x",key[len-1]);
		strcat(buffer,buffer_aux);
	}
	debug(buffer);

}

void ViewKey(unsigned char *key, int len){
	char buffer[1024];
	char buffer_aux[1024];
	int i;

	strcpy(buffer,"Key: ");
	for (i=0; i<len-1; i++) {
		sprintf(buffer_aux,"%02x:",key[i]);
		strcat(buffer,buffer_aux);
	}
	if (len) {
		sprintf(buffer_aux,"%02x",key[len-1]);
		strcat(buffer,buffer_aux);
	}
	printf("%s\n",buffer);

}


void DebugViewPacketHeaders(unsigned char *packet){
	t_wi_frame *wi_h=(t_wi_frame *) packet;	
	debug ("Frame Ctl: 0x%04x",wi_h->wi_frame_ctl_1);
	DebugViewKey(packet+sizeof(t_wi_frame),3);
	//debug ("Seq Ctl: %u",(u_int16_t) wi_h->wi_seq_ctl);
}

// Uses key_len stored in global_v.key_len
short VerifyPacketWithKey(t_storedPacket *packet, unsigned char *key){
	int len=packet->len;
	if (global_v.fcsPresent) len-=4;
	if (VerifyKey(packet->packet+sizeof (t_wi_frame),key,global_v.key_len,len-sizeof(t_wi_frame))) return 1;
	else return 0;
	
}

short Verify10PacketsWithKey(t_storedPacket **packets, unsigned char *key){
	int i;
	int trues=0;
	for (i=0; i<10; i++){
			if (packets[i]->packet) if (VerifyPacketWithKey(packets[i], key)) trues ++;
	}
	return trues;
}

/*
 * function to extract BSSID of of a given packet
 * returns 0, in case, the BSSID of -s <BSSID> matches the packet
 * return 1 in case BSSID differs
 *
*/

int target_bssid(const u_char *pkt)
{
	const u_char *packet; 
	static t_wi_frame *wi_h;
	unsigned char bssid[6];
	packet = (unsigned char *) pkt;
	wi_h = (t_wi_frame *)packet;
	// STA TO AP data
	if (wi_h->wi_frame_ctl_2 & 0x01) {
		memcpy(bssid, wi_h->wi_addr1, 6);
	}
	// AP TO STA data
	else if (wi_h->wi_frame_ctl_2 & 0x02) {
		memcpy(bssid, wi_h->wi_addr2, 6);
	}
	// AP TO AP
	else if (wi_h->wi_frame_ctl_2 & 0x03) {
	}
	// STA TO STA or management frame
	else if (wi_h->wi_frame_ctl_2 & 0x00) {
		memcpy(bssid, wi_h->wi_addr3, 6);	
	}
	else {
		// printf("weird, hehe... ;)\n");
	}
	if (global_v.debug>1){ 
		if (global_v.target_bssid_selected == 1) {
			debug("BSSID: [%02x:%02x:%02x:%02x:%02x:%02x]\n", TOMAC(bssid));
		}
	}
	if (memcmp(global_v.target_bssid, bssid, 6) == 0) {
		return(0);
	}
	else {
		return(1);
	}
}

int GetPacketBssid(const u_char *pkt, unsigned char *bssid)
{
	int returnvalue=0;
	const u_char *packet; 
	static t_wi_frame *wi_h;
	packet = (unsigned char *) pkt;
	wi_h = (t_wi_frame *)packet;
	// STA TO AP data
	if (wi_h->wi_frame_ctl_2 & 0x01) {
		memcpy(bssid, wi_h->wi_addr1, 6);
		returnvalue=1;
	}
	// AP TO STA data
	else if (wi_h->wi_frame_ctl_2 & 0x02) {
		memcpy(bssid, wi_h->wi_addr2, 6);
		returnvalue=1;
	}
	// AP TO AP
	else if (wi_h->wi_frame_ctl_2 & 0x03) {
	}
	// STA TO STA or management frame
	else if (wi_h->wi_frame_ctl_2 & 0x00) {
		memcpy(bssid, wi_h->wi_addr3, 6);
		returnvalue=1;	
	}
	else {
		// printf("weird, hehe... ;)\n");
	}
	if (global_v.debug>1){ 
			debug("Detected candidate BSSID: [%02x:%02x:%02x:%02x:%02x:%02x]\n", TOMAC(bssid));
	}
	return returnvalue;
}

