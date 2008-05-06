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

	wep.h: wep generic functions
*/

#ifndef	_WEP_H
#define	_WEP_H

#include <sys/types.h>
#include <pcap.h>

typedef struct rc4_key{
	unsigned char state[256];
	unsigned char x;
	unsigned char y;	
} rc4_key;

u_int32_t calculateCrc(unsigned char *buffer, int len);
short verifyKey(unsigned char *pkt, unsigned char *key, int key_len, int pkt_len);

typedef struct{
	unsigned int len;
	unsigned char *packet;	
}t_storedPacket;

typedef struct {
        //u_int16_t wi_status; /* 0x00 2*/
        //u_int16_t wi_rsvd0; /* 0x02 4*/
        //u_int16_t wi_rsvd1; /* 0x04 6*/
        //u_int16_t wi_q_info; /* 0x06 8*/
        //u_int16_t wi_rsvd2; /* 0x08 10*/
        //u_int16_t wi_rsvd3; /* 0x0A 12*/
        //u_int16_t wi_tx_ctl; /* 0x0C 14*/
        
        // u_int16_t wi_frame_ctl; /* 0x0E 16*/ // Instead of this use 2 bytes for little-big endian
        u_int8_t wi_frame_ctl_1;
        u_int8_t wi_frame_ctl_2;
        u_int16_t wi_id; /* 0x10 18*/
        u_int8_t wi_addr1[6]; /* 0x12 24*/
        u_int8_t wi_addr2[6]; /* 0x18 30*/
        u_int8_t wi_addr3[6]; /* 0x1E 36*/
        u_int16_t wi_seq_ctl; /* 0x24 38*/
        //u_int8_t wi_addr4[6]; /* 0x26 44*/
        
        //u_int16_t wi_dat_len; /* 0x2C 46*/
        //u_int8_t wi_dst_addr[6]; /* 0x2E 52*/
        //u_int8_t wi_src_addr[6]; /* 0x34 58*/
        //u_int16_t wi_len; /* 0x3A 60*/
        //u_int16_t wi_dat[3]; /* 0x3C */ /* SNAP header */
        //u_int16_t wi_type; /* 0x42 */
} t_wi_frame; 



pcap_t *OpenPcapFile(char *file);
void ClosePcapFile(pcap_t *file);
int GetLessSizedPackets(pcap_t *pfile, t_storedPacket **packets);
void DebugView10Packets(t_storedPacket **packets, int totalPackets);
void DebugViewPacketHeaders(unsigned char *packet);
short VerifyPacketWithKey(t_storedPacket *packet, unsigned char *key);
void DebugViewKey(unsigned char *key, int len);
void ViewKey(unsigned char *key, int len);
short Verify10PacketsWithKey(t_storedPacket **packets, unsigned char *key);

#endif
