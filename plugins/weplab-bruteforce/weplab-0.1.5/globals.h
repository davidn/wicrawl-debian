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

	globals.h: global resources.
*/


#ifndef	_GLOBALS_H
#define	_GLOBALS_H



#define	PROGRAM_NAME	"weplab - Wep Key Cracker"
#define PROGRAM_VERSION	"v0.1.5"
#define PROGRAM_AUTHOR	"Jose Ignacio Sanchez Martin - Topo[LB] <topolb@users.sourceforge.net>"

#define DELAY_GC	10
#define LEN_KEY	40
#define LEN_IV	3
#define LEN_ID	1
#define MAX_PKT_LEN	65535
#define MAX_PKT_SIZE	65000
#define MIN_PKT_SIZE	20

#define TOMAC(x) (unsigned char)x[0], (unsigned char)x[1], (unsigned char)x[2], (unsigned char)x[3], (unsigned char)x[4], (unsigned char)x[5]

typedef struct{
	int verbose;
	int daemon;
	int debug;
	char filterString[2048];
	char device[256];
	char packetsFilename[256];
	char weakPcapFilename[256];
	int key_len;
	short fcsPresent;
	short prismHeaderPresent;
	short allowdups;
	short ascii;
	short useDebugKey;
	unsigned char debugKey[128];
	unsigned int caplen;
	short keyid;
	short percSucceed;
	int processes;
	int totalAttacksSelected;
	char target_bssid[6];
	int target_bssid_selected;
	int stability;
	short alnum;
	short alpha;
	char wordfile[256];
}t_global_v;

extern t_global_v global_v;

extern unsigned char S_InitialBackup[256];

#endif
