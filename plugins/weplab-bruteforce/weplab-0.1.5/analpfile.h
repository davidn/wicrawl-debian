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

	analpfile.h: dictionary based wep crack.
*/

typedef struct{
	unsigned long int totalPackets;	
	unsigned long int totalValidPackets;
	unsigned long int totalUniqIV;
	unsigned long int totalPacketsTruncated;
	unsigned long int totalPacketsNonData;
	unsigned long int totalPacketsChecksumFF;
	unsigned long int totalPacketsNegativePrismheader;
}bssidStat;

void AnalyzePcapFile(void);
