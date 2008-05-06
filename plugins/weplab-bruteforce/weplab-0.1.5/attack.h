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

	attack.h: WEP statistical cracking algorithms.
*/

#ifndef	_ATTACK_H
#define	_ATTACK_H


// Defines
#define N	256								// RC4 number of elements in permutation array
#define NUMBER_ATTACKS	17		// Number of attacks implemented
#define STABILITY_LEVELS	5	// Number of predefined stability levels

extern unsigned int weakKeyBranch[NUMBER_ATTACKS][13];
extern unsigned char defaultAttacks[STABILITY_LEVELS+1][NUMBER_ATTACKS];	// Sets whether an specific attack number launched by default (1) or not (0).

void InitKeyByteSearch(void);
void AttackAndEvaluate(int keyByte, u_char *sKey, unsigned char *K, unsigned char *S, unsigned char *actual_iv, unsigned int votes[17][256], unsigned int totalIvs);
void FinishKeyByteSearch(int keyByte,  unsigned int totalIvs, unsigned int votes[17][256]);

#endif
