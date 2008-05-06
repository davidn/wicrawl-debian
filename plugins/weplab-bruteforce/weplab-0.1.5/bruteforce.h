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

	bruteforce.h: dictionary based wep crack.
*/

#ifndef	_BRUTEFORCE_H
#define	_BRUTEFORCE_H

typedef struct{
	short values[256];		
	short total;
} t_keyspace;

typedef struct{
	unsigned char key[13];
	t_keyspace keyspace[13];
	short logicalStatus[13];
	int byte0IntValue;
} t_bruteforceKey;

void bruteforce (void);
short IncrementKey(t_bruteforceKey *key);

#endif

