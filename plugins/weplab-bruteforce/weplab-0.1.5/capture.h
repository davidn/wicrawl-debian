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

	capture.h: wep capture packets
*/

#ifndef	_CAPTURE_H
#define	_CAPTURE_H

#ifndef DLT_PRISM_HEADER
#define DLT_PRISM_HEADER 119 /* prism header, not defined on some platforms */
#endif


void captureWeakPackets(void);
void captureWepDataPackets(void);

#endif
