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

	attack.c: cryptoanalysis attacks to WEP encryption
*/

#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "globals.h"
#include "attack.h"

unsigned int weakKeyBranch[NUMBER_ATTACKS][13];

// Implemented Korek's attacks: A_s5_1, A_s2, A_s13, A_w13_1, Aw5_1, A_w5_2, A_w13_2, A_w13_3, A_w5_3, A_w15, A_s5_2
// 				A_s5_3, A_4_s13, A_4_w5_1, A_4_w5_2, A_4_w5_4, A_neg
unsigned char defaultAttacks[STABILITY_LEVELS+1][NUMBER_ATTACKS]={	// Sets whether an specific attack number launched by default (1) or not (0).
	{5,3,13,11,4,4,11,11,4,15,5,5,13,4,4,4,1},
	{5,3,13,11,0,0,11,11,0,15,5,5,13,3,3,3,1},
	{5,3,13,0,0,0,0,0,0,15,5,5,13,0,0,0,1},
	{5,3,13,0,0,0,0,0,0,0,0,0,13,0,0,0,1},
	{5,0,13,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}
};
int reject[256];

static void SwapByte(unsigned char *a, unsigned char *b){
	unsigned char swapByte;
	swapByte=*a;
	*a=*b;
	*b=swapByte;	
}

// This function initializes global variables needed for different heuristics attacks.
void InitKeyByteSearch(void){
	int i;
	for (i=0; i<256; i++) reject[i]=0;
}

// This function finishes normalize needed for different heuristics attacks.
void FinishKeyByteSearch(int keyByte, unsigned int totalIvs, unsigned int votes[17][256]){
  /* reject the "impossible" keybytes */
	int i;
	for( i = 0; i < 256; i++ ){
		if (reject[i]>3+(int)(totalIvs/150000)) votes[keyByte][i]=0;
		if (votes[keyByte][i]>10 * reject[i]) votes[keyByte][i]-= 10 * reject[i];
			else votes[keyByte][i]=1;	// This byte has 0% probab. of suceed
	}
}

// Insert your custom attack algorithm in this function.
// keyByte: current keybyte being attacked at this moment.
// sKey: previous guessed keybytes on this particual branch.
// S: calculated permutation vector
// actual_iv: positions 0..2 contains the current packet IV
//						positions 2..3 contains the two first bytes of the RC4 encryption stream
// votes[keybyte][candidateKeyValue]: contains the total votes for current keybyte at a particular possible value 0..0xFF
void AttackAndEvaluate(int keyByte, u_char *sKey, unsigned char *K, unsigned char *S, unsigned char *actual_iv, unsigned int votes[17][256], unsigned int totalIvs){
	int i,j;
	unsigned char jj[256];
	unsigned char Si[256];	
	u_char E,o1,o2;
	unsigned char foundWeak[NUMBER_ATTACKS];

	// Initialization. foundWeak contains boolean values that indicates if the current data packet was suitable for previous attacks
	// Very usefull if you want to know within your attack algorithm if current packet was found weak by previous attacks
	for (i=0; i<NUMBER_ATTACKS; i++) foundWeak[i]=0;

	// Si[]=S[]
	memcpy(Si,S,256);

	// First let's calculate some variables: S[], j, o1, o2, Si[]... for differents heuristics attacks
	// Create S and jj[](contains all j for each iteration
	for(i = 0, j = 0; i <keyByte+3; i++)
	{
		j = (j + S[i] + K[i % (keyByte + 3)]) & 0xFF; // &0xFF is like %256
		jj[i]=j;
		SwapByte(&S[i], &S[j]);
 	}
	
	// Create Si that will contain final index in S for each byte value
	// We need jj for this because we are going backward with the KSA
	for (i=keyByte+3-1;i>=0;i--) SwapByte(&Si[i],&Si[jj[i]]);
	
	
	// Now let's go for o1 and o2
	o1= actual_iv[3];
	o2= actual_iv[4];
	
	// NOW ATTACKS BEGINS!
	
	// ------------------------------------------------------------
	//   Attack 1: classic FMS attack to byte 0 of output stream
	// ------------------------------------------------------------
	// SOURCE: original FMS paper
	// DESCRIPTION: Half-strong (ie strong 5 and some weak 5) 5% - Korek A_s5_1

	if (defaultAttacks[global_v.stability][0] && defaultAttacks[STABILITY_LEVELS][0]){
    		if((S[1] < keyByte + 3 && ((S[1] + S[S[1]]) & 0xFF) == keyByte + 3) &&
    		(Si[o1]!=1) && (Si[o1]!=S[S[1]]))
    		{
			foundWeak[0]=1;
			weakKeyBranch[0][keyByte]++;
			E=(Si[o1]-S[keyByte+3]-jj[keyByte+3-1]) & 0xFF;		// Si[o1]-S[keyByte+3]-jj[keyByte+3-1]
	    	votes[keyByte][E]+= defaultAttacks[global_v.stability][0]; 
		}
	}

	// ------------------------------------------------------------
	//   Attack 2: classic FMS attack to byte 1 of output stream
	// ------------------------------------------------------------
	// SOURCE: h1kari second byte FMS attack implemented by Topo[LB]
	// DESCRIPTION: stable 3% - Korek A_s2
    	if ( defaultAttacks[global_v.stability][1] && defaultAttacks[STABILITY_LEVELS][1]){
    		if (((S[1]!=2) && (S[2]!=0) && ((S[2]+S[1]) < keyByte+3) 
    		&& ((S[2] + S[S[2]+S[1]]) & 0xFF) == keyByte + 3) 
    		&& (Si[o2]!=1) && (Si[o2]!=2) && (Si[o2]!=S[1]+S[2])) 
    		{
			foundWeak[1]=1;
			weakKeyBranch[1][keyByte]++;
			E = (Si[o2]-S[keyByte+3]-jj[keyByte+3-1])&0xFF;		// Si[o2]-S[keyByte+3]-jj[keyByte+3-1]
	    	votes[keyByte][E]+= defaultAttacks[global_v.stability][1]; 
    		}
	}

	// ------------------------------------------------------------
	//   Attack 3: strong 13%
	// ------------------------------------------------------------
	// SOURCE: Korek strong 13%
	// DESCRIPTION: if S[1]==q and o1=q then S[q]=0
	//		stable 13% - Korek A_s13
	if (defaultAttacks[global_v.stability][2] && defaultAttacks[STABILITY_LEVELS][2]){
		if( S[1] == keyByte + 3 && o1 == keyByte + 3 )
		{
			foundWeak[2]=1;
			weakKeyBranch[2][keyByte]++;
			E = (Si[0]-S[keyByte+3]-jj[keyByte+3-1])&0xFF;
			votes[keyByte][E] += defaultAttacks[global_v.stability][2];
		}
	}

	// ------------------------------------------------------------
	//   Attack 4: semi-weak 13%
	// ------------------------------------------------------------
	// SOURCE: Korek semi-weak 13%
	// DESCRIPTION: if S[1]==q and o1=1-q then S[q]=1-q
	//		unstable 13% - Korek A_w13_1
	if (defaultAttacks[global_v.stability][3] && defaultAttacks[STABILITY_LEVELS][3]){
		if( S[1] == keyByte + 3 && o1 == ((1 - (keyByte + 3))&0xFF) )
		{
			foundWeak[3]=1;
			weakKeyBranch[3][keyByte]++;
			E = (Si[o1]-S[keyByte+3]-jj[keyByte+3-1])&0xFF;
			votes[keyByte][E] += defaultAttacks[global_v.stability][3];
		}
	}

	// ------------------------------------------------------------
	//   Attack 5: weak 5%
	// ------------------------------------------------------------
	// SOURCE: Korek weak 5%
	// DESCRIPTION: if S[q]+q=io1<q, io1!=1, o1!=q
	//		unstable 13% - Korek A_w5_1
	if (defaultAttacks[global_v.stability][4] && defaultAttacks[STABILITY_LEVELS][4] ){
		if(( S[1] == keyByte + 3 && o1!=((1 - (keyByte + 3))&0xFF) && o1!= keyByte+3 &&
		Si[o1]<keyByte+3 && Si[(Si[o1]-(keyByte+3))&0xFF]) != 1)
		{
			foundWeak[4]=1;
			weakKeyBranch[4][keyByte]++;
			E = (Si[(Si[o1]-(keyByte+3))&0xFF]-S[keyByte+3]-jj[keyByte+3-1])&0xFF;
			votes[keyByte][E] += defaultAttacks[global_v.stability][4];
		}
	}

	// ------------------------------------------------------------
	//   Attack 6: unstable 5%
	// ------------------------------------------------------------
	// SOURCE: Korek unstable 5%
	// DESCRIPTION: S[1]=q, S[q]=1 io1=2
	//		unstable 5% - Korek A_w5_2
	if (defaultAttacks[global_v.stability][5]  && defaultAttacks[STABILITY_LEVELS][5]){
		if( Si[o1]==2 && S[keyByte+3]==1)
		{
			foundWeak[5]=1;
			weakKeyBranch[5][keyByte]++;
			E = (1-S[keyByte+3]-jj[keyByte+3-1])&0xFF;
			votes[keyByte][E] += defaultAttacks[global_v.stability][5];
		}
	}

	// ------------------------------------------------------------
	//   Attack 7: unstable 13%
	// ------------------------------------------------------------
	// SOURCE: Korek unstable 13%
	// DESCRIPTION: S'[1]=q, S'[q]=1 j_q=1 then 1->q->0 so o1=q
	//		unstable 13% - Korek A_w13_2
	if (defaultAttacks[global_v.stability][6]  && defaultAttacks[STABILITY_LEVELS][6]){
		if( S[keyByte+3]==keyByte+3 && S[1]==0 && o1==keyByte+3)
		{
			foundWeak[6]=1;
			weakKeyBranch[6][keyByte]++;
			E = (1-S[keyByte+3]-jj[keyByte+3-1])&0xFF;
			votes[keyByte][E] += defaultAttacks[global_v.stability][6];
		}
	}

	// ------------------------------------------------------------
	//   Attack 8: unstable 13%
	// ------------------------------------------------------------
	// SOURCE: Korek unstable 13%
	// DESCRIPTION: S'[1]=1-q, S'[q]=q j_q=1 then 1->q->1-q so o1=1-q
	//		unstable 13% - Korek A_w13_3
	if (defaultAttacks[global_v.stability][7]  && defaultAttacks[STABILITY_LEVELS][7]){
		if( S[keyByte+3]==keyByte+3 && o1==S[1] && S[1]==((1-(keyByte+3))&0xFF))
		{
			foundWeak[7]=1;
			weakKeyBranch[7][keyByte]++;
			E = (1-S[keyByte+3]-jj[keyByte+3-1])&0xFF;	
			votes[keyByte][E] += defaultAttacks[global_v.stability][7];
		}
	}


	// ------------------------------------------------------------
	//   Attack 9: unstable 5%
	// ------------------------------------------------------------
	// SOURCE: Korek unstable 5%
	// DESCRIPTION: jq=1, S[q]=q, S[1]!=0,1-q
	//		unstable 5% - Korek A_w5_3
	if (defaultAttacks[global_v.stability][8]  && defaultAttacks[STABILITY_LEVELS][8]){
		if( S[keyByte+3]==keyByte+3 && S[1]>=((-1*(keyByte+3))&0xFF) && S[1]==((Si[o1]-(keyByte+3))&0xFF))
		{
			foundWeak[8]=1;
			weakKeyBranch[8][keyByte]++;
			E = (1-S[keyByte+3]-jj[keyByte+3-1])&0xFF;
			votes[keyByte][E] += defaultAttacks[global_v.stability][8];
		}
	}

	// ------------------------------------------------------------
	//   Attack 10: semi-stable 15%
	// ------------------------------------------------------------
	// SOURCE: Korek semi-stable 15%
	// DESCRIPTION: semi-stable 15 - Korek A_w15
	//		
	if (defaultAttacks[global_v.stability][9]  && defaultAttacks[STABILITY_LEVELS][9]){
		if( S[2]!=0 && o2==0 && S[keyByte+3]==0 )
		{
			foundWeak[9]=1;
			weakKeyBranch[9][keyByte]++;
			E = (2-S[keyByte+3]-jj[keyByte+3-1])&0xFF;
			votes[keyByte][E] += defaultAttacks[global_v.stability][9];
		}
	}

	// ------------------------------------------------------------
	//   Attack 11: strong 5% on o2
	// ------------------------------------------------------------
	// SOURCE: Korek strong  5% on o2
	// DESCRIPTION: strong 5% on o2 - Korek A_s5_2
	//		
	if (defaultAttacks[global_v.stability][10]  && defaultAttacks[STABILITY_LEVELS][10]){
		if( S[1]>keyByte+3 && ((S[2]+S[1])&0xFF)==keyByte+3
		&& o2==S[1] && Si[(S[1]-S[2])&0xFF]!=1 && Si[(S[1]-S[2])&0xFF]!=2)
		{
			foundWeak[10]=1;
			weakKeyBranch[10][keyByte]++;
			E = (Si[(S[1]-S[2])&0xFF]-S[keyByte+3]-jj[keyByte+3-1])&0xFF;
			votes[keyByte][E] += defaultAttacks[global_v.stability][10];
		}
	}

	// ------------------------------------------------------------
	//   Attack 12: strong 5% on o2
	// ------------------------------------------------------------
	// SOURCE: Korek strong  5% on o2
	// DESCRIPTION: strong 5% on o2 - Korek A_s5_3
	//		
	if (defaultAttacks[global_v.stability][11]  && defaultAttacks[STABILITY_LEVELS][11]){
		if( S[1]>keyByte+3 && ((S[2]+S[1])&0xFF)==keyByte+3
		&& o2==((2-S[2])&0xFF) && Si[o2]!=1 && Si[o2]!=2)
		{
			foundWeak[11]=1;
			weakKeyBranch[11][keyByte]++;
			E = (Si[o2]-S[keyByte+3]-jj[keyByte+3-1])&0xFF;
			votes[keyByte][E] += defaultAttacks[global_v.stability][11];
		}
	}

	// ------------------------------------------------------------
	//   Attack 13: strong 13% on q=4
	// ------------------------------------------------------------
	// SOURCE: Korek strong 13% on q=4
	// DESCRIPTION: strong 13% on q=4 - Korek A_4_s13
	//		
	if (defaultAttacks[global_v.stability][12]  && defaultAttacks[STABILITY_LEVELS][12]){
		if( keyByte+3==4 && S[1]==2 && o2==0)
		{
			foundWeak[12]=1;
			weakKeyBranch[12][keyByte]++;
			E = (Si[0]-S[keyByte+3]-jj[keyByte+3-1])&0xFF;
			votes[keyByte][E] += defaultAttacks[global_v.stability][12];
		}
	}

	// ------------------------------------------------------------
	//   Attack 14: unstable 5% on q=4
	// ------------------------------------------------------------
	// SOURCE: Korek unstable 5% on q=4
	// DESCRIPTION: unstable 5% on q=4 - Korek A_4_w5_1
	//		
	if (defaultAttacks[global_v.stability][13]  && defaultAttacks[STABILITY_LEVELS][13]){
		if( keyByte+3==4 && S[1]==2 && o2!=0 && jj[1]==2 && Si[o2]==0)
		{
			foundWeak[13]=1;
			weakKeyBranch[13][keyByte]++;
			E = (Si[254]-S[keyByte+3]-jj[keyByte+3-1])&0xFF;
			votes[keyByte][E] += defaultAttacks[global_v.stability][13];
		}
	}

	// ------------------------------------------------------------
	//   Attack 15: unstable 5% on q=4
	// ------------------------------------------------------------
	// SOURCE: Korek unstable 5% on q=4
	// DESCRIPTION: unstable 5% on q=4 - Korek A_4_w5_2
	//		
	if (defaultAttacks[global_v.stability][14]  && defaultAttacks[STABILITY_LEVELS][14]){
		if( keyByte+3==4 && S[1]==2 && o2!=0 && jj[1]==2 && Si[o2]==2)
		{
			foundWeak[14]=1;
			weakKeyBranch[14][keyByte]++;
			E = (Si[255]-S[keyByte+3]-jj[keyByte+3-1])&0xFF;
			votes[keyByte][E] += defaultAttacks[global_v.stability][14];
		}
	}

	// ------------------------------------------------------------
	//   Attack 16: unstable 5% on q=4
	// ------------------------------------------------------------
	// SOURCE: Korek unstable 5% on q=4
	// DESCRIPTION: unstable 5% on q=4 - Korek A_4_w5_4
	//		
	if (defaultAttacks[global_v.stability][15]  && defaultAttacks[STABILITY_LEVELS][15]){
		if( keyByte+3>4 && S[4]+2==keyByte+3 && Si[o2]!=1 && Si[o2]!=4)
		{
			foundWeak[15]=1;
			weakKeyBranch[15][keyByte]++;
			E = (Si[o2]-S[keyByte+3]-jj[keyByte+3-1])&0xFF;
			votes[keyByte][E] += defaultAttacks[global_v.stability][15];
		}
	}


	// ------------------------------------------------------------
	//   Attack 17: inversed Korek
	// ------------------------------------------------------------
	// SOURCE: Korek inversed - Korek A_neg
    if (defaultAttacks[global_v.stability][16]  && defaultAttacks[STABILITY_LEVELS][16]){
        if( S[2] == 0 )
        {
            if( S[1] == 2 && o1 == 2 )
            {
                reject[(1 - jj[keyByte+3-1] - S[keyByte+3]) & 0xFF]++;
                reject[(2 - jj[keyByte+3-1] - S[keyByte+3]) & 0xFF]++;
		foundWeak[16]=1;
		weakKeyBranch[16][keyByte]++;

            }
            else if( o2 == 0 )
            {
                reject[(2 - jj[keyByte+3-1] - S[keyByte+3]) & 0xFF]++;
		foundWeak[16]=1;
		weakKeyBranch[16][keyByte]++;
            }

	}else{
            if( o2==0 && S[keyByte+3]==0 )
            {
                //reject[(2 - jj[keyByte+3-1] - S[keyByte+3]) & 0xFF]++;
		foundWeak[16]=1;
		weakKeyBranch[16][keyByte]++;
            }    	
	}
	
	if (S[1]==1 && o1==S[2]){
       reject[(1 - jj[keyByte+3-1] - S[keyByte+3]) & 0xFF]++;
		reject[(2 - jj[keyByte+3-1] - S[keyByte+3]) & 0xFF]++;
		foundWeak[16]=1;
		weakKeyBranch[16][keyByte]++;
	} 

	if (S[1]==0 && S[0]==1 && o1==1){
        reject[(0-jj[keyByte+3-1] - S[keyByte+3]) & 0xFF]++;
		reject[(1 - jj[keyByte+3-1] - S[keyByte+3]) & 0xFF]++;
		foundWeak[16]=1;
		weakKeyBranch[16][keyByte]++;
	} 
    }


}
