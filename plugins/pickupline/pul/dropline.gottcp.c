#include"pul.h"

void gottcp(struct puldb* mydb,const struct pcap_pkthdr* header,const u_char* pkt)
{
	// filter out any activity that is only on the local network
	if((pkt[26]==pkt[30])&&(pkt[27]==pkt[31]))return;
	
	char ip[4]; // allocate the local packet information
	char mac[6];
	char dstip[4];
	char dstmac[6];

	dstmac[0]=pkt[0]; // assign the destination mac of the packet
	dstmac[1]=pkt[1];
	dstmac[2]=pkt[2];
	dstmac[3]=pkt[3];
	dstmac[4]=pkt[4];
	dstmac[5]=pkt[5];
	
	mac[0]=pkt[6]; // assign the source mac of the packet
	mac[1]=pkt[7];
	mac[2]=pkt[8];
	mac[3]=pkt[9];
	mac[4]=pkt[10];
	mac[5]=pkt[11];

	ip[0]=pkt[26]; // assign the source ip of the packet
	ip[1]=pkt[27];
	ip[2]=pkt[28];
	ip[3]=pkt[29];

	dstip[0]=pkt[30]; // assign the destination ip of the packet
	dstip[1]=pkt[31];
	dstip[2]=pkt[32];
	dstip[3]=pkt[33];


	int gwguess=0;
	int gwalt=0;

	if(mydb->gotgwmac) // throw away any packets I dont like
	{
		if(memcmp(mac,mydb->gwmac,6)==0)++gwguess;
		if(memcmp(dstmac,mydb->gwmac,6)==0)++gwguess;
		if(memcmp(mac,mydb->gwmacalt,6)==0)++gwalt;
		if(memcmp(dstmac,mydb->gwmacalt,6)==0)++gwalt;

		if((gwguess||gwalt)!=1)
		{
			//fprintf(stderr,"%d %d\n",gwguess,gwalt);
			return;
		}
	}
	
	// if nothing is known about the gateway, guess!
	if(mydb->gotgwmac==0)
	{
		fprintf(stderr,"\n** got the gateway MAC");
		
		/*
		fprintf(stderr,"\n**  detected communication %hi.%hi.%hi.%hi->%hi.%hi.%hi.%hi",
				ip[0],ip[1],ip[2],ip[3],dstip[0],dstip[1],dstip[2],dstip[3]);
		
		fprintf(stderr,"\n**  guessing that the gateway is %02x:%02x:%02x:%02x:%02x:%02x",
			dstmac[0],dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5]);

		fprintf(stderr,"\n**  or maybe %02x:%02x:%02x:%02x:%02x:%02x",
			mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
		*/
			
		memcpy(mydb->gwmac,dstmac,6);
		memcpy(mydb->gwmacalt,mac,6);
		mydb->gotgwmac=1;
		return;
	}

	// add the packet to the database!
	if(!memcmp(mac,mydb->gwmac,6))addtarget(dstip,dstmac,mydb);   // if incoming
	else if(!memcmp(dstmac,mydb->gwmac,6))addtarget(ip,mac,mydb); // if outgoing
	else
	{
		if(!memcmp(mydb->gwmacalt,"xxxxxx",6)) // this should never happen
		{
			return;
		}
			
		// looks like the wrong one was guessed, switch to alt
		
		mydb->head=0;
		
		memcpy(mydb->gwmac,mydb->gwmacalt,6);
		strncpy(mydb->gwmacalt,"xxxxxx",6); // x out the alternate
	}
}
