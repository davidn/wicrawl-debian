#include"pul.h"

void gotarp(struct puldb* mydb,const struct pcap_pkthdr* header,const u_char* pkt)
{
	if(mydb->gotgwip==1)return;
	if(mydb->gotgwmac==0)return;
	
	u_char ip[4];    // allocate the local packet information
	u_char mac[6];

	mac[0]=pkt[6]; // assign the source mac of the packet
	mac[1]=pkt[7];
	mac[2]=pkt[8];
	mac[3]=pkt[9];
	mac[4]=pkt[10];
	mac[5]=pkt[11];

	ip[0]=pkt[28];
	ip[1]=pkt[29];
	ip[2]=pkt[30];
	ip[3]=pkt[31];

	if(memcmp(mac,mydb->gwmac,6)==0)
	{
		memcpy(mydb->gwip,ip,4);
		mydb->gotgwip=1;
		fprintf(stderr,"\n** got the gateway IP (%u.%u.%u.%u)",
				ip[0],ip[1],ip[2],ip[3]);
		strncpy(mydb->gwmacalt,"xxxxxx",6); // we know that the gateway is right
	}
	else if(memcmp(mac,mydb->gwmacalt,6)==0)
	{
		memcpy(mydb->gwip,ip,4);
		mydb->gotgwip=1;
		fprintf(stderr,"\n** got the gateway IP (%u.%u.%u.%u)",
				ip[0],ip[1],ip[2],ip[3]);

		memcpy(mydb->gwmac,mydb->gwmacalt,6);
		strncpy(mydb->gwmacalt,"xxxxxx",6);
		mydb->head=0;
	}

	// or else this arp packet wasnt really that important was it?
}
