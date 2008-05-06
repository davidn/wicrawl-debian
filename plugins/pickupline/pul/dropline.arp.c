#include"pul.h"

extern void gotarp(struct puldb*,const struct pcap_pkthdr*,const u_char*);

void* sniffarp(struct puldb* mydb)
{
	//  ** set up all the pcap goodness **
	
	pcap_t* handle;
	char    errbuf[PCAP_ERRBUF_SIZE];
	struct  bpf_program filter;
	char    filterstring[30]; // the bpf filter

	bpf_u_int32 mask;
	bpf_u_int32 net;

	struct pcap_pkthdr header;
	u_char* packet;

	pcap_lookupnet(mydb->interface,&net,&mask,errbuf);

	if(handle=pcap_open_live(mydb->interface,BUFSIZ,1,0,errbuf));
	else printf("** error: %s\n",errbuf);
	
	strncpy(filterstring,"arp",8);
	pcap_compile(handle,&filter,filterstring,0,net);
	pcap_setfilter(handle,&filter);

	while(1) // begin to slowly gather the data (slow==safe)
	{
		pcap_loop(handle,1,gotarp,mydb); // get a packet
	}
}
