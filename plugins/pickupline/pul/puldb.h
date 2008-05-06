struct puldbnode // this contains information on the targets
{
	u_char ip[4];  // the ip of the target
	u_char mac[6]; // the mac of the target

	struct puldbnode* next; // this points to the next target in the list
};

struct puldb
{
	char interface[10]; // the default is "eth1"

	int  gotgwmac;   // do we have the mac of the gateway?
	int  gotgwip;    // do we have the ip  of the gateway?
	int  gotnetmask; // do we know what the netmask is?
	int  sniffing;   // is the sniffer running?

	u_char gwmac[6];    // the mac of the gateway
	u_char gwmacalt[6]; // another possible mac for the gateway
	u_char gwip[4];     // the ip of the gateway
	u_char netmask[4];  // the netmask of the interface
	
	struct puldbnode* head; // this is the first in the linked list of tagets
};
