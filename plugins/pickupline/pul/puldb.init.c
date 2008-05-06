#include"pul.h"

int puldbinit(struct puldb* mydb)
{
	strncpy(mydb->interface,"eth1",10);
	mydb->gotgwmac=0;
	mydb->gotgwip=0;
	mydb->gotnetmask=0;
	mydb->sniffing=0;
	mydb->head=0;
}
