#include"pul.h"

int dhcp(struct puldb* mydb)
{
	char buffer[40];
	sprintf(buffer,"pump -i %s",mydb->interface);
	system(buffer);;
}
