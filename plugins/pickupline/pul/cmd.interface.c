#include"pul.h"

int interface(struct puldb* mydb)
{
	fprintf(stderr,"interface: ");
	
	char buffer[10];
	fgets(buffer,8,stdin);
	buffer[strlen(buffer)-1]=0; // chop off \n
	
	strncpy(mydb->interface,buffer,10);
	fprintf(stderr,"** interface changed to %s\n",mydb->interface);
}
