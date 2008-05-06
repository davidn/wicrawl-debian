#include"pul.h"

int spoof(struct puldb* mydb)
{
	// TODO something nicer than calls to system() ...

	if(mydb->gotgwip==0)
	{
		fprintf(stderr,"EE sorry, you dont have enough information about the gateway\n");
		return 0;
	}
	
	struct puldbnode* current;
	current=mydb->head; // need to make this point someplace better
	if(current==0)
	{
		fprintf(stderr,"EE no targets collected yet\n");
	}

	int target;
	printf("target# ");
	scanf("%d",&target);
	getchar(); // need to get rid of the extra newline
	
	// traverse to the proper node
	for(;target>1;--target)
	{
		if(current)
		{
			current=current->next;
		}
		else 
		{
			fprintf(stderr,"EE target isnt in list\n");
			return 0;
		}
	}
	
	char buffer[100];
	
	printf("-- bringing down interface..\n");

	sprintf(buffer,"ifconfig %s down",mydb->interface);
	system(buffer);
	
	// spoof MAC address
	printf("-- setting mac to  %02x:%02x:%02x:%02x:%02x:%02x\n",
			current->mac[0],current->mac[1],current->mac[2],current->mac[3],current->mac[4],current->mac[5]);
	sprintf(buffer,"ifconfig %s hw ether %02x%02x%02x%02x%02x%02x",mydb->interface,
			current->mac[0],current->mac[1],current->mac[2],current->mac[3],current->mac[4],current->mac[5]);

	system(buffer);
	
	// spoof IP address
	printf("-- setting ip  to  %u.%u.%u.%u\n",
			current->ip[0],current->ip[1],current->ip[2],current->ip[3]);

	if(mydb->gotnetmask)
	{
		sprintf(buffer,"ifconfig %s up %u.%u.%u.%u netmask %u.%u.%u.%u",mydb->interface,
				current->ip[0],current->ip[1],current->ip[2],current->ip[3],
				mydb->netmask[0],mydb->netmask[1],mydb->netmask[2],mydb->netmask[3]);
		system(buffer);
	}

	else
	{
		printf("-- guessing netmask\n");
		sprintf(buffer,"ifconfig %s up %u.%u.%u.%u",mydb->interface,
				current->ip[0],current->ip[1],current->ip[2],current->ip[3]);
		system(buffer);
	}

	
	// set proper route
	printf("-- routing through %u.%u.%u.%u\n",
		mydb->gwip[0],mydb->gwip[1],mydb->gwip[2],mydb->gwip[3]);

	sprintf(buffer,"route add default gw %hi.%hi.%hi.%hi",
		mydb->gwip[0],mydb->gwip[1],mydb->gwip[2],mydb->gwip[3]);
	system(buffer);
}
