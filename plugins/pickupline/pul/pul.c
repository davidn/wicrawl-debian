/*
		This is the main function in the program.  It runs the whole show.
		If you follow along with the comments, it should all be pretty clear
		how the program works.
 */


#include"pul.h"

int main()
{
	//  ** make sure you have all the permissions **
	
	setuid(0);
	if(getuid())
	{
		printf("error: you must be root to run this program\n");
		return 0;
	}
	//  ** create the database **
	
	struct puldb* mydb;                 // name the database
	mydb=malloc(sizeof(struct puldb));  // allocate the database
	puldbinit(mydb);                    // initalize the database
	
	char buffer[80]; // the input buffer
	

	// ** start the program! **
	
	printf("\npickupline 0.5.1 - pickupline.berlios.de\n");
	printf(  "interface set to %s\n",mydb->interface);
	printf(  "type 'help' if you need it\n\n");
	
	while(1)
	{
		printf("> ");            // print the prompt
		fgets(buffer,75,stdin);  // ask for input
		if(strlen(buffer)<2)continue;
		
		if(!strncmp(buffer,"exit\n",10))return 0;
		
		else if(!strncmp(buffer,"start\n",10))dropline(mydb);
		else if(!strncmp(buffer,"list\n",10))list(mydb);
		else if(!strncmp(buffer,"spoof\n",10))spoof(mydb);
		else if(!strncmp(buffer,"resolvegw\n",15))resolvegw(mydb);
		
		// setting related commands
		else if(!strncmp(buffer,"settings\n",10))settings(mydb);
		else if(!strncmp(buffer,"interface\n",15))interface(mydb);
		else if(!strncmp(buffer,"dhcp\n",15))dhcp(mydb);
		else if(!strncmp(buffer,"clearinfo\n",15))clearinfo(mydb);

		else if(!strncmp(buffer,"help\n",10))help();
		else printf("EE command not found (type 'help' if you need it)\n");
	}
}
