#include"pul.h"

extern snifftcp(struct puldb*);
extern sniffarp(struct puldb*);
extern sniffudp(struct puldb*);

int dropline(struct puldb* mydb)
{
	if(mydb->sniffing)
	{
		printf("EE the sniffer is already running\n");
		return 0;
	}
	
	mydb->sniffing=1; // to prevent multiple runs
	
	char cmdbuf[80];
	sprintf(cmdbuf,"ifconfig %s up",mydb->interface);
	system(cmdbuf);
	
	printf("** starting the sniffer\n");
	
	//  ** set the dropline **

	pthread_t tcpline; // name the dropline threads
	pthread_t arpline;
	pthread_t udpline;
	
	pthread_attr_t sametime;           // name the thread attributes
	pthread_attr_init(&sametime);      // init the thread attributes

	pthread_attr_setschedpolicy(&sametime,PTHREAD_INHERIT_SCHED);
		// set the sametime attribute to mean "execute the threads
		// at the same time"
	
	pthread_create(&tcpline,&sametime,snifftcp,(void*)mydb);
	pthread_create(&arpline,&sametime,sniffarp,(void*)mydb);
	pthread_create(&udpline,&sametime,sniffudp,(void*)mydb);
		// start the dropline thread, which will execute the function "line"
		// at the same time as the rest of the program, and pass it a
		// pointer to the pickupline database
}
