#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>


int main (int argc , char *argv[]){
char interface[32];
char  essid[32];


if(argc == 1 ){
	printf("Usage  is :   associated <interface>\n");
	return 0;
}

strncpy(interface,argv[1],32);
struct iwreq wrq;
char buf[33];
int s;

memset (buf,0,sizeof(buf));
memset (&wrq,0,sizeof(wrq));

strcpy(wrq.ifr_name , interface);
wrq.u.essid.pointer = (caddr_t) buf;
wrq.u.essid.length = 33;
s = socket (AF_INET,SOCK_DGRAM,0);
	if(s == -1){
		printf("socket failed");
		return 0;
	}
if(ioctl(s,SIOCGIWESSID,&wrq) < 0){
	printf("Error : Can't get essid ");
	return -1;

}else{
	if(wrq.u.essid.length > 0 ) {
		printf("1\n");
		
		return EXIT_SUCCESS;
	}else{
		printf("0\n");
		return 0;
	}
}


}

