#include"pul.h"

int clearinfo(struct puldb* mydb)
{
	mydb->gotgwip=0;
	mydb->gotgwmac=0;
	mydb->gotnetmask=0;
}
