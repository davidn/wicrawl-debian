// TODO: This command really shouldnt be needed, but for now it is

#include"pul.h"

int resolvegw(struct puldb* mydb)
{
	FILE *fd;
	char buf[256], buf2[256];
	char *ptr, *ptr2;
	int i;

	printf("\n**  resolving gateway..");

	/* flush buffer */
	memset(buf, '\0', sizeof(buf));

	system("rm /tmp/pulroute"); // so as to not create some bad things
	sprintf(buf,"arping -I %s %02x:%02x:%02x:%02x:%02x:%02x >/tmp/pulroute",mydb->interface,
			mydb->gwmac[0],mydb->gwmac[1],mydb->gwmac[2],mydb->gwmac[3],mydb->gwmac[4],mydb->gwmac[5]);
	
	fprintf(stderr,"running '%s'\n",buf);
	system(buf);

	//ptr = REDIRECT + 3; /* REDIRECT+3 == '/tmp/pulroute' */

	fd = fopen("/tmp/pulroute", "r");

	memset(buf, '\0', sizeof(buf));

	// parse the temp file
	while (fgets(buf, sizeof(buf)-1, fd))
	{
		if (ptr = strstr(buf, "from "))
		{
			ptr +=5;
			ptr2 = strstr(ptr, " ");


			/* yes.  I know.  potential for overflow because
			 * im only copying for length between pointers
			 * without checking bounds for buffers...
			 */


			memset(buf2, '\0', sizeof(buf2));
			strncpy(buf2, ptr, (ptr2 - ptr));


			memset(buf, '\0', sizeof(buf));	

			ptr = strstr(buf2, ".");
			strncpy(buf, buf2, (ptr - buf2));
			mydb->gwip[0]=atoi(buf);

			memset(buf, '\0', sizeof(buf));
			ptr2=++ptr;
			ptr = strstr(ptr2, ".");
			strncpy(buf, ptr2, (ptr - ptr2));
			mydb->gwip[1]=atoi(buf);

			memset(buf, '\0', sizeof(buf));
			ptr2=++ptr;
			ptr = strstr(ptr2, ".");
			strncpy(buf, ptr2, (ptr - ptr2));
			mydb->gwip[2]=atoi(buf);


			memset(buf, '\0', sizeof(buf));
			ptr2 = ++ptr;
			strcpy(buf, ptr2);
			mydb->gwip[3]=atoi(buf);

			break;
		}

	/* silly h4x0r, skripz are for kids! */
	/* its current 1:22 AM, and my roflcopter is waiting */	
	}
	fclose(fd);

	fprintf(stderr,"**  gateway ip resolved to %hi.%hi.%hi.%hi\n",
			mydb->gwip[0],mydb->gwip[1],mydb->gwip[2],mydb->gwip[3]);
	
	return 1;
}
