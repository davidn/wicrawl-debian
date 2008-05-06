#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <err.h>

// unix socket
int s;

void read_loop(void)
{
  int rc;
  char * rets;
  char buf[512];

  while(1) {
    memset(buf, 0, sizeof(buf));
    
    rets = fgets(buf, sizeof(buf) - 1, stdin);
    if(rets == NULL)
      warn("fgets() failed");
    
    rc = send(s, buf, strlen(buf) - 1, 0);
    if(rc == -1)
      err(1, "send() failed");
    
    rc = recv(s, buf, sizeof(buf) - 1, 0);
    if(rc == -1)
      err(1, "recv() failed");
    buf[rc] = '\0';

    printf("%s\n", buf);
  }
}

int main(int argc, char * argv[])
{
  int rc;

  struct sockaddr_un sun;

  if(argc < 2) {
    fprintf(stderr, "Usage: testclient SOCKET\n");
    return EXIT_FAILURE;
  }

  s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if(s == -1)
    err(1, "socket() failed");

  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  strncpy(sun.sun_path, argv[1], sizeof(sun.sun_path) - 1);

  rc = connect(s, (struct sockaddr *) &sun, sizeof(sun));
  //  rc = bind(s, (struct sockaddr *) &sun, sizeof(sun));
  if(rc == -1)
    err(1, "connect() failed");

  read_loop();

  return EXIT_SUCCESS;
}
