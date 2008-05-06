#include "wicrawl.h"

void warn(const char * format, ...)
{
  char buf[1024];
  char * p;
  unsigned int written;
  int count;

  p = buf;
  written = 0;
  vsnprintf_loop(buf, sizeof(buf) - sizeof(buf[0]), format, &count);
  p += count;
  written += count;

  if(errno) {
    count += snprintf(p, sizeof(buf) - sizeof(buf[0]) - written,
		      ": %s", strerror(errno));
  }

  fprintf(stderr, buf);
}

void warnx(const char * format, ...)
{
}
