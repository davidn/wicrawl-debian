#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#define MAX_CHANNELS 256

unsigned long channels[MAX_CHANNELS];

void usage(void)
{
  fprintf(stderr, "Usage: parse CHANNELSTRING\n");
  exit(EXIT_FAILURE);
}

enum states
{
  S_INITIAL,
  S_DIGIT,
  S_COMMA,
  S_DASH,
  S_ERROR,
  S_END
};

void parse(char * str, unsigned long * out)
{
  char * p;
  enum states state;
  unsigned int chanidx;
  unsigned long accum1, accum2;
  unsigned long * accum;

  p = str;
  chanidx = 0;
  accum1 = 0;
  accum2 = 0;
  accum = &accum1;
  state = S_INITIAL;

  while(*p != '\0') {
    switch(state)
    {
    case S_INITIAL:
      if(! isdigit(*p)) {
	state = S_ERROR;
	break;
      }

      state = S_DIGIT;
      if(accum1 != 0) {
	out[chanidx] = accum1;
      }
      
      accum1 = 0;
      accum2 = 0;
      
      accum1 = *p - '0';
      
      break;

    case S_COMMA:
      chanidx++;
      state = S_INITIAL;
      continue;

    case S_DIGIT:
      if(*p == ',') {
	state = S_COMMA;
	out[chanidx] = *accum;
	break;
      }
      else if(*p == '-') {
	state = S_DASH;
	break;
      }
      else if(isdigit(*p)) {
	*accum *= 10;
	*accum += *p - '0';
	break;
      }
      else {
	state = S_ERROR;
	break;
      }

      break;
    case S_DASH:
      
      break;

    case S_ERROR:
      fprintf(stderr, "broke\n");
      return;
      break;

    case S_END:
      
      break;
    }

    p++;
  }

  if(accum1) {
    out[chanidx] = *accum;
  }
}

int main(int argc, char * argv[]) 
{
  int i;

  if(argc < 2) {
    usage();
  }

  memset(channels, 0, sizeof(channels));
  parse(argv[1], channels);

  for(i = 0; i < sizeof(channels) / sizeof(channels[0]); ++i) {
    if(channels[i]) {
      printf("%lu\n", channels[i]);
    }
  }
  
  return EXIT_SUCCESS;
}
