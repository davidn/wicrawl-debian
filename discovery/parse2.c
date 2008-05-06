#include "wicrawl.h"

/**
 * Parse a channel specification.
 *
 * A channel specification is a character string containing the
 * following characters:
 *
 *   Digits: 0-9
 *   Dash: -
 *   Space: ' '
 *   Comma: ,
 *
 * Examples:
 *
 *  1
 *  1,2,3,4
 *  1, 2, 3, 4
 *  1, 3-5, 7-20, 69,42
 *
 * The formal grammar is, with spaces ignored for simplicity:
 *
 * DIGIT = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9
 * NONZERO = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9
 * DASH = '-'
 * SPACE = ' '
 * COMMA = ','
 *
 * channel ::= NONZERO | <channel> DIGIT
 * channel_range ::= channel DASH channel
 * channels ::= <channel> | <channel_range>
 * channel_specification ::= <channels> | <channels> COMMA <channels>
 *
 * If something is wrong with the channel specification, 0 is
 * returned.  If the channel specification is parsed correctly, the
 * number of channels written to the channels array is returned.
 */
int parse(char * string, channel_t * channels)
{
  char * p;
  unsigned long * accum;
  unsigned long accum1;
  unsigned long accum2;
  size_t channel;

  p = string;
  accum1 = accum2 = 0;
  accum = &accum1;
  channel = 0;

  while(1) {
    if(*p >= '0' && *p <= '9') {
      *accum *= 10;
      *accum += (*p - '0');
      if(*accum > UCHAR_MAX) {
	fprintf(stderr, "Bad channel number (too high).\n");
	return 0;
      }
      if(*accum == 0) {
	fprintf(stderr, "Zero is not a valid channel number.\n");
	return 0;
      }
    }
    else if(*p == '-') {
      /* Two dashes in a row aren't allowed. */
      if(*(p + 1) == '-') {
	fprintf(stderr, "Invalid channel list.\n");
	return 0;
      }

      /* Ranges like a-b-c aren't allowed either. */
      if(accum == &accum2) {
	fprintf(stderr, "Invalid channel list.\n");
	return 0;
      }

      accum = &accum2;
      channels[channel] = *accum;
      channel++;
    }
    else if(*p == ' ') {
      /* Ignore spaces. */
    }
    else if(*p == ',' || *p == '\0') {
      if(accum == &accum1) {
	channels[channel] = *accum;
	channel++;
	*accum = 0;
      }
      else if(accum == &accum2) {
	int i;
	
	if(accum2 - accum1 + 1 > MAX_CHANNELS - channel) {
	  fprintf(stderr, "Too many channels.\n");
	  return 0;
	}
       
	for(i = accum1; i <= accum2; ++i) {
	  channels[channel] = i;
	  channel++;
	}

	accum1 = accum2 = 0;
	accum = &accum1;
      }
      else {
	fprintf(stderr, "Wtf\n");
	return 0;
      }

      if(*p == '\0') {
	/* This is the only way to get out successfully. */
	return channel;
      }
    }
    else {
      fprintf(stderr, "Invalid channel list.\n");
      return 0;
    }

    p++;

    /* Sanity check */
    if(channel >= MAX_CHANNELS) {
      fprintf(stderr, "Wtf++\n");
      return 0;
    }
  }
}

#ifndef __APCORE__ 

void usage(void)
{
  fprintf(stderr, "Usage: parse2 PARSESTRING\n");
  exit(EXIT_FAILURE);
}

int main(int argc, char * argv[])
{
  int i;
  channel_t channels[MAX_CHANNELS];

  if(argc < 2) {
    usage();
  }

  memset(channels, 0, sizeof(channels));

  if(parse(argv[1], channels) == 0) {
    return EXIT_FAILURE;
  }

  for(i = 0; i < MAX_CHANNELS; ++i) {
    if(channels[i]) {
      printf("%u\n", channels[i]);
    }
  }

  return EXIT_SUCCESS;
}

#endif /* ! __APCORE__ */
