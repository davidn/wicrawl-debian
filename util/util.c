/*
 * $Id: util.c,v 1.6 2006-10-17 20:10:44 jspence Exp $
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>

#include "util.h"

void *
xmalloc(size_t size)
{
  void * ret;

  ret = malloc(size);
  if(ret == NULL) {
    fprintf(stderr, "malloc() failed: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  return ret;
}

void 
xfree(void * p)
{
  free(p);
}

void
tokenize(char *usrc, char **tokens, int *ntokens) {
  int i;
  static char src[DEF_LINELEN];
  
  strncpy(src, usrc, DEF_LINELEN);
  for(i=1,tokens[0] = strtok(src, " "); (tokens[i]=strtok(NULL, " ")); i++)
    ;
  *ntokens = i;
}

unsigned char *
geek_print(unsigned int n) {
  static unsigned char buf[DEF_LINELEN];
  
  if(n < 1024)
    snprintf((char *) buf, DEF_LINELEN, "%d", n);
  else if(n < 1024 * 1024)
    snprintf((char *) buf, DEF_LINELEN, "%.1fK", (float)n/(float)1024);
  else if(n < 1024 * 1024 * 1024)
    snprintf((char *) buf, DEF_LINELEN, "%.1fM", (float)n/(float)1048576);
  else
    snprintf((char *) buf, DEF_LINELEN, "%.1fG", (float)n/(float)1073741824);
  return buf;
}

unsigned char *
uptime(time_t start) {
  static unsigned char buf[DEF_LINELEN];
  time_t uptime;
  struct tm *tm;

  uptime = time(NULL) - start;
  tm = gmtime(&uptime);
  if(tm->tm_yday)
    snprintf((char *) buf, DEF_LINELEN, "%d days, %02d:%02d:%02d", 
	     tm->tm_yday, tm->tm_hour, tm->tm_min, tm->tm_sec);
  else
    snprintf((char *) buf, DEF_LINELEN, "%02d:%02d:%02d", 
	     tm->tm_hour, tm->tm_min, tm->tm_sec);
  return buf;
}

unsigned char *
mac2ascii(const unsigned char *p) {
  static unsigned char out[DEF_LINELEN];
  
  snprintf((char *) out, DEF_LINELEN, "%02x:%02x:%02x:%02x:%02x:%02x", 
	   p[0], p[1], p[2], p[3], p[4], p[5]);
  return out;
}

unsigned char *
hex2ascii(unsigned char *p, int l) {
  int i;
  static unsigned char out[DEF_LINELEN];
  char temp[DEF_LINELEN];

  out[0] = '\0';
  for(i=0; i<l; i++) {
    snprintf(temp, DEF_LINELEN, "%02x", p[i]);
    strncat((char *) out, temp, DEF_LINELEN);
  }
  return out;
}

unsigned char *
string_printable(unsigned char *in) {
  static unsigned char out[DEF_LINELEN];
  char octal[DEF_LINELEN];
  unsigned char *ret;

  memset(out, '\0', DEF_LINELEN);
  ret = out;

  while(*in) {
    if(*in >= 32 && *in <= 127) {
      *ret++ = *in;
    } else if(*in == '\\') {
      *ret++ = '\\';
      *ret++ = '\\';
    } else if(*in == '\a') {
      *ret++ = '\\';
      *ret++ = 'a';
    } else if(*in == '\b') {
      *ret++ = '\\';
      *ret++ = 'b';
    } else if(*in == '\n') {
      *ret++ = '\\';
      *ret++ = 'n';
    } else if(*in == '\r') {
      *ret++ = '\\';
      *ret++ = 'r';
    } else {
      snprintf(octal, DEF_LINELEN, "\\%03o", *in);
      strncat((char *) ret, octal, strlen(octal));
      ret += strlen(octal);
    }
    in++;
  }
  return out;
}


int
strings_clear(strings_t *s) {
  memset(s->strings, 0x20, sizeof(s->strings));
  s->start = 0;
  return 0;
}

int
strings_add(strings_t *s, unsigned char *p, int l) {
  char temp[DEF_LINELEN];
  int i;
  int j, k;

  j = 0;
  for(i=0; i<l; i++) {

    if(j == DEF_LINELEN) {
      for(k=0; k<j; k++) {
	s->strings[s->start] = temp[k];
	s->start = (s->start + 1) % sizeof(s->strings); 
      }
      j=0;
    }

    if(ISSTRING(p[i]))
      temp[j++] = p[i];
    else {      
      if(j >= STRINGS_LEN) {
	for(k=0; k<j; k++) {
	  s->strings[s->start] = temp[k];
	  s->start = (s->start + 1) % sizeof(s->strings);
	}
	s->strings[s->start] = ' ';
	s->start = (s->start + 1) % sizeof(s->strings);
      }
      j = 0;
    }
  }
  return 0;
}

void hexdump(const uint8_t * buf, unsigned int buflen) {
  int i;
  int j;
  int n;

  for(i = 0; i < buflen; i += _BYTES_PER_LINE) {
    if(i >= buflen)
      break;

    /* Left column */
    printf("%08x  ", i);

    /* Center column */
    if(i + _BYTES_PER_LINE >= buflen)
      n = buflen - i;
    else
      n = _BYTES_PER_LINE;

    for(j = 0; j < n; ++j) {
      printf("%02x ", buf[i + j]);
    }

    /* Right column */
    printf(" |");

    for(j = 0; j < n; ++j) {
      if(isprint(buf[i + j]))
	printf("%c", buf[i + j]);
      else
	printf(".");
    }
    printf("|\n");
  }
}

#if defined(__i386__)

typedef struct prof_t 
{
  uint32_t t2_upper, t2_lower;
  uint32_t t1_upper, t1_lower;
} prof_t;

#define READ_TSC(upper, lower) \
__asm("sfence\n" \
      "rdtsc\n" \
      "movl %%edx, %0\n" \
      "movl %%eax, %1\n" : \
      "=m" (upper), "=m" (lower) : \
      : \
      "%eax", "%edx" \
      ) 

uint32_t tsc_delta(uint32_t t1_upper, uint32_t t1_lower, 
		   uint32_t t2_upper, uint32_t t2_lower)
{
  int32_t upper_delta;
  int32_t lower_delta;

  upper_delta = t2_upper - t1_upper;
  lower_delta = t2_lower - t1_lower;

  // FIXME check this math
  if(lower_delta < 0 && upper_delta > 0) {
    return (UINT_MAX - t1_lower) + t2_lower;
  }
  
  return lower_delta;
}

static uint32_t kHz;
static uint32_t noop_cycles;

inline void start_prof(prof_t * prof)
{
  READ_TSC(prof->t1_upper, prof->t1_lower);
}

inline void end_prof(prof_t * prof)
{
  READ_TSC(prof->t2_upper, prof->t2_lower);
}

void init_prof(prof_t * prof)
{
  int i;
  FILE * fp;
  uint32_t olddelta;
  uint32_t delta;
  prof_t nothing;

  fp = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
  if(fp == NULL) {
    fprintf(stderr, "Could not open cpuinfo from sysfs: %s\n", strerror(errno));
    return;
  }

  fscanf(fp, "%u", &kHz);
  printf("DEBUG: detected %u MHz CPU\n", kHz / 1000);

  start_prof(&nothing);
  end_prof(&nothing);
  olddelta = tsc_delta(nothing.t1_upper, nothing.t1_lower, 
		       nothing.t2_upper, nothing.t2_lower);
  for(i = 0; i < 100; ++i) {
    start_prof(&nothing);
    end_prof(&nothing);
    delta = tsc_delta(nothing.t1_upper, nothing.t1_lower, 
		      nothing.t2_upper, nothing.t2_lower);
    if(delta != olddelta) {
      printf("DEBUG: cycle count for a no-op is changing!\n");
    }
    olddelta = delta;
  }

  noop_cycles = delta;
  printf("DEBUG: noop cycles: %u\n", noop_cycles);

  fclose(fp);
}

void dump_stats(prof_t * prof)
{
  uint32_t delta;

  delta = tsc_delta(prof->t1_upper, prof->t1_lower, 
		    prof->t2_upper, prof->t2_lower);

  delta -= noop_cycles;

  printf("  %u cycles (%g usec)\n", delta, 
	 ((double) delta / ((double) kHz * 1000.0)) * 1000000.0 );
}
#endif /* __i386__ */
