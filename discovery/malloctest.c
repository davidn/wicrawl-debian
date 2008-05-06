#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

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

void malloc_prof(void)
{
  int i;
  uint8_t * p;
  size_t size;
  prof_t prof;

  for(size = 1; size < 1024 * 1024; size *= 2) {
    printf("malloc size: %u\n", size);
    start_prof(&prof);
    p = malloc(size);
    end_prof(&prof);
    dump_stats(&prof);

    start_prof(&prof);
    memset(p, 0x69, size);
    end_prof(&prof);
    dump_stats(&prof);
     
    start_prof(&prof);
    free(p);
    end_prof(&prof);
    dump_stats(&prof);   
  }
}

int main(void)
{
  int i;
  prof_t prof;
  uint32_t upper, lower;

  READ_TSC(upper, lower);
  init_prof(&prof);
  start_prof(&prof);
  printf("%u, %u\n", upper, lower);
  end_prof(&prof);
  dump_stats(&prof);

  malloc_prof();
  start_prof(&prof);
  end_prof(&prof);
  dump_stats(&prof);

  start_prof(&prof);
  i = 1 + 1;
  end_prof(&prof);
  dump_stats(&prof);
  printf("%u\n", i);

  return EXIT_SUCCESS;
}
