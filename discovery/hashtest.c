#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define GET_U32(p) (*((uint32_t *) p))
#define GET_U16(p) (*((uint16_t *) p))

#define ENTRIES 512
#define EUI48_HASH_TABLE_SIZE 1021 // must be prime
//#define EUI48_HASH_TABLE_SIZE 2029 // must be prime
//#define EUI48_HASH_TABLE_SIZE 4093 // must be prime

typedef unsigned char EUI48[6];

typedef uint32_t (* HASH_FUNC) (EUI48 eui48);

struct stuff
{
  EUI48 eui48;
};

typedef struct EUI48_HASH_TABLE_ENTRY 
{
  struct stuff * s;
  struct EUI48_HASH_TABLE_ENTRY * next;
} EUI48_HASH_TABLE_ENTRY;

EUI48_HASH_TABLE_ENTRY eui48_hash_table[EUI48_HASH_TABLE_SIZE];

/* The golden ratio: an arbitrary value */
#define JHASH_GOLDEN_RATIO	0x9e3779b9

static inline uint32_t hash_func1(EUI48 eui48)
{
  uint32_t a;
  uint32_t b;
  uint32_t c;
  
  a = GET_U32(eui48);
  b = GET_U16(eui48 + 4);

  a += JHASH_GOLDEN_RATIO;
  b += JHASH_GOLDEN_RATIO;
  c = 0;

  a -= b; a -= c; a ^= (c>>13); 
  b -= c; b -= a; b ^= (a<<8); 
  c -= a; c -= b; c ^= (b>>13); 
  a -= b; a -= c; a ^= (c>>12);  
  b -= c; b -= a; b ^= (a<<16); 
  c -= a; c -= b; c ^= (b>>5); 
  a -= b; a -= c; a ^= (c>>3);  
  b -= c; b -= a; b ^= (a<<10); 
  c -= a; c -= b; c ^= (b>>15); 

  return c % EUI48_HASH_TABLE_SIZE;
}

static inline uint32_t hash_func2(EUI48 eui48)
{
  uint32_t ret;

  ret = (eui48[0] << 1) + 
    (eui48[1] >> 3) + 
    (eui48[2] << 5) +
    (eui48[3] >> 7) +
    (eui48[4] << 9) +
    (eui48[5] >> 14);

  return ret % EUI48_HASH_TABLE_SIZE;
}

static inline uint32_t hash_func3(EUI48 eui48)
{
  uint32_t ret;

  ret = (eui48[0] << 9) +
    eui48[1] * 1073 +
    eui48[2] * 255 +
    eui48[3] * 47 +
    eui48[4] * 307 +
    eui48[5];
  return ret % EUI48_HASH_TABLE_SIZE;
}

void * xmalloc(size_t size)
{
  void * ret;
  ret = malloc(size);
  if(ret == NULL) {
    fprintf(stderr, "malloc() failed: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  return ret;
}

static void get_rand_eui48(EUI48 eui48)
{
  int i;
  
  for(i = 0; i < 6; ++i) {
    eui48[i] = (lrand48() % 256U);
  }
}

void init_eui48_hash(void)
{
  unsigned int i;
  EUI48_HASH_TABLE_ENTRY * ent;
  EUI48_HASH_TABLE_ENTRY * next;

  for(i = 0; i < EUI48_HASH_TABLE_SIZE; ++i) {
    ent = &eui48_hash_table[i];
    do {
      next = ent->next;
      if(ent->s != NULL) {
	free(ent->s);
      }
      if(ent != &eui48_hash_table[i]) {
	free(ent);
      }
      ent = next;
    } while(next != NULL);
  }

  memset(eui48_hash_table, 0, sizeof(eui48_hash_table));
}

unsigned int hash_eui48(EUI48 eui48, HASH_FUNC hash_func)
{
  uint32_t hash;

  hash = hash_func(eui48);
  return hash % EUI48_HASH_TABLE_SIZE;
}

void add_eui48(EUI48 eui48, HASH_FUNC hash_func)
{
  EUI48_HASH_TABLE_ENTRY * ent;

  ent = &eui48_hash_table[hash_func(eui48)];

  while(ent->next != NULL) {
    ent = ent->next;
  }

  if(ent->s != NULL) {
    EUI48_HASH_TABLE_ENTRY * new;

    new = xmalloc(sizeof(EUI48_HASH_TABLE_ENTRY));
    new->next = NULL;
    ent->next = new;
    ent = ent->next;
  }

  ent->s = xmalloc(sizeof(struct stuff));

  memcpy(ent->s->eui48, eui48, 6);
}

void print_eui48(EUI48 eui48)
{
  printf("%02x:%02x:%02x:%02x:%02x:%02x\n", 
	 eui48[0],
	 eui48[1],
	 eui48[2],
	 eui48[3],
	 eui48[4],
	 eui48[5]);
}

void dump_collisions(void)
{
  int i;
  unsigned int entries;
  unsigned int collisions;
  unsigned int bucket_collisions;

  entries = 0;
  collisions = 0;
  bucket_collisions = 0;
  for(i = 0; i < EUI48_HASH_TABLE_SIZE; ++i) {
    EUI48_HASH_TABLE_ENTRY * ent;

    ent = &eui48_hash_table[i];
    if(ent->s != NULL) {
      //      printf("  Entry %u\n", i);
      entries++;
    }
    else {
      //      printf("  Entry %u (empty)\n", i);
    }

    bucket_collisions = 0;
    while(ent->next != NULL) {
      bucket_collisions++;
      //      printf("  Entry %u:%u\n", i, bucket_collisions);
      collisions++;
      entries++;
      ent = ent->next;
    }
  }

  printf("Entries: %u\n", entries);
  printf("Collisions: %u/%u (%.01f %%)\n", collisions, EUI48_HASH_TABLE_SIZE,
	 ((float) collisions / (float) EUI48_HASH_TABLE_SIZE) * 100.0f);
}

int main(void)
{
  int i;
  EUI48 eui48;

  srand48(getpid());
  //	srand48(1);

  init_eui48_hash();
  for(i = 0; i < ENTRIES; ++i) {
    get_rand_eui48(eui48);
    add_eui48(eui48, hash_func1);
  }
  dump_collisions();


  init_eui48_hash();
  for(i = 0; i < ENTRIES; ++i) {
    get_rand_eui48(eui48);
    add_eui48(eui48, hash_func2);
  }
  dump_collisions();

  init_eui48_hash();
  for(i = 0; i < ENTRIES; ++i) {
    get_rand_eui48(eui48);
    add_eui48(eui48, hash_func3);
  }
  dump_collisions();

  return EXIT_SUCCESS;
}
