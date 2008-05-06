/**
 * @file hash.c
 *
 * This module implements a BSSID hash table for storing wireless
 * network data.  The table size is fixed at creation, and collisions
 * are handled by adding new entries to a singly linked list that
 * hangs off the first entry in each hash slot.
 */
#include "wicrawl.h"

bssid_hash_ent bssid_hash_table[BSSID_HASH_SIZE];

/**
 * Port of the Jenkins hash from the Linux kernel.  This function maps
 * from the 48-bit EUI48 domain to the range of 32-bit integers.
 *
 * @param bssid The bssid to hash. 
 *
 * @return The hash of the BSSID.
 */
static inline uint32_t hash_func1(const bssid_t bssid)
{
  uint32_t a;
  uint32_t b;
  uint32_t c;
  
  a = 0;
  b = 0;
  a = GET_U32(bssid);
  b = GET_U16(bssid + 4);

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

  return c % BSSID_HASH_SIZE;
}

/**
 * Initialize the bssid hash tables, clearing them if necessary.
 */ 
void init_bssid_hash(void)
{
  unsigned int i;
  bssid_hash_ent * ent;
  bssid_hash_ent * next;

  for(i = 0; i < BSSID_HASH_SIZE; ++i) {
    ent = &bssid_hash_table[i];
    do {
      next = ent->next;
      if(ent->s != NULL) {
	free(ent->s);
      }
      if(ent != &bssid_hash_table[i]) {
	free(ent);
      }
      ent = next;
    } while(next != NULL);
  }

  memset(bssid_hash_table, 0, sizeof(bssid_hash_table));
}

/**
 * Add a BSSID to the BSSID hash table.
 *
 * @param bssid [in] The bssid to add to the hash table.
 *
 * @return A pointer to the newly added BSSID table entry.
 */
bssid_hash_ent * add_bssid(bssid_t bssid)
{
  int collision;
  bssid_hash_ent * ent;
  bssid_hash_ent * new;
 
  ent = &bssid_hash_table[hash_func1(bssid)];

  if(ent->s != NULL) {
    collision = 1;
    /* If the slot is occupied, walk the list of entries to find a free one. */
    while(ent->next != NULL) {
      ent = ent->next;
    }

    /* Allocate some memory for a new hash slot. */
    new = xmalloc(sizeof(bssid_hash_ent));
    memset(new, 0, sizeof(bssid_hash_ent));
    new->next = NULL;

  }
  else {
    collision = 0;
    new = ent;
  }

  /* Allocate memory for the slot contents and copy them in. */
  new->s = xmalloc(sizeof(struct ssid_info));
  memset(new->s, 0, sizeof(struct ssid_info));

  memcpy(&new->s->bssid, bssid, sizeof(bssid_t));

  if(collision == 1) {
    /* Link the new entry in. */
    ent->next = new;
  }

  return new;
}

/**
 * Print a BSSID in hex-colon format.
 *
 * @param bssid [in] The bssid to print.
 */
void print_bssid(bssid_t bssid)
{
  printf("%02x:%02x:%02x:%02x:%02x:%02x\n", 
	 bssid[0],
	 bssid[1],
	 bssid[2],
	 bssid[3],
	 bssid[4],
	 bssid[5]);
}

/**
 * See if a BSSID is present in the hash table.  If the hash table
 * isn't very full, this routine should be constant-time.  Because
 * collisions are handled via a linked list, the search time
 * approaches linear as the table gets impacted.
 *
 * @param bssid [in] The BSSID to add to the hash table.
 *
 * @return A pointer to the entry if found, or NULL otherwise.
 */
bssid_hash_ent * find_bssid(const bssid_t bssid)
{
  struct bssid_hash_ent * ent;
  struct ssid_info * s;

  /* Get a pointer to the hash slot, and see if there's anything there. */
  ent = &bssid_hash_table[hash_func1(bssid)];
  if(ent->s == NULL) {
    return NULL;
  }

  /* The first one didn't match.  Follow the links until we find it. */
  while(ent != NULL) {
    s = ent->s;
    if(! memcmp(bssid, s->bssid, sizeof(bssid_t))) {
      return ent;
    }
    ent = ent->next;
  }

  return NULL;
}

/**
 * Update some statistics for an ssid that we've captured a frame from.
 *
 * @param bssid [in] The BSSID of the station to update the statistics
 * for.
 *
 * @param rhdr [in] A pointer to a radio header from a captured frame.
 */
void update_bssid(const bssid_t bssid, const radio_hdr_info_t * rhdr)
{
  bssid_hash_ent * ent;

  ent = find_bssid(bssid);
  if(ent == NULL) {
    fprintf(stderr, "DEBUG: Can't find bssid %s in update_bssid()...\n", mac2ascii(bssid));
    return;
  }
  ent->s->signal_dBm = rhdr->signal_dBm;
  ent->s->broadcasts++;
}

/**
 * Dump some collision statistics for the hash table.  For debugging
 * purposes only.
 */
void dump_collisions(void)
{
  int i;
  unsigned int entries;
  unsigned int collisions;
  unsigned int bucket_collisions;

  entries = 0;
  collisions = 0;
  bucket_collisions = 0;
  for(i = 0; i < BSSID_HASH_SIZE; ++i) {
    bssid_hash_ent * ent;

    ent = &bssid_hash_table[i];
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
  printf("Collisions: %u/%u (%.01f %%)\n", collisions, BSSID_HASH_SIZE,
	 ((float) collisions / (float) BSSID_HASH_SIZE) * 100.0f);
}

inline void set_cos(const bssid_hash_ent * ent, const enum cos_state state)
{
  ent->s->cos_state = state;
}

inline void clear_cos(const bssid_hash_ent * ent)
{
  ent->s->cos_state = NO_COS;
}

/**
 * Check whether there is any pending CoS on a particular BSSID.
 *
 * @param ent [in] A pointer to the BSSID hash entry to check for
 * pending CoS.
 *
 * @return 1 if there is pending CoS for the given bssid, 0 otherwise.
 */
inline int has_cos(const bssid_hash_ent * ent)
{
  if(ent->s->cos_state != NO_COS) {
    return 1;
  }
  else {
    return 0;
  }
}
