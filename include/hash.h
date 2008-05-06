#ifndef _HASH_H
#define _HASH_H

#define BSSID_HASH_SIZE 1021 // must be prime
//#define EUI48_HASH_SIZE 2029 // must be prime
//#define EUI48_HASH_SIZE 4093 // must be prime

/* The golden ratio: an arbitrary value */
#define JHASH_GOLDEN_RATIO	0x9e3779b9

typedef struct bssid_hash_ent
{
  struct ssid_info * s;
  struct bssid_hash_ent * next;
} bssid_hash_ent;

bssid_hash_ent * add_bssid(bssid_t bssid);
bssid_hash_ent * find_bssid(const bssid_t bssid);
void update_bssid(const bssid_t bssid, const radio_hdr_info_t * rhdr);
void init_bssid_hash(void);

inline void set_cos(const bssid_hash_ent * ent, enum cos_state state);
inline void clear_cos(const bssid_hash_ent * ent);
inline int has_cos(const bssid_hash_ent * ent);

#endif /* _HASH_H */

