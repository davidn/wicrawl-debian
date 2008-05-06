/*
 * $Id: util.h,v 1.6 2006-09-30 08:11:58 jspence Exp $
 *
 */

#ifndef _UTIL_H
#define _UTIL_H

#include <time.h>

#define DEF_LINELEN 1024
#define STRINGS_LEN 8

#define ISSTRING(x) (x>32 && x<128)

#define GET_U32(p) (*((uint32_t *) p))
#define GET_U16(p) (*((uint16_t *) p))
#define GET_U8(p) (*((uint8_t *) p))

#define GET_S32(p) (*((int32_t *) p))
#define GET_S16(p) (*((int16_t *) p))
#define GET_S8(p) (*((int8_t *) p))

#ifndef MIN
#define MIN(_X_, _Y_) (_X_ < _Y_ ? _X_ : _Y_)
#endif

#ifndef MAX
#define MAX(_X_, _Y_) (_X_ < _Y_ ? _Y_ : _X_)
#endif

#define BREAKPOINT __asm ( "int $3" );

typedef struct strings_t {
  char strings[DEF_LINELEN];
  int start;
} strings_t;

void * xmalloc(size_t size);
void xfree(void * p);
void tokenize(char *usrc, char **tokens, int *ntokens);
unsigned char *geek_print(unsigned int);
unsigned char *mac2ascii(const unsigned char *);
unsigned char *hex2ascii(unsigned char *, int);
unsigned char *string_printable(unsigned char *);
unsigned char *uptime(time_t);
int strings_clear(strings_t *s);
int strings_add(strings_t *s, unsigned char *p, int l);

#define _BYTES_PER_LINE 16
void hexdump(const uint8_t * buf, unsigned int buflen);

int encodestream( unsigned char * outbuf, unsigned int outbuflen, 
		   unsigned char * inbuf, unsigned int inbuflen );


#endif /* _UTIL_H */
