// Shamelessly stolen from http://base64.sourceforge.net/b64.c

#include "wicrawl.h"

/*
** Translation Table as described in RFC1113
*/
static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
** Translation Table to decode (created by author)
*/
static const char cd64[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

/*
** encodeblock
**
** encode 3 8-bit binary bytes as 4 '6-bit' characters
*/
void encodeblock( unsigned char in[3], unsigned char out[4], int len )
{
    out[0] = cb64[ in[0] >> 2 ];
    out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
    out[2] = (unsigned char) (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
    out[3] = (unsigned char) (len > 2 ? cb64[ in[2] & 0x3f ] : '=');
}

int encodestream( unsigned char * outbuf, unsigned int outbuflen, 
		  unsigned char * inbuf, unsigned int inbuflen )
{
  unsigned char * outp;
  unsigned char * inp;
  int outleft;
  int inleft;
  int written;

  outp = outbuf;
  inp = inbuf;
  outleft = outbuflen;
  inleft = inbuflen;
  written = 0;

  if(outbuflen < (inbuflen * 4) / 3) {
    fprintf(stderr, "encodestream() got called with nonsensical sizes\n");
    return -1;
  }

  do {
    encodeblock(inp, outp, inleft);
    outp += 4;
    outleft -= 4;
    inp += 3;
    inleft -= 3;
    written += 4;
  } while(inleft > 0);

  return written;
}

/*
** decodeblock
**
** decode 4 '6-bit' characters into 3 8-bit binary bytes
*/
void decodeblock( unsigned char in[4], unsigned char out[3] )
{   
    out[ 0 ] = (unsigned char ) (in[0] << 2 | in[1] >> 4);
    out[ 1 ] = (unsigned char ) (in[1] << 4 | in[2] >> 2);
    out[ 2 ] = (unsigned char ) (((in[2] << 6) & 0xc0) | in[3]);
}
