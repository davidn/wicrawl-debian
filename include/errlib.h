/**
 * @file errlib.h
 *
 * Defines interfaces for the error handling library.
 */

#ifndef _ERRLIB_H
#define _ERRLIB_H

/**
 * This is the return type for internal routines.
 *
 * This return type is defined as being equal to 0 when a call results
 * in the intended effect, and equal to a routine-specific value in
 * all other cases.
 */
typedef unsigned int ret_t;

// Equivalent prototype:
// vsnprintf_loop(const char * buf, 
//                size_t buflen,
//                const char * format, 
//                int * written);
#define vsnprintf_loop(_buf, _buflen, _format, _written)                      \
{                                                                             \
  int _rc;                                                                    \
  va_list _vl;                                                                \
  size_t _count;                                                              \
                                                                              \
  _count = 0;                                                                 \
                                                                              \
  va_start(_vl, _format);                                                     \
    _rc = vsnprintf(_buf, _buflen - _count, _format, _vl);                    \
    _count += _rc;                                                            \
    _buf[_count] = '\0';                                                      \
  va_end(_vl);                                                                \
  *_written = _count;                                                         \
}

void warn(const char * format, ...);
void warnx(const char * format, ...);

#endif /* _ERRLIB_H */
