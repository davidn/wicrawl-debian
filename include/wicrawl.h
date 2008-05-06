/*
 * @file wicrawl.h
 *
 * This is the main header for the wicrawl sources.  All other headers
 * should be included via this file.
 *
 * wicrawl - A modular and thorough wi-fi scanner
 * http://midnightresearch.com/projects/wicrawl - for details
 *
 * Original Code: jspence, focus
 * Contributors:
 * $Id: wicrawl.h,v 1.16 2007-08-20 01:50:08 jspence Exp $
 *
 * Copyright (C) 2005-2006 Midnight Research Laboratories
 *
 * THIS SOFTWARE IS PROVIDED "AS IS". NO WARRANTY IS ASSUMED.
 * NO LIABILITY OF ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING
 * FROM THE USE OF THIS SOFTWARE WILL BE ACCEPTED. IT CAN BURN
 * YOUR HARD DISK, ERASE ALL YOUR DATA AND BREAK DOWN YOUR
 * MICROWAVE OVEN. YOU ARE ADVISED.
 *
 * wicrawl is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.  For details see doc/LICENSE.
 */

/* First, let's tell everyone we're compiling for apcore, and not
   something else. */

#define __APCORE__ = APCORE_VERSION_NUMBER

/*
 * Standard C library headers.
 */
#include <ctype.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * POSIX headers.
 */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/file.h>

/*
 * Platform-specific socket headers.  We just need enough to call
 * socket(3) at this point.  This is nice because the set of target
 * platforms is the same as the set of platforms which provide these
 * three headers:
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>

/*
 * Headers for other packages we use.
 */
#include <getopt.h>
#include <pcap.h>

/*
 * Platform-specific wireless headers.
 */
// FreeBSD wireless API
#ifdef FreeBSD
#include <net80211/ieee80211_ioctl.h>
#endif

// Linux wireless API
#ifdef linux
#include <asm/types.h>
#include <linux/if.h>
#include <linux/wireless.h>

// We keep around our own copy of a few kernel structures, so we can
// select which version we want at runtime.  There's no guarantee the
// user has the headers for their running kernel in
// /usr/include/linux.
#include "linux_wireless.h"
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long u32;

#endif

// OS X
#ifdef __APPLE__
#include <limits.h>
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long u32;
#endif

// Windows
#ifdef _WIN32
#include <wpcap.h>
#endif

/*
 * Headers for our sources.
 */
#include "80211.h"
#include "ieee80211_radiotap.h"
#include "discovery.h"
#include "errlib.h"
#include "hash.h"
#include "util.h"
#include "version.h"

// You can turn this on to override the frequency table detection
// safety in the channel hopper, but you're not supposed to do this
// anywhere your radio could interfere with others.  I suppose it
// might be ok if you're in an underground bunker or something, but
// I'm not a lawyer and you should get your driver author to fix the
// problem anyway.

// #define MY_DRIVER_AUTHOR_DID_NOT_PREVALIDATE_THE_GOAT
