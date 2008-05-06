/**
 * @file linux.c
 *
 * Linux versions of the APIs required by the discovery core.
 *
 * wicrawl - A modular and thorough wi-fi scanner
 * http://midnightresearch.com/projects/wicrawl - for details
 *
 * Original Code: jspence, Focus
 * Contributors:
 * $Id: linux.c,v 1.33 2007-08-07 06:43:55 jspence Exp $
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
 *
*/

#include "wicrawl.h"

#include <err.h>


/** File descriptor of the aironet control file. */
// This probably shouldn't be here.
FILE * airo_fp;

/**
 * Use the SIOCGIWNAME ioctl on a specific interface to see if it
 * supports the Linux wireless API.
 *
 * @param iface [in] A pointer to a C string with the name of the
 * interface to check.
 *
 * @return 1 if the interface supports the Linux wireless API, 0
 * otherwise.
 */
int isWireless(const char * iface)
{
  int s;
  int rc;
  int ret;
  struct iwreq req;

  s = socket(AF_INET, SOCK_DGRAM, 0);
  if(s == -1)
    err(EXIT_FAILURE, "socket() failed to create an ioctl socket");

  memcpy(req.ifr_ifrn.ifrn_name, iface,IFNAMSIZ-1);

  rc = ioctl(s, SIOCGIWNAME, &req);
  if(rc == -1)
    ret = 0;
  else
    ret = 1;

  close(s);

  return ret;
}

/**
 * See if this is an aironet card.  They use a similar naming scheme
 * but a different config API, so we have to explicitly test for them
 * when we see an interface name that could be them.
 *
 * @param iface [in] A character string with the name of the interface
 * to check for aironetness.
 *
 * @return If the interface is an Aironet card, you get a file pointer
 * to the Status file in /proc for the driver.  If not, you get NULL.
 * You must close the returned file pointer with fclose(3) when you
 * are finished screwing with it.
 */
static FILE * isAironet(const char * iface) {
  FILE * fp;
  int count;
  char fnbuf[64];

  count = snprintf(fnbuf, sizeof(fnbuf) - 1, "/proc/driver/aironet/%s/Status", iface);
  if(count < 0)
    return 0;

  fnbuf[count] = '\0';

  fp = fopen(fnbuf, "rw");

  return fp;
}

/**
 * Enable an interface by using the SIOCGIFFLAGS ioctl on it to set
 * the IFF_UP bit.
 *
 * @param iface [in] A pointer to a C string with the name of the
 * interface to enable.
 */
static void enableInterface(char * iface)
{
  int s;
  int rc;
  struct ifreq req;

  s = socket(AF_INET, SOCK_DGRAM, 0);
  if(s == -1) {
    warn("socket() failed to create an ioctl socket in enableInterface");
    return;
  }

  memset(&req, 0, sizeof(req));
  memcpy(req.ifr_ifrn.ifrn_name, iface, IFNAMSIZ - 1);
  rc = ioctl(s, SIOCGIFFLAGS, &req);
  if(rc == -1) {
    warn("ioctl(SIOCGIFFLAGS) failed in enableInterface()");
    goto out;
  }

  req.ifr_ifru.ifru_flags |= IFF_UP;

  rc = ioctl(s, SIOCSIFFLAGS, &req);
  if(rc == -1) {
    warn("ioctl(SIOCSIFFLAGS) failed in enableInterface()");
    goto out;
  }

 out:
  close(s);
}

// 1 == associated, 0 == not so much.
int isAssociated(char * iface)
{
  int s;
  int rc;
  int ret;
  struct iwreq req;
  bssid_t zero_bssid = { 0, 0, 0, 0, 0, 0 };

  s = socket(AF_INET, SOCK_DGRAM, 0);
  if(s == -1) {
    warn("socket() failed in isAssociated()");
    return 0;
  }
   
  memset(&req, 0, sizeof(req));
  memcpy(req.ifr_name, iface, strlen(iface));
  rc = ioctl(s, SIOCGIWAP, &req);
  if(rc == -1) {
    warn("ioctl(SIOCGIWAP) failed in isAssociated()");
    return 0;
  }

  if(!memcmp(req.u.ap_addr.sa_data, zero_bssid, 6))
    ret = 0;
  else
    ret = 1;

  return ret;
}

int setMonitorMode(char *iface, int enable)
{
  int rc;

  int s;
  struct protoent * proto;
  
  proto = getprotobyname("udp");
  if(proto == NULL) {
    warn("getprotobyname() failed in setMonitorMode()");
    return 0;
  }
 
  s = socket(AF_INET, SOCK_DGRAM, proto->p_proto);
  if(s == -1) {
    warn("socket() failed in setMonitorMode()");
    return 0;
  }

  // First, turn the interface on.
  enableInterface(iface);

  // "ath" interfaces are:
  //   Atheros (madwifi)
  
  // "eth" interfaces can be:
  //   Intel 2100 series (ipw2100)
  //   Intel 2200 series (ipw2200)
  //   Cisco Aironet cards (airo)

  // Is it an aironet card?
  if(! strncmp(iface, "eth", 3)) {
    FILE * fp;

    fp = isAironet(iface);
    if(fp != NULL) {
      // Yup, the file's there, so this interface must be an Aironet card.
      
      fprintf(fp, "Mode: %s\n", enable ? "rfmon" : "ESS");
      fclose(fp);
    }
  }

  // Both ath and eth interfaces use the linux wireless API for monitor mode.
  if(! strncmp(iface, "eth", 3) || ! strncmp(iface, "ath", 3) || ! strncmp(iface, "wlan", 4) || ! strncmp(iface, "wifi", 4)) {
    struct iwreq req;

    memset(&req, 0, sizeof(req));

    strncpy(req.ifr_ifrn.ifrn_name, iface, sizeof(req.ifr_ifrn.ifrn_name));
      
    rc = ioctl(s, SIOCGIWMODE, &req);
    if(rc == -1) {
      warn("ioctl(SIOCGWIMODE) failed on %s", iface);
      return 0;
    }
    
    if(enable) {
      req.u.mode = IW_MODE_MONITOR;
    }
    else {
      // Now, you'd think you could just turn off the monitor bit, but
      // it turns out that the atheros driver whines when no mode is set.
      // I think that's kind of funny, because no bits is defined as
      // IW_MODE_AUTO, where the driver picks the appropriate mode...
      req.u.mode = IW_MODE_INFRA;
    }
      
    rc = ioctl(s, SIOCSIWMODE, &req);
    if(rc == -1) {
      warn("ioctl(SIOCSWIMODE) failed to %s monitor mode on %s", 
           enable ? "enable" : "disable",
           iface);
      return 0;
    }

    return 1;
  }

  // "wlan" interfaces can be:
  //   Prism 2 (wlan-ng)
  else if(! strncmp(iface, "wlan", 4)) {
    // wlan-ng version
    {
#if 0
      p80211ioctl_req_t req;

      req.magic = P80211_IOCTL_MAGIC;

      // see wlanctl.c in the linux-wlan sources for an example
#endif

      int pid;
      int status;
      char * args[5];

      // for now, we just call wlanctl-ng
      pid = fork();
      if(! pid) {
        args[0] = "wlanctl-ng";
        args[1] = "lnxreq_wlansniff";
        args[2] = enable ? "enable=true" : "enable=false"; 
        args[3] = "channel=6";
        args[4] = NULL;
        execve("wlanctl-ng", args, NULL);
      }

      waitpid(pid, &status, 0);

      if(WEXITSTATUS(status)) {
        warnx("setMonitorMode() failed to enable monitor mode for %s", iface);
        return 0;
      }

      return 1;
    }

    close(s);

    return 1;
  }
  else {
    warnx("setMonitorMode() doesn't know how to enable monitoring on interface %s", iface);
    return 0;
  }
}

// Initialize some data tables for talking to the linux wireless api.
// 1 if we initialize ok, 0 otherwise.
int _initChannelTable(char * iface, struct iw_freq * chans)
{
  int i;
  int s;
  int rc;
  struct iw_range * r;
  struct iwreq wrq;
  struct iw_range_r18 range;

  s = socket(AF_INET, SOCK_DGRAM, 0);
  if(s == -1){
    warn("socket() failed to create a dinky socket for ioctl()");
    return 0;
  }

  // Ask the driver for it's operating parameters.
  memset(&wrq, 0, sizeof(struct iwreq));
  strncpy(wrq.ifr_name, iface, IFNAMSIZ-1);
  wrq.u.data.pointer = &range;
  wrq.u.data.length = sizeof(range);

  rc = ioctl(s, SIOCGIWRANGE, &wrq);
  if(rc == -1) {
    warn("ioctl(SIOCGIWRANGE) failed");
    return 0;
  }

  // Make a copy of the frequency list to feed to the channel hopper
  // later.
  r = (struct iw_range *) wrq.u.data.pointer;
  ap.hw_channel_count = r->num_channels;
  memcpy(chans, r->freq, r->num_channels * sizeof(struct iw_freq));

#ifndef MY_DRIVER_AUTHOR_DID_NOT_PREVALIDATE_THE_GOAT
  if(r->num_channels == 0) {
    fprintf(stderr, 
	    "HEY!  Your wireless driver isn't giving us a list of allowed frequencies.\n"
	    "Without this, we can't guarantee that wicrawl won't set the radio's transmitter\n"
	    "legally, so we're going to abort now.  Figure out who's responsible for your\n"
	    "wireless hardware driver and get them to fix this.\n");
    ap.shutdown = 1;
    return 0;
  }
#endif

  if(r->num_channels > MAX_CHANNELS) {
    fprintf(stderr, 
	    "Your wireless driver says your hardware supports more than %u channels.\n"
	    "This is more than wicrawl supports internally, so either your driver is\n"
	    "on crack, or you need to upgrade wicrawl.\n", MAX_CHANNELS);
    ap.shutdown = 1;
    return 0;
  }

  if(ap.infodump) {
    printf("Driver reports the following frequency table:\n");
  }
  for(i = 0; i < r->num_channels; ++i) {
    if(ap.infodump) {
      printf("  Index %i: Channel #%i m=%i\n", i, r->freq[i].i, r->freq[i].m);
    }

    /* Fill out the OS independent frequency table. */
    ap.hw_channels[i] = r->freq[i].i;
  }
  if(ap.infodump >= 2) {
    printf("DEBUG: channel count: %i\n", r->num_channels);
  }

  if(ap.channel_count > 0) {
    int i, j;

    /* If the user gave specific channels to scan, make sure the driver
       actually supports those channels. */
   
    for(i = 0; i < ap.channel_count; i++) {
      for(j = 0; j < r->num_channels; j++) {
	if(ap.channels[i] == 0) {
	  /* This isn't supposed to happen. */
	  __asm("int $3");
	}
	if(r->freq[j].i == ap.channels[i]) {
	  break;
	}
      }

      if(j == r->num_channels) {
	fprintf(stderr, "Oops, channel #%u given on the command line doesn't seem to\n"
		"be available through your driver.\n", ap.channels[j]);
	return 0;
      }
    }
  }
  else {
    /* Jesus fuck, we shouldn't have this behind-the-back init
       protocol here.  We need to have an os independent channel table. */
    ap.channel_count = r->num_channels;
    memcpy(ap.channels, ap.hw_channels, sizeof(channel_t) * MAX_CHANNELS);
  }

  close(s);

  return 1;
}

/** 1 if the channel is set, 0 if something went wrong. */
int setChannel(char * iface, channel_t channel)
{
  int i;
  int s;
  int rc;
  static int initialized = 0;
  struct iwreq wrq;
  char buf[32];
  static struct iw_freq chans[MAX_CHANNELS];

  // Special case for aironet cards, which don't use the linux-wireless API.
  if(airo_fp != NULL) {
    snprintf(buf, sizeof(buf) - 1, "Channel: %u", channel + 1);
    fprintf(airo_fp, "%s", buf);
    // there are supposed to be wireless-G and -A cards, but we 
    // don't know how to test for them.  Assume B for now.
    channel %= 14;

    return 1;
  }

  if(initialized == 0) {
    if(_initChannelTable(iface, chans) == 0) {
      return 0;
    }
    else {
      initialized = 1;
    }
  }

  s = socket(AF_INET, SOCK_DGRAM, 0);
  if(s == -1){
    warn("socket() failed to create a dinky socket for ioctl()");
    return 0;
  }

  // Set up for the wireless ioctl.
  memset(&wrq,0,sizeof(struct iwreq));
  strncpy(wrq.ifr_name, iface, IFNAMSIZ-1);

  // Find the iw_freq entry corresponding to the channel wanted.
  for(i = 0; i < ap.hw_channel_count; ++i) {
    if(chans[i].i == channel) {
      memcpy(&wrq.u.freq, &chans[i], sizeof(struct iw_freq));
      break;
    }
  }

  if(i == ap.hw_channel_count) {
    fprintf(stderr, "Could not find channel #%u in the driver's channel table.\n",
	    channel);
    return 0;
  }

  rc = ioctl(s, SIOCSIWFREQ, &wrq);
  if(rc == -1) {
    // Occasionally drivers are busy with something else, and aren't
    // capable of queuing our request.  In this case the SIWFREQ call
    // fails, but that's fine since we're not too concerned about
    // missing a channel during a given channel scan run.
    //
    // It's also possible that the card simply doesn't support channel
    // changing using the Linux Wireless APIs, in which case this is
    // going to fail 100% of the time.  Then it's the user's
    // responsibility to have some channel hopping script going on in
    // the background if they really want channel hopping.
    return 0;
  }
  else {
    ap.channel = channel;
  }

  rc = close(s);
  if(rc == -1) {
    fprintf(stderr, "close() failed on dinky socket, leaking one.\n");
  }

  return 1;
}

void * channelHopper(void * arg)
{
  unsigned int channel;
  chanhop_request_t * cr;
  int chan_idx;

  cr = (chanhop_request_t *) arg;
  
  airo_fp = isAironet(cr->iface);

  channel = 1; 

  /* HACK: do this once so we get the channel count */
  setChannel(cr->iface, channel);

  while(cr->shutdown != 0) {
    channel = ap.channels[chan_idx];
    chan_idx++;
    chan_idx %= ap.channel_count;

    setChannel(cr->iface, channel);

    usleep(cr->delay_usecs);
  }

  return NULL;
}

