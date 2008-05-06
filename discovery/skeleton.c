/**
 * @file CHANGETHIS.c
 *
 * Skeleton for platform specific APIs.
 */

#include "wicrawl.h"

// OS specific headers go here.


int isWireless(const char * iface)
{
  if(this_is_wireless(iface)) {
    return 1;
  }
  else {
    return 0;
  }
}

int isAssociated(char * iface)
{
  if(this_interface_is_associated(iface)) {
    return 1;
  }
  else {
    return 0;
  }
}

int setMonitorMode(char *iface, int enable)
{
  if(! interface_exists) {
    return 0;
  }

  if(enable) {
    turn_on_monitor_mode_here();
  }
  else {
    turn_off_monitor_mode_here();
  }
}

void * channelHopper(void * arg)
{
  unsigned int channels;
  unsigned int channel_num;
  chanhop_request_t * cr;

  cr = arg;

  if(chanhop_request == NULL) {
    errx("caller is on crack");
  }

  channels = get_channel_count_from(chanhop_request->iface);

  channel_num = 0;

  while(chanhop_request->shutdown == 0) {

    set_channel(chanhop_request->iface, channel_num);
    
    usleep(chanhop_request->delay_usecs);

    channel_num++;
    channel_num %= channels;
  }
}
