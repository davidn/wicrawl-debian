/*
 * @file discovery.c
 *
 * wicrawl - A modular and thorough wi-fi scanner
 * http://midnightresearch.com/projects/wicrawl - for details
 *
 * Original Code: jspence, Focus
 * Contributors:
 * $Id: discovery.c,v 1.99 2007-10-06 05:37:01 jspence Exp $
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
 *
 * "The world is coming to an end. Please log off."
 * -Posix 2.1.1 System Shutdown Message
 *
*/

#include "wicrawl.h"

apcore_s ap;

/** Number of characters currently in the IPC message buffer. */
unsigned int ipc_msg_buf_count;

/** IPC message buffer. */
char ipc_msg_buf[IPC_MSGBUF_SIZE];

int crack_prism2(const unsigned char * pkt, unsigned long pktlen, radio_hdr_info_t * hdr_info);
int crack_avs(const unsigned char * pkt, unsigned long pktlen, radio_hdr_info_t * hdr_info);
int crack_radiotap(const unsigned char * pkt, unsigned long pktlen, radio_hdr_info_t * hdr_info);

char * beacon_element_table[] =
{
  "SSID",
  "Supported rates",
  "FH parameter set",
  "DS parameter set",
  "CF parameter set",
  "Traffic indicator map",
  "IBSS parameter set",
  "Reserved element ID 7",
  "Reserved element ID 8",
  "Reserved element ID 9",
  "Reserved element ID 10",
  "Reserved element ID 11",
  "Reserved element ID 12",
  "Reserved element ID 13",
  "Reserved element ID 14",
  "Reserved element ID 15",
  "Challenge text",
  "Reserved element ID 32",
  "Reserved element ID 33",
  "Reserved element ID 34",
  "Reserved element ID 35",
  "Reserved element ID 36",
  "Reserved element ID 37",
  "Reserved element ID 38",
  "Reserved element ID 39",
  "Reserved element ID 40",
  "Reserved element ID 41",
  "Reserved element ID 42",
  "Reserved element ID 43",
  "Reserved element ID 44",
  "Reserved element ID 45",
  "Reserved element ID 46",
  "Reserved element ID 47",
  "RSN",
  "Reserved element ID 49",
  "Reserved element ID 50",
  "Reserved element ID 51",
  "Reserved element ID 52",
  "Reserved element ID 53",
  "Reserved element ID 54",
  "Reserved element ID 55",
  "Reserved element ID 56",
  "Reserved element ID 57",
  "Reserved element ID 58",
  "Reserved element ID 59",
  "Reserved element ID 60",
  "Reserved element ID 61",
  "Reserved element ID 62",
  "Reserved element ID 63",
  "Reserved element ID 64",
  "Reserved element ID 65",
  "Reserved element ID 66",
  "Reserved element ID 67",
  "Reserved element ID 68",
  "Reserved element ID 69",
  "Reserved element ID 70",
  "Reserved element ID 71",
  "Reserved element ID 72",
  "Reserved element ID 73",
  "Reserved element ID 74",
  "Reserved element ID 75",
  "Reserved element ID 76",
  "Reserved element ID 77",
  "Reserved element ID 78",
  "Reserved element ID 79",
  "Reserved element ID 80",
  "Reserved element ID 81",
  "Reserved element ID 82",
  "Reserved element ID 83",
  "Reserved element ID 84",
  "Reserved element ID 85",
  "Reserved element ID 86",
  "Reserved element ID 87",
  "Reserved element ID 88",
  "Reserved element ID 89",
  "Reserved element ID 90",
  "Reserved element ID 91",
  "Reserved element ID 92",
  "Reserved element ID 93",
  "Reserved element ID 94",
  "Reserved element ID 95",
  "Reserved element ID 96",
  "Reserved element ID 97",
  "Reserved element ID 98",
  "Reserved element ID 99",
  "Reserved element ID 100",
  "Reserved element ID 101",
  "Reserved element ID 102",
  "Reserved element ID 103",
  "Reserved element ID 104",
  "Reserved element ID 105",
  "Reserved element ID 106",
  "Reserved element ID 107",
  "Reserved element ID 108",
  "Reserved element ID 109",
  "Reserved element ID 110",
  "Reserved element ID 111",
  "Reserved element ID 112",
  "Reserved element ID 113",
  "Reserved element ID 114",
  "Reserved element ID 115",
  "Reserved element ID 116",
  "Reserved element ID 117",
  "Reserved element ID 118",
  "Reserved element ID 119",
  "Reserved element ID 120",
  "Reserved element ID 121",
  "Reserved element ID 122",
  "Reserved element ID 123",
  "Reserved element ID 124",
  "Reserved element ID 125",
  "Reserved element ID 126",
  "Reserved element ID 127",
  "Reserved element ID 128",
  "Reserved element ID 129",
  "Reserved element ID 130",
  "Reserved element ID 131",
  "Reserved element ID 132",
  "Reserved element ID 133",
  "Reserved element ID 134",
  "Reserved element ID 135",
  "Reserved element ID 136",
  "Reserved element ID 137",
  "Reserved element ID 138",
  "Reserved element ID 139",
  "Reserved element ID 140",
  "Reserved element ID 141",
  "Reserved element ID 142",
  "Reserved element ID 143",
  "Reserved element ID 144",
  "Reserved element ID 145",
  "Reserved element ID 146",
  "Reserved element ID 147",
  "Reserved element ID 148",
  "Reserved element ID 149",
  "Reserved element ID 150",
  "Reserved element ID 151",
  "Reserved element ID 152",
  "Reserved element ID 153",
  "Reserved element ID 154",
  "Reserved element ID 155",
  "Reserved element ID 156",
  "Reserved element ID 157",
  "Reserved element ID 158",
  "Reserved element ID 159",
  "Reserved element ID 160",
  "Reserved element ID 161",
  "Reserved element ID 162",
  "Reserved element ID 163",
  "Reserved element ID 164",
  "Reserved element ID 165",
  "Reserved element ID 166",
  "Reserved element ID 167",
  "Reserved element ID 168",
  "Reserved element ID 169",
  "Reserved element ID 170",
  "Reserved element ID 171",
  "Reserved element ID 172",
  "Reserved element ID 173",
  "Reserved element ID 174",
  "Reserved element ID 175",
  "Reserved element ID 176",
  "Reserved element ID 177",
  "Reserved element ID 178",
  "Reserved element ID 179",
  "Reserved element ID 180",
  "Reserved element ID 181",
  "Reserved element ID 182",
  "Reserved element ID 183",
  "Reserved element ID 184",
  "Reserved element ID 185",
  "Reserved element ID 186",
  "Reserved element ID 187",
  "Reserved element ID 188",
  "Reserved element ID 189",
  "Reserved element ID 190",
  "Reserved element ID 191",
  "Reserved element ID 192",
  "Reserved element ID 193",
  "Reserved element ID 194",
  "Reserved element ID 195",
  "Reserved element ID 196",
  "Reserved element ID 197",
  "Reserved element ID 198",
  "Reserved element ID 199",
  "Reserved element ID 200",
  "Reserved element ID 201",
  "Reserved element ID 202",
  "Reserved element ID 203",
  "Reserved element ID 204",
  "Reserved element ID 205",
  "Reserved element ID 206",
  "Reserved element ID 207",
  "Reserved element ID 208",
  "Reserved element ID 209",
  "Reserved element ID 210",
  "Reserved element ID 211",
  "Reserved element ID 212",
  "Reserved element ID 213",
  "Reserved element ID 214",
  "Reserved element ID 215",
  "Reserved element ID 216",
  "Reserved element ID 217",
  "Reserved element ID 218",
  "Reserved element ID 219",
  "Reserved element ID 220",
  "Reserved element ID 221",
  "Reserved element ID 222",
  "Reserved element ID 223",
  "Reserved element ID 224",
  "Reserved element ID 225",
  "Reserved element ID 226",
  "Reserved element ID 227",
  "Reserved element ID 228",
  "Reserved element ID 229",
  "Reserved element ID 230",
  "Reserved element ID 231",
  "Reserved element ID 232",
  "Reserved element ID 233",
  "Reserved element ID 234",
  "Reserved element ID 235",
  "Reserved element ID 236",
  "Reserved element ID 237",
  "Reserved element ID 238",
  "Reserved element ID 239",
  "Reserved element ID 240",
  "Reserved element ID 241",
  "Reserved element ID 242",
  "Reserved element ID 243",
  "Reserved element ID 244",
  "Reserved element ID 245",
  "Reserved element ID 246",
  "Reserved element ID 247",
  "Reserved element ID 248",
  "Reserved element ID 249",
  "Reserved element ID 250",
  "Reserved element ID 251",
  "Reserved element ID 252",
  "Reserved element ID 253",
  "Reserved element ID 254",
  "Vendor-specific element ID"
};

void printUsage(void)
{
  //               1         2         3         4         5         6         7         8
  //      12345678901234567890123456789012345678901234567890123456789012345678901234567890
  printf("Usage : apcore [-l] <interface> \n"
	 " -c, --channels CHANS Only scan channels in CHANS\n"
	 " -d, --dump-dlts      Dump datalink types for interface\n"
	 " -f, --file FILE      Read frames from FILE instead of an interface\n"
	 " -h, --help           This help message\n"
	 " -l, --list           List all wireless interfaces\n"
	 " -m, --mon-script SCR Use script SCR to change the interface's monitor setting\n"
	 " -n, --no-monitor     Do not change interface's monitor mode setting\n"
	 " -o, --output FILE    Output XML to FILE\n"
	 " -v, --verbose        Print more details\n"
	 " -V, --version        Display program version\n"
	 " -q, --quiet          Less verbose output\n"
	 " -w, --write          Write a pcap file containing all the captured packets\n"
	 " -x, --hexdump        Hexdump incoming packets\n"
	 "Send bug reports to <wicrawl-cvs@midnightresearch.com>\n");
}

void printVersion(void)
{
  printf("Wicrawl discovery engine version %s, compiled on %s at %s\n", 
	 APCORE_VERSION,
	 __DATE__,
	 __TIME__);
}

/**
 * Figure out how to figure out the size of any radio headers, based
 * on the DLT pcap returned.
 *
 * A note about the AVS headers: libpcap doesn't ever return the AVS
 * DLT, because it only shows up in save files.  The ARPHRD mechanism
 * that Linux uses to tell pcap what DLT to use doesn't even have a
 * value for the AVS headers -- drivers that return AVS headers just
 * use the Prism ARPHRD value.  This makes things a little ambigious,
 * but fortunately the AVS headers include a very unambigious version
 * as their first field.  If we see this version as the first four
 * bytes of a Prism radio header, we switch to the AVS cracker.
 */
void calc_ll_offset(apcore_s * ap)
{
  ap->offset = 0;

  switch ( pcap_datalink(ap->pd) ) {
  case DLT_IEEE802_11:
    ap->offset = 0;
    break;

  case DLT_PRISM_HEADER:
    ap->cracker = crack_prism2;
    ap->offset = -1;
    break;

  case DLT_IEEE802_11_RADIO:
    ap->cracker = crack_radiotap;
    ap->offset = -1;
    break;

    // No drivers we know of will trigger this, but just in case...
  case DLT_IEEE802_11_RADIO_AVS:
    fprintf(stderr, 
	    "HEY!  Your copy of libpcap is doing something we thought was impossible.\n"
	    "Wicrawl will work, but please tell us what you're running wicrawl on.\n");
    sleep(2);
    ap->cracker = crack_avs;
    ap->offset = -1;
    break;
      
  default:
    fprintf(stderr, "Warning: unknown DLT type %i, assuming no header.\n", pcap_datalink(ap->pd));
    break;
    
  }
}

void list(void)
{
  int rc;
  char errbuf[PCAP_ERRBUF_SIZE];
  unsigned ifindex;
  pcap_if_t * ifaces;
  pcap_if_t * iface;

  rc = pcap_findalldevs(&ifaces, errbuf);
  if(rc == -1) {
    printf("pcap_findalldevs() failed: %s\n", errbuf);
    goto out;
  }

  iface = ifaces;
  ifindex = 0;
  while(iface != NULL) {
    if(isWireless(iface->name)) {
      printf("%u: %s", ifindex, iface->name);
      if(iface->description) {
	printf(" (%s)", iface->description);
      }
      printf("\n");
    }

    iface = iface->next;
    ifindex++;
  }

 out:
  pcap_freealldevs(ifaces);
}

/*
  Element IDs are in table 20 on page 70 of the spec.

  Timestamp                 8    (see 11.1)
  Beacon interval           2    in time units
  Capability information    2    see 7.3.1.4
  SSID                      2-34 see 7.3.2.1
  Supported rates           3-10 see 7.3.2.2
  FH parameter              
  DS parameter
  CF parameter
  IBSS parameter
  TIM
*/

typedef struct chan_freq_table_entry {
  unsigned int channel;
  unsigned int freq_mHz;
} chan_freq_table_entry;

chan_freq_table_entry chan_freq_table[] = {
  { 1, 2412 },
  { 2, 2417 },
  { 3, 2422 },
  { 4, 2427 },
  { 5, 2432 },
  { 6, 2437 },
  { 7, 2442 },
  { 8, 2447 },
  { 9, 2452 },
  { 10, 2457 },
  { 11, 2462 },
  { 12, 2467 },
  { 13, 2472 },
  { 14, 2484 },
  { 36, 5180 },
  { 40, 5200 },
  { 44, 5220 },
  { 48, 5240 },
  { 52, 5260 },
  { 56, 5280 },
  { 60, 5300 },
  { 64, 5320 },
  { 149, 5745 },
  { 153, 5765 },
  { 157, 5785 },
  { 161, 5805 }
};

#define CHAN_FREQ_TABLE_ROWS (sizeof(chan_freq_table) / sizeof(chan_freq_table[0]))

unsigned int freq_to_chan(unsigned int freq_mHz)
{
  int i;
  for(i = 0; i < CHAN_FREQ_TABLE_ROWS; ++i) {
    if(freq_mHz == chan_freq_table[i].freq_mHz) {
      return chan_freq_table[i].channel;
    }
  }

  return 0;
}

double dBm_to_mW(int dBm)
{
  return pow(10.0, ((double) dBm / 20.0));
}

/**
 * Crack a PRISM 2 header.
 */
int crack_prism2(const unsigned char * pkt, unsigned long pktlen, radio_hdr_info_t * hdr_info)
{
  wlan_ng_prism2_header * hdr;

  if(ntohl(GET_U32(pkt)) == 0x80211001) {
    // Oh, this is an AVS header.  Switch modes.
    ap.cracker = crack_avs;
    return crack_avs(pkt, pktlen, hdr_info);
  }

  if(pktlen < sizeof(wlan_ng_prism2_header)) {
    fprintf(stderr, "wtf, pcap gave us a prism2 frame smaller than a prism2 radio header.  Dropping.\n");
    return -1;
  }

  hdr = (wlan_ng_prism2_header *) pkt;
  
  hdr_info->fields = F_CHANNEL | F_SIGNAL_DBM | F_RATE_KBPS;
  hdr_info->rate_kbps = hdr->rate.data;
  hdr_info->signal_dBm = hdr->signal.data;
  hdr_info->channel = hdr->channel.data;

  return sizeof(wlan_ng_prism2_header);
}

/**
 * Crack a PRISM 2 AVS header.
 *
 * The fucktard that implemented this couldn't keep his website up, so
 * there is no official documentation on the format of this header.
 * What you see here is the result of what we call "computer
 * archeology," otherwise known as a "royal pain in the ass."
 */
int crack_avs(const unsigned char * pkt, unsigned long pktlen, radio_hdr_info_t * hdr_info)
{
  avs_80211_1_header * hdr;

  if(pktlen < sizeof(avs_80211_1_header)) {
    fprintf(stderr, "wtf, pcap gave us an AVS frame smaller than an AVS header.  Dropping.\n");
    return -1;
  }

  hdr = (avs_80211_1_header *) pkt;

  if(ntohl(hdr->version) != 0x80211001) {
    fprintf(stderr, "Received AVS radio header with unrecognized version %x\n", ntohl(hdr->version));
    return -1;
  }

  hdr_info->fields = F_SIGNAL_DBM | F_CHANNEL | F_RATE_KBPS;
  // FIXME: What units are these?!
  hdr_info->signal_dBm = ntohl(hdr->ssi_signal);
  hdr_info->channel = ntohl(hdr->channel);
  hdr_info->rate_kbps = hdr->datarate;

  return sizeof(avs_80211_1_header);
}

/**
 * Radiotap header cracker.
 *
 * Although the radiotap header file doesn't say so, the fields in a
 * radiotap frame header are in the byte order of the processor that
 * ran the card driver.
 */
int crack_radiotap(const unsigned char * pkt, unsigned long pktlen, radio_hdr_info_t * hdr_info)
{
  uint8_t * p;
  uint32_t fields;
  unsigned long remaining;
  struct ieee80211_radiotap_header * hdr;
  int8_t antsignal_dBm;
  int8_t antsignal_noise;
  uint8_t rate; /* in multiples of 500 Kb/sec */
  uint8_t flags;
  uint8_t antenna;
  uint64_t tsft;

  struct channel {
    uint16_t freq_mHz;
    uint16_t flags;
  } channel;

  rate = 0;
  antsignal_dBm = 0;
  channel.freq_mHz = 0;
  
  if(pktlen < sizeof(struct ieee80211_radiotap_header)) {
    fprintf(stderr, "pcap said it's feeding us radiotap headers, but then gave us a packet too small to contain a radiotap header (%lu bytes) :(\n", pktlen);
    return -1;
  }

  hdr = (struct ieee80211_radiotap_header *) pkt;
  if(hdr->it_version != 0) {
    fprintf(stderr, "Got radiotap header with unrecognized version %u.  Dropping.\n", hdr->it_version);
    return -1;
  }

  if(hdr->it_len > pktlen) {
    fprintf(stderr, "Got radiotap header claiming its packet is bigger than pcap says.  Dropping.\n");
    return -1;
  }

  if(hdr->it_len < sizeof(struct ieee80211_radiotap_header)) {
    fprintf(stderr, "Got radiotap header claiming it's smaller than the header prefix.  Dropping.\n");
    return -1;
  }

  remaining = hdr->it_len - sizeof(struct ieee80211_radiotap_header);
  fields = hdr->it_present;
  p = ((uint8_t *) pkt) + sizeof(struct ieee80211_radiotap_header);

  if(ap.infodump && 0) {
    printf("pktlen : %lu\n", pktlen);
    printf("hdr->it_len : %u\n", hdr->it_len);
  }

#define EXTRACT(_WHAT_, _TYPE_, _TO_HERE_)				\
  do {									\
    if(fields & (1 << _WHAT_)) {					\
      if(remaining < sizeof(_TYPE_)) {					\
	fprintf(stderr, "Found field %u in radiotap header walking off the end.  Dropping.\n", _WHAT_); \
	return -1;							\
      }									\
      memset(_TO_HERE_, 0, sizeof(_TYPE_));				\
      memcpy(_TO_HERE_, p, sizeof(_TYPE_));				\
      remaining -= sizeof(_TYPE_);					\
      p += sizeof(_TYPE_);						\
    }									\
  } while (0)

  // These fields appear in the same order they are listed in the
  // bitfield, from lsb to msb.
  EXTRACT(IEEE80211_RADIOTAP_TSFT, uint64_t, &tsft);
  EXTRACT(IEEE80211_RADIOTAP_FLAGS, uint8_t, &flags);
  EXTRACT(IEEE80211_RADIOTAP_RATE, uint8_t, &rate);
  EXTRACT(IEEE80211_RADIOTAP_CHANNEL, uint32_t, &channel);
  EXTRACT(IEEE80211_RADIOTAP_DBM_ANTSIGNAL, int8_t, &antsignal_dBm);
  EXTRACT(IEEE80211_RADIOTAP_DBM_ANTNOISE, int8_t, &antsignal_noise);
  EXTRACT(IEEE80211_RADIOTAP_ANTENNA, uint8_t, &antenna);

  memset(hdr_info, 0, sizeof(*hdr_info));
  if(channel.freq_mHz) {
    hdr_info->fields |= F_CHANNEL;
  }
  if(rate) {
    hdr_info->fields |= F_RATE_KBPS;
  }
  if(antsignal_dBm) {
    hdr_info->fields |= F_SIGNAL_DBM;
  }
  hdr_info->channel = freq_to_chan(channel.freq_mHz);
  hdr_info->signal_dBm = antsignal_dBm;
  hdr_info->rate_kbps = rate * 500;

  if(ap.infodump >= 2) {
    printf(" Radiotap header fields:\n");
    if(fields & (1 << IEEE80211_RADIOTAP_TSFT)) {
      printf("  IEEE80211_RADIOTAP_TSFT\n");
    }
    if(fields & (1 << IEEE80211_RADIOTAP_FLAGS)) {
      printf("  IEEE80211_RADIOTAP_FLAGS\n");
    }
    if(fields & (1 << IEEE80211_RADIOTAP_RATE)) {
      printf("  IEEE80211_RADIOTAP_RATE\n");
    }
    if(fields & (1 << IEEE80211_RADIOTAP_CHANNEL)) {
      printf("  IEEE80211_RADIOTAP_CHANNEL\n");
    }
    if(fields & (1 << IEEE80211_RADIOTAP_FHSS)) {
      printf("  IEEE80211_RADIOTAP_FHSS\n");
    }
    if(fields & (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL)) {
      printf("  IEEE80211_RADIOTAP_DBM_ANTSIGNAL\n");
    }
    if(fields & (1 << IEEE80211_RADIOTAP_DBM_ANTNOISE)) {
      printf("  IEEE80211_RADIOTAP_DBM_ANTNOISE\n");
    }
    if(fields & (1 << IEEE80211_RADIOTAP_LOCK_QUALITY)) {
      printf("  IEEE80211_RADIOTAP_LOCK_QUALITY\n");
    }
    if(fields & (1 << IEEE80211_RADIOTAP_TX_ATTENUATION)) {
      printf("  IEEE80211_RADIOTAP_TX_ATTENUATION\n");
    }
    if(fields & (1 << IEEE80211_RADIOTAP_DB_TX_ATTENUATION)) {
      printf("  IEEE80211_RADIOTAP_DB_TX_ATTENUATION\n");
    }
    if(fields & (1 << IEEE80211_RADIOTAP_DBM_TX_POWER)) {
      printf("  IEEE80211_RADIOTAP_DBM_TX_POWER\n");
    }
    if(fields & (1 << IEEE80211_RADIOTAP_ANTENNA)) {
      printf("  IEEE80211_RADIOTAP_ANTENNA\n");
    }
    if(fields & (1 << IEEE80211_RADIOTAP_DB_ANTSIGNAL)) {
      printf("  IEEE80211_RADIOTAP_DB_ANTSIGNAL\n");
    }
    if(fields & (1 << IEEE80211_RADIOTAP_DB_ANTNOISE)) {
      printf("  IEEE80211_RADIOTAP_DB_ANTNOISE\n");
    }
    if(fields & (1 << IEEE80211_RADIOTAP_EXT)) {
      printf("  IEEE80211_RADIOTAP_EXT\n");
    }
  }

  return hdr->it_len;
}

/**
 * Initialize the IPC message buffer for a new message.
 *
 * @param msgtype [in] A string describing the message type.  Valid
 * values are "new" and "update".
 */
void init_ipc_msg_buf(const char * msgtype)
{
  unsigned int count;

  ipc_msg_buf_count = 0;
  memset(ipc_msg_buf, 0, sizeof(ipc_msg_buf));

  count = snprintf(ipc_msg_buf, sizeof(ipc_msg_buf) - 1, 
		   "%s", msgtype);
  ipc_msg_buf_count += count;
  ipc_msg_buf[ipc_msg_buf_count] = '\0';
}
/**
 * Append a field to an IPC message.  This acts just like printf,
 * except the results are base64 encoded in the message itself.
 */

void append_ipc_msg_buf(const char * field, const char * format, ...)  
{
  va_list vl; 
  unsigned char encodedbuf[512]; 
  unsigned char databuf[512];
  int count;

  va_start(vl, format);
  count = vsnprintf((char *) databuf, sizeof(databuf) - 1, format, vl);
  if(count < 0) {
    return;
  }
  va_end(vl);
  databuf[count] = '\0';

  count = encodestream(encodedbuf, sizeof(encodedbuf) - 1,
		       databuf, count);

  encodedbuf[count] = '\0';

  count = snprintf(ipc_msg_buf + ipc_msg_buf_count, 
		   sizeof(ipc_msg_buf) - ipc_msg_buf_count - 1,
		   "|%s:%s",
		   field, encodedbuf);
  ipc_msg_buf_count += count;
  ipc_msg_buf[ipc_msg_buf_count] = '\0';
}

/**
 * Close the IPC message buffer and put it into a state where it can
 * be transmitted.  Right now, this just appends a newline.
 */
void close_ipc_msg_buf(void)
{
  unsigned int count;
  
  count = snprintf(ipc_msg_buf + ipc_msg_buf_count, 
		   sizeof(ipc_msg_buf) - ipc_msg_buf_count - 1,
		   "\n");
  ipc_msg_buf_count += count;
  ipc_msg_buf[ipc_msg_buf_count] = '\0';
}

void dump_ipc_queue(void)
{
  ipc_update_msg * p;

  printf("head: %p\n", ap.ipc_update_head);
  printf("tail: %p\n", ap.ipc_update_tail);
  p = ap.ipc_update_tail;
  while(p) {
    printf("  %p <- %p -> %p\n", p->prev, p, p->next);
    p = p->next;
  }
}

/**
 * Enqueue an update message into the IPC queue.
 */
inline void enqueue_ipc_msg(bssid_t bssid, 
			    char * ssid,
			    unsigned int ssid_len,
			    encryption_type enc,
			    radio_hdr_info_t * radio_hdr)
{
  ipc_update_msg * new;
  bssid_hash_ent * ent;

  /* Add the BSSID to the hash table if it's not already there. */
  ent = find_bssid(bssid);
  if(ent == NULL) {
    ent = add_bssid(bssid);
    set_cos(ent, COS_INITIAL);
  }
  else {
    if(has_cos(ent)) {
      /* The IPC manager already knows there's CoS for this node. */
      return;
    }

    set_cos(ent, COS_PRESENT);
  }

  update_bssid(bssid, radio_hdr);

  new = xmalloc(sizeof(ipc_update_msg));
  memset(new, 0, sizeof(ipc_update_msg));

  memcpy(new->bssid, bssid, sizeof(bssid_t));
  memcpy(new->ssid, ssid, ssid_len);
  new->ent = ent;
  memcpy(&new->enc, &enc, sizeof(new->enc));
  memcpy(&new->radio_hdr, radio_hdr, sizeof(new->radio_hdr));

  new->prev = NULL;
  new->next = NULL;

  if(ap.ipc_update_head != NULL) {
    new->next = ap.ipc_update_head;
    ap.ipc_update_head->prev = new;
  }
  ap.ipc_update_head = new;

  if(ap.ipc_update_tail == NULL) {
    ap.ipc_update_tail = ap.ipc_update_head;
  }
}

/**
 * Dequeue an IPC update message from the update queue.  These
 * messages are dynamically allocated, so you need to free them after
 * you dequeue them.
 *
 * Example usage:
 *@code
 *ipc_update_msg * msg;
 * 
 *if(dequeue_ipc_msg(&msg)) {
 *  do_stuff(msg);
 *  free(msg);
 *}
 *@endcode
 *
 * @param msg [out] A pointer to an ipc_update_msg pointer, which gets
 * the address of the dequeued IPC update message.
 *
 * @return 1 if a message is successfully dequeued, or 0 if the update
 * queue is empty.
 */
unsigned int dequeue_ipc_msg(ipc_update_msg ** msg)
{
  if(ap.ipc_update_tail == NULL) {
    return 0;
  }

  *msg = ap.ipc_update_tail;
  ap.ipc_update_tail = ap.ipc_update_tail->prev;

  if(ap.ipc_update_tail == NULL) {
    ap.ipc_update_head = NULL;
  }
  else {
    ap.ipc_update_tail->next = NULL;
  }

  (*msg)->next = NULL;
  (*msg)->prev = NULL;

  return 1;
}

void * ipc_handler(void * unused)
{
  ipc_update_msg * msg;

  /* Wait for something to show up in the IPC message queue... */
  while(1) {
    sleep(1);

    if(ap.ipc_update_tail == NULL) {
      continue;
    }

    /* Oh, here's something.  Flush all the messages in the queue. */
    while(1) {
      if(dequeue_ipc_msg(&msg) == 0) {
	break;
      }

      /* Is this a new BSSID or an update to an existing one? */
      if(msg->ent->s->cos_state == COS_INITIAL) {
	init_ipc_msg_buf("new");
      }
      else {
	init_ipc_msg_buf("update");
      }      
      clear_cos(msg->ent);
      
      append_ipc_msg_buf("ssid", "%s", msg->ssid);
      append_ipc_msg_buf("bssid", "%c%c%c%c%c%c", 
			 msg->bssid[0],
			 msg->bssid[1],
			 msg->bssid[2],
			 msg->bssid[3],
			 msg->bssid[4],
			 msg->bssid[5]);
      if(msg->radio_hdr.fields & F_CHANNEL) {
	append_ipc_msg_buf("channel", "%c", msg->radio_hdr.channel);
      }
      if(msg->radio_hdr.fields & F_SIGNAL_DBM) {
	append_ipc_msg_buf("power", "%li", msg->radio_hdr.signal_dBm);
      }
      append_ipc_msg_buf("encryption", "%s",
			 msg->enc == ENC_WEP ? "WEP" : "None");
      
      close_ipc_msg_buf();

      if(ap.ipc2_socket) {
	send(ap.ipc2_socket, ipc_msg_buf, ipc_msg_buf_count, 0);
      }
      else if(ap.ipc_pipe_fd) {
	flock(ap.ipc_pipe_fd, LOCK_EX);
	write(ap.ipc_pipe_fd, ipc_msg_buf, ipc_msg_buf_count);
	flock(ap.ipc_pipe_fd, LOCK_UN);
      }
      else {
	fprintf(stderr, "The IPC manager is running, but can't find any IPC pipes!  wtf?\n");
	exit(EXIT_FAILURE);
      }

      xfree(msg);
    }
  }
}

void print_ssid(unsigned char * ssid, unsigned int ssid_len)
{
  int i;
  int printable;

  printable = 1;
  for(i = 0; i < ssid_len; ++i) {
    if(! isprint(ssid[i])) {
      printable = 0;
      break;
    }
  }

  printf(" SSID: ");
  if(printable) {
    printf("%s\n", ssid);
  }
  else {
    printf("\n");
    hexdump(ssid, ssid_len);
  }
}

/**
 * Check an 802.11 frame to see if it's a beacon.
 * 
 * @param pkt [in] Pointer to the bytes from the frame.
 *
 * @param hdrlen [in] Length of the frame in bytes, from the pcap header.
 *
 * @param pktoffset [in] Offset to the 802.11 header in bytes, relative 
 * to the beginning of the frame.  If negative, then use the cracker
 * function from the ap structure to compute the offset.
 * 
 * @return 1 if this frame contains a beacon, 0 otherwise.
 */
int chkforbeacon(const unsigned char *pkt, const int hdrlen, const int pktoffset)
{
  ret_t ret;
  int rhdr_bytes;
  f80211_mac_t *mac;
  frame_control_t *fc;
  beacon_header_t *bchdr;
  radio_hdr_info_t rhdr;
  char ssid[32 + 1]; // $7.3.2.1
  static unsigned int network_num = 1;

  ret = 0;
  memset(ssid, 0, sizeof(ssid));
  memset(&rhdr, 0, sizeof(rhdr));

  //We need to set the offset for the header
  if(pktoffset >= 0) {
    pkt = pkt + pktoffset;
  }
  else {
    rhdr_bytes = ap.cracker(pkt, hdrlen, &rhdr);
    if(rhdr_bytes <= 0) {
      return 0;
    }

    pkt = pkt + rhdr_bytes;
  }

  if(ap.infodump) {
    printf(" Signal : %li (%g nW)\n", rhdr.signal_dBm, dBm_to_mW(rhdr.signal_dBm) * 1000.0 * 1000.0);
    printf(" Channel : %lu\n", rhdr.channel);
  }

  mac = (f80211_mac_t *)pkt;
  fc = (frame_control_t *)mac->fc;

  if(hdrlen<sizeof(mac)) {
    printf("Packet can't be a beacon, header is too small\n");
  }

  if(fc->subtype == MGT_BEACON) {
    bchdr = (beacon_header_t *)(pkt+sizeof(f80211_mac_t));
    if(ap.infodump) {
      printf(" Beacon Timestamp : %s\n",hex2ascii(bchdr->timestamp,8));
      printf(" BSS : %s\n",mac2ascii(mac->address2)); 
      printf(" Dest : %s\n",mac2ascii(mac->address1)); 
      printf(" Source : %s\n",mac2ascii(mac->address3)); 
      printf(" Cap :  %.04x\n", bchdr->capability);
    }
    
    if(bchdr->ssid_length > 32) {
      // SSIDs must be between 0 and 32 bytes long.
      return 0;
    }
    memcpy(ssid, bchdr->ssid, bchdr->ssid_length);
    ssid[bchdr->ssid_length] = '\0';

    if(ap.infodump) {
      int remaining;
      unsigned char * p;

      print_ssid((unsigned char *) ssid, bchdr->ssid_length);
      p = (unsigned char *) &bchdr->ssid_element_id;
      remaining = hdrlen - rhdr_bytes - sizeof(f80211_mac_t) - 12;

      while(remaining > 1) {
        if(p[1] == 0)
          break;
        printf("  Element %u (%s), length %u\n", 
	       p[0], beacon_element_table[p[0]], p[1]);
        remaining -= (p[1] + 2);
        p += p[1] + 2;
      }
    }

    //dump_ipc_queue();

    enqueue_ipc_msg(mac->address2, 
		    ssid, 
		    bchdr->ssid_length + 1,
		    bchdr->capability & IEEE80211_CAPINFO_PRIVACY ? 
		    ENC_WEP : ENC_NONE,
		    &rhdr);
    ret = 1;
    goto out;

    fprintf(ap.xml_out, "  <wireless-network number=\"%u\" type=\"\" wep=\"%s\">\n"
	    "    <SSID>%s</SSID>\n"
	    "    <BSSID>%s</BSSID>\n"
	    "    <channel>%u</channel>\n"
	    "    <encryption>%s</encryption>\n"
	    "    <power>%li</power>\n"
	    "  </wireless-network>\n",
	    network_num++, 
	    bchdr->capability & IEEE80211_CAPINFO_PRIVACY ? "true" : "false",
	    ssid,
	    mac2ascii(mac->address2),
	    ap.channel,
	    bchdr->capability & IEEE80211_CAPINFO_PRIVACY ? "WEP" : "None",
	    rhdr.signal_dBm);
  }
  else if(fc->subtype == MGT_PROBE_REQ) {
    if(ap.infodump) {
      printf("Found Probe:\n");
      printf("\tDest : %s\n",mac2ascii(mac->address2));
      printf("\tSource : %s\n",mac2ascii(mac->address3));
      printf("\tBSS : %s\n",mac2ascii(mac->address2));
    }
    ret = 0;
  }
  else {
    //printf("Unidentified subtype %u\n", fc->subtype);
    ret = 0;
  }

  if(ap.infodump) {
    printf("\n");
  }

out:

  return ret;
}

void dump_dlts(pcap_t * p)
{
  int rc;
  int * dlt_buf;
  unsigned int i;

  fprintf(stderr, "Supported datalink types:\n");

  rc = pcap_list_datalinks(p, &dlt_buf);
  if(rc == -1) {
    pcap_perror(p, "pcap_list_datalinks() failed");
    return;
  }

  for(i = 0; i < rc; ++i) {
    printf("%s: %u\n", pcap_datalink_val_to_name(dlt_buf[i]), dlt_buf[i]);
  }

  free(dlt_buf);
}

void sigint_handler(int signum, siginfo_t * si, void * unused)
{
  ap.shutdown = 1;
  pcap_breakloop(ap.pd);
}

void sigterm_handler(int signum, siginfo_t * si, void * unused)
{
  ap.shutdown = 1;
  pcap_breakloop(ap.pd);
}

// 1 == ok, 0 == not so much
int open_xml_file(char * optarg)
{
  int empty;
  FILE * f;

  empty = 0;

  // is the file there?
  f = fopen(optarg, "r");
  if(f == NULL)
    empty = 1;
  else
    fclose(f);

  ap.xml_out = fopen(optarg, "a+");
  if(ap.xml_out == NULL) {
    fprintf(stderr, "Could not open %s for XML output\n", optarg);
    return 0;
  }

  setbuf(ap.xml_out, NULL);

  if(empty) {
    // first time writing to this file, so an XML header would be nice
    fprintf(ap.xml_out, "<?xml version=\"1.0\"?>\n");
  }

  return 1;
}

void write_xml_header(void)
{
  time_t now;
  char ctime_buf[26];

  now = time(NULL);
  ctime_r(&now, ctime_buf);
  ctime_buf[strlen(ctime_buf) - 1] = '\0';

  fprintf(ap.xml_out, "<detection-run wicrawl-version=\"%s\" start-time=\"%s\">\n",
	  APCORE_VERSION,
	  ctime_buf);
}

#define IPC2_RESPOND(s)                                       \
count = snprintf(tx_buf, sizeof(tx_buf) - 1, s);              \
if(count < 1) {                                               \
  return NULL;                                                \
}                                                             \
tx_buf[count] = '\0';

void * ipc2_connection_thread(void * socket_param)
{
  int rc;
  int peer;
  int count;
  char buf[512];
  char tx_buf[512];
  fd_set infd;
  
  peer = *((int *) socket_param);

  while(1) {
    FD_ZERO(&infd);
    FD_SET(peer, &infd);

    rc = select(peer + 1, &infd, NULL, NULL, NULL);
    if(rc == -1) {
      if(errno == EPIPE)
	return NULL;

      fprintf(stderr, "select() failed while waiting for IPC data: %s\n", strerror(errno));
      return NULL;
    }

    if(rc == 0) {
      // "Ok, here's some dat-- JUST KIDDING!"
      fprintf(stderr, "select() returned with no data from IPC socket, wtf\n");
      continue;
    }

    memset(buf, 0, sizeof(buf));
    rc = read(peer, buf, sizeof(buf) - 1);
    if(rc == -1) {
      if(errno == EPIPE)
	return NULL;

      fprintf(stderr, "read() failed to read a command from the IPC pipe: %s\n", strerror(errno));
      return NULL;
    }

    buf[rc] = '\0';

    if(! strncasecmp(buf, "shutdown", 8)) {
      printf("Shutdown command received.\n");
      ap.shutdown = 1;
      count = snprintf(tx_buf, sizeof(tx_buf) - 1, "Shutting down\n");
      if(count == -1) {
	return NULL;
      }
      tx_buf[count] = '\0';
    }
    else if(! strncasecmp(buf, "version", 7)) {
      IPC2_RESPOND(APCORE_VERSION);
    }
    else if(! strncasecmp(buf, "filter", 6)) {
      struct bpf_program bpf;

      printf("Got filter command: %s\n", buf);

      /* FIXME you're supposed to figure out and pass the netmask here. */
      rc = pcap_compile(ap.pd, &bpf, buf + 7, 1, 0);
      if(rc == -1) {
	IPC2_RESPOND("pcap_compile() failed to compile that filter string.\n");
      }
      else {
	rc = pcap_setfilter(ap.pd, &bpf);
	if(rc == -1) {
	  IPC2_RESPOND("pcap_setfilter() failed to apply that filter string.\n");
	}
	else {
	  IPC2_RESPOND("filter applied\n");
	}
      }
    }
    else {
      fprintf(stderr, "Unknown IPC command %s received, ignoring.\n", buf);
      count = snprintf(tx_buf, sizeof(tx_buf) - 1, "Huh?\n");
      tx_buf[count] = '\0';
    }

    rc = send(peer, tx_buf, count, 0);
    if(rc == -1) {
      if(errno == EPIPE)
	return NULL;

      fprintf(stderr, "send() failed to send a response to the IPC peer: %s\n", strerror(errno));
      return NULL;
    }

    if(ap.shutdown == 1) {
      return NULL;
    }
  }
}

void * ipc2_handler(void * unused)
{
  int peer;
  struct sockaddr_un sun;
  socklen_t sunlen;
  pthread_t do_not_care;

  while(1) {
    sunlen = sizeof(sun);
    peer = accept(ap.ipc2_socket, (struct sockaddr *) &sun, &sunlen);
    if(peer == -1) {
      fprintf(stderr, "accept() failed while accepting new connection: %s\n",
	      strerror(errno));
      return NULL;
    }

    pthread_create(&do_not_care, NULL, &ipc2_connection_thread, &peer);
  }
}

enum monitor_state
{
  MONITOR_OFF = 0,
  MONITOR_ON = 1
};

// 1 if the monitor state is set right, 0 otherwise.
int run_monitor_script(char * dev, enum monitor_state state)
{
  int rc;
  pid_t pid;
  int status;
  char * argv1;

  if(state == MONITOR_OFF) {
    argv1 = "off";
  }
  else if(state == MONITOR_ON) {
    argv1 = "on";
  }
  else {
    return 0;
  }

  pid = fork();
  if(! pid) {
    rc = execl(ap.monitor_script, ap.monitor_script, dev, argv1, NULL);
    if(rc == -1) {
      fprintf(stderr, "Could not execute monitor script: %s\n", strerror(errno));
    }
    exit(rc);
  }

  pid = waitpid(pid, &status, 0);
  if(pid == -1) {
    fprintf(stderr, "Error waiting for external monitor state script to finish: %s\n", strerror(errno));
    return 0;
  }

  if(! WIFEXITED(status)) {
    fprintf(stderr, "External monitor state script terminated abnormally\n");
    return 0;
  }

  if(WEXITSTATUS(status) != 0) {
    fprintf(stderr, "External monitor state script returned error code %i\n", WEXITSTATUS(status));
    return 0;
  }
  
  return 1;
}

// Returns 0 if something broke, 1 otherwise.
int open_pcap_file(char * filename)
{
  ap.dumper = pcap_dump_open(ap.pd, filename);
  if(ap.dumper == NULL) {
    fprintf(stderr, "pcap_dump_open() failed to open %s: %s\n", filename, pcap_geterr(ap.pd));
    return 0;
  }

  return 1;
}

void * shutdown_watchdog(void * unused)
{
  while(1) {
    if(ap.shutdown == 0) {
      sleep(1);
      continue;
    }

    pcap_breakloop(ap.pd);

    sleep(10);
    printf("SHUTDOWN WATCHDOG: shutdown request didn't get processed.\n");
    printf("SHUTDOWN WATCHDOG: something may be wrong with your wireless drivers.\n");
    exit(1);
  }
}

void spawn_shutdown_watchdog(void)
{
  int rc;
  pthread_t thread;

  rc = pthread_create(&thread, NULL, &shutdown_watchdog, NULL);
  if(rc == -1) {
    fprintf(stderr, "pthread_create() failed in spawn_shutdown_watchdog().\n");
  }
}

void spawn_ipc2_handler(void)
{
  int rc;
  pthread_t thread;

  rc = pthread_create(&thread, NULL, &ipc2_handler, NULL);
  if(rc == -1) {
    fprintf(stderr, "pthread_create() failed in spawn_ipc2_handler().\n");
  }
}

// 1: success, 0: not so much
int open_ipc_pipe(char * pipe_name)
{
  ap.ipc_pipe_fd = open(pipe_name, O_RDWR);
  if(ap.ipc_pipe_fd == -1) {
    fprintf(stderr, "open() failed to open %s as the IPC pipe: %s\n", pipe_name, strerror(errno));
    return 0;
  }

  ap.ipc_flag = 1;
  return 1;
}

void spawn_channel_hopper(void)
{
  int rc;
  static chanhop_request_t cr;

  cr.iface = ap.dev;
  cr.delay_usecs = 333 * 1000;
  cr.shutdown = &ap.shutdown;

  rc = pthread_create(&ap.channel_hopper, NULL, &channelHopper, &cr);
  if(rc == -1) {
    fprintf(stderr, "pthread_create() failed to spawn the channel hopper");
  }
}

void spawn_ipc_handler(void) 
{
  int rc;

  rc = pthread_create(&ap.ipc_handler, NULL, &ipc_handler, NULL);
  if(rc == -1) {
    fprintf(stderr, "pthread_create() failed to spawn the IPC handler");
  }
}

int open_ipc2_pipe(const char * socketname)
{
  int s;
  int rc;
  struct sockaddr_un sun;

  s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if(s == -1) {
    fprintf(stderr, "socket() failed to create the IPC socket: %s\n", 
	    strerror(errno));
    return 0;
  }

  sun.sun_family = AF_UNIX;
  strncpy(sun.sun_path, socketname, sizeof(sun.sun_path));

  umask(077);
  rc = bind(s, (struct sockaddr *) &sun, sizeof(sun));
  if(rc == -1) {
    fprintf(stderr, "bind() failed to set up the IPC socket: %s\n", 
	    strerror(errno));
    return 0;
  }

  rc = listen(s, SOMAXCONN);
  if(rc == -1) {
    fprintf(stderr, "listen() failed to set up the IPC socket: %s\n",
	    strerror(errno));
    return 0;
  }

  ap.ipc2_socket = s;
  ap.ipc_flag = 1;
  return 1;
}

int main(int argc, char **argv){
  int rc;
  int ret;
  int dump_dlts_opt;
  char errbuf[PCAP_ERRBUF_SIZE];
  char option;
  char * pcap_filename;
  struct pcap_pkthdr pkthdr;
  const unsigned char *pkt;
  struct sigaction sa;
  //wnet_t *network;

  static char *options = "c:df:hlm:no:qs:vVw:xA:I:";
  static struct option longoptions[] = {
    { "associated",     0,  NULL,   'A' },
    { "channels",       0,  NULL,   'c' },
    { "dump-dlts",      0,  NULL,   'd' },
    { "file",           0,  NULL,   'f' },
    { "help",           0,  NULL,   'h' },
    { "hexdump",        0,  NULL,   'x' },
    { "ipc",            0,  NULL,   'I' },
    { "ipc2",           0,  NULL,   's' },
    { "list",           0,  NULL,   'l' },
    { "no-monitor",     0,  NULL,   'n' },
    { "output",         0,  NULL,   'o' },
    { "quiet",          0,  NULL,   'q' },
    { "verbose",        0,  NULL,   'v' },
    { "version",        0,  NULL,   'V' },
    { "write",          0,  NULL,   'w' },
    { 0,                0,  0,      0   }
  };
  
  /* Arguments are required */
  if(argc == 1) {
    printUsage();
    return 1;
  }

  memset(&ap, 0, sizeof(ap));
  dump_dlts_opt = 0;
  ap.infodump = 1;

  while((option = getopt_long(argc, argv, options, longoptions, NULL)) != -1) {
    switch(option) {
    case 'A':
      if(optarg == NULL) {
        fprintf(stderr, "Error: interface required.\n");
        printUsage();
        return EXIT_FAILURE;
      }
      if(isAssociated(optarg)) {
        return EXIT_SUCCESS;
      }
      else {
        return EXIT_FAILURE;
      }
    case 'c':
      ap.channel_count = parse(optarg, ap.channels);
      if(ap.channel_count == 0) {
	return EXIT_FAILURE;
      }
      if(ap.infodump >= 2) {
	int i;

	printf("Got cmdline channels:\n");
	for(i = 0; i < ap.channel_count; ++i) {
	  printf(" %u\n", ap.channels[i]);
	}
      }
      break;
    case 'd':
      dump_dlts_opt = 1;
      break;
    case 'f':
      ap.capture_from_file = 1;
      strncpy(ap.dev, optarg, sizeof(ap.dev) - 1);
      break;
    case 'h':
      printUsage();
      return EXIT_SUCCESS;
    case 'I':
      // this is the undocumented "--ipc" option to specify the name
      // of the IPC pipe
      if(open_ipc_pipe(optarg) == 0)
	return EXIT_FAILURE;
      break;
    case 's':
      // this is the undocumented "--ipc2" option to specify the name
      // of the unix socket / named pipe we're using for IPC v2
      if(open_ipc2_pipe(optarg) == 0)
	return EXIT_FAILURE;
      break;
    case 'l':
      list();
      return EXIT_SUCCESS;
    case 'm':
      ap.monitor_script = strdup(optarg);
      if(ap.monitor_script == NULL) {
	return EXIT_FAILURE;
      }
      break;
    case 'n':
      ap.no_monitor = 1;
      break;
    case 'o':
      if(open_xml_file(optarg) == 0)
	return EXIT_FAILURE;
      break;
    case 'v':
      ap.infodump++;
      break;
    case 'V':
      printVersion();
      return EXIT_SUCCESS;
    case 'q':
      ap.infodump = 0;
      break;
    case 'w':
      ap.dumping = 1;
      pcap_filename = optarg;
      break;
    case 'x':
      ap.hexdump = 1;
      break;
    }
  }

  sa.sa_sigaction = &sigint_handler;
  sa.sa_flags = SA_SIGINFO;
  rc = sigaction(SIGINT, &sa, NULL);
  if(rc == -1) {
    fprintf(stderr, "sigaction() failed to install SIGINT handler");
    return EXIT_FAILURE;
  }

  sa.sa_sigaction = &sigterm_handler;
  sa.sa_flags = SA_SIGINFO;
  rc = sigaction(SIGTERM, &sa, NULL);
  if(rc == -1) {
    fprintf(stderr, "sigaction() failed to install SIGTERM handler");
    return EXIT_FAILURE;
  }

  if(optind == argc && ! ap.capture_from_file) {
    fprintf(stderr, "Error: an interface name would be nice.\n");
    printUsage();
    return EXIT_FAILURE;
  }

  if(! ap.capture_from_file) {
    strncpy(ap.dev, argv[optind], MIN(strlen(argv[optind]), sizeof(ap.dev)));

    if(! isWireless(ap.dev)) {
      fprintf(stderr, "%s is not a wireless interface.\n", ap.dev);
      return EXIT_FAILURE;
    }

    if(! ap.no_monitor) {
      printf("Placing %s into monitor mode",ap.dev);	
      if(ap.monitor_script == NULL) {
	/* FIXME these two routines should have the same prototypes... */
	rc = setMonitorMode(ap.dev, 1);
      }
      else {
	printf(" using %s", ap.monitor_script);
	rc = run_monitor_script(ap.dev, MONITOR_ON);
      }

      if(rc == 0) {
	printf("... nope\n");
	return EXIT_FAILURE;
      }
      printf("... ok\n");
    }
  }

  if(ap.capture_from_file == 1) {
    ap.pd = pcap_open_offline(ap.dev, errbuf);
  }
  else {
    ap.pd = pcap_open_live(ap.dev,PCAP_ERRBUF_SIZE,1,100,errbuf);
  }

  if(ap.pd == NULL) {
    fprintf(stderr, "pcap failed to open %s: %s\n", ap.dev, errbuf);
    return EXIT_FAILURE;
  }
  //	pcap_lookupnet(ap.dev,&pcap_if_net,&pcap_if_mask,errbuf);
  //	pcap_compile(ap.pd , &pcap_fcode,pcap_filter,1000,pcap_if_mask);			

  // We prefer the DLTs in this order.  Try them, one at a time.
  if ( pcap_set_datalink(ap.pd, DLT_IEEE802_11_RADIO) == -1 &&
       pcap_set_datalink(ap.pd, DLT_IEEE802_11_RADIO_AVS) == -1 &&
       pcap_set_datalink(ap.pd, DLT_PRISM_HEADER) == -1 &&
       pcap_set_datalink(ap.pd, DLT_IEEE802_11) == -1 ) {

    fprintf(stderr, 
	    "pcap_set_datalink() failed to set an appropriate DLT on %s.\n"
	    "Available DLTs for this device are:\n", ap.dev);
    dump_dlts(ap.pd);
    ret = EXIT_FAILURE;
    goto out;
  }

  if(dump_dlts_opt) {
    dump_dlts(ap.pd);
    ret= EXIT_SUCCESS;
    goto out;
  }

  if(ap.infodump) {
     printf("DLT set to %u (%s)\n", 
       pcap_datalink(ap.pd),
       pcap_datalink_val_to_description(pcap_datalink(ap.pd)));
  }

  if(ap.dumping) {
    if(open_pcap_file(pcap_filename) == 0) {
      ret = EXIT_FAILURE;
      goto out;
    }
  }

  if(ap.xml_out == NULL) {
    if(open_xml_file("wicrawl_discovery-out.xml") == 0) {
      ret = EXIT_FAILURE;
      goto out;
    }
  }

  write_xml_header();

  calc_ll_offset(&ap);
  ap.channel=0;
  ap.shutdown = 0;

  init_bssid_hash();

  /* Setup is complete now.  Start running things. */

  spawn_shutdown_watchdog();
  if(! ap.capture_from_file) {
    spawn_channel_hopper();
  }
  if(ap.ipc_flag) {
    spawn_ipc_handler();
  }
  if(ap.ipc2_socket) {
    spawn_ipc2_handler();
  }

  while(! ap.shutdown) {
    pkt = pcap_next(ap.pd,&pkthdr);
    if(pkt != NULL) {
      if(ap.infodump) {
        printf(" Packet: %i bytes\n",pkthdr.caplen);
      }
      if(ap.hexdump) {
	hexdump(pkt, pkthdr.caplen);
      }
      if(ap.dumper != NULL) {
	pcap_dump((u_char *) ap.dumper, &pkthdr, pkt);
      }
      chkforbeacon(pkt,pkthdr.len,ap.offset);
    }
  }

 out:

  if((! ap.no_monitor) && (! ap.capture_from_file)) {
    printf("\nTaking %s out of monitor mode\n", ap.dev);
    if(ap.monitor_script == NULL) {
      setMonitorMode(ap.dev, 0);
    }
    else {
      run_monitor_script(ap.dev, MONITOR_OFF);
    }
  }

  if(ap.xml_out) {
    fprintf(ap.xml_out, "</detection-run>\n");
  }

  if(ap.dumper != NULL) {
    pcap_dump_flush(ap.dumper);
    pcap_dump_close(ap.dumper);
  }

  return ret;
}


