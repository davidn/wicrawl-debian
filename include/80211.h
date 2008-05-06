/*
 * $Id: 80211.h,v 1.4 2006-11-01 09:22:31 jspence Exp $
 * 
 *
 * 
 * Thank you ethereal
 *
 *
 *
 * 
 */



#ifndef _80211_H
#define _80211_H

#define f80211_LINELEN 1024

/* This is from the 80211 dissector included with ethereal */

/* IEEE802.11 Frame types */
#define MGT_FRAME            0x00       /* Frame type is management */
#define CONTROL_FRAME        0x01       /* Frame type is control */
#define DATA_FRAME           0x02       /* Frame type is Data */

/* IEEE802.11 Frame subtypes */
#define MGT_ASSOC_REQ        0x00       /* Management - association request        */
#define MGT_ASSOC_RESP       0x01       /* Management - association response       */
#define MGT_REASSOC_REQ      0x02       /* Management - reassociation request      */
#define MGT_REASSOC_RESP     0x03       /* Management - reassociation response     */
#define MGT_PROBE_REQ        0x04       /* Management - Probe request              */
#define MGT_PROBE_RESP       0x05       /* Management - Probe response             */
#define MGT_BEACON           0x08       /* Management - Beacon frame               */
#define MGT_ATIM             0x09       /* Management - ATIM                       */
#define MGT_DISASS           0x0A       /* Management - Disassociation             */
#define MGT_AUTHENTICATION   0x0B       /* Management - Authentication             */
#define MGT_DEAUTHENTICATION 0x0C       /* Management - Deauthentication           */
#define CTRL_PS_POLL         0x1A       /* Control - power-save poll               */
#define CTRL_RTS             0x1B       /* Control - request to send               */
#define CTRL_CTS             0x1C       /* Control - clear to send                 */
#define CTRL_ACKNOWLEDGEMENT 0x1D       /* Control - acknowledgement               */
#define CTRL_CFP_END         0x1E       /* Control - contention-free period end    */
#define CTRL_CFP_ENDACK      0x1F       /* Control - contention-free period end/ack */
#define DATA                 0x20       /* Data - Data                             */
#define DATA_CF_ACK          0x21       /* Data - Data + CF acknowledge            */
#define DATA_CF_POLL         0x22       /* Data - Data + CF poll                   */
#define DATA_CF_ACK_POLL     0x23       /* Data - Data + CF acknowledge + CF poll  */
#define DATA_NULL_FUNCTION   0x24       /* Data - Null function (no data)          */
#define DATA_CF_ACK_NOD      0x25       /* Data - CF ack (no data)                 */
#define DATA_CF_POLL_NOD     0x26       /* Data - Data + CF poll (No data)         */
#define DATA_CF_ACK_POLL_NOD 0x27       /* Data - CF ack + CF poll (no data)       */

/* Beacon header capability */
#define IEEE80211_CAPINFO_ESS                   0x0001
#define IEEE80211_CAPINFO_IBSS                  0x0002
#define IEEE80211_CAPINFO_CF_POLLABLE           0x0004
#define IEEE80211_CAPINFO_CF_POLLREQ            0x0008
#define IEEE80211_CAPINFO_PRIVACY               0x0010
#define IEEE80211_CAPINFO_SHORT_PREAMBLE        0x0020
#define IEEE80211_CAPINFO_PBCC                  0x0040
#define IEEE80211_CAPINFO_CHNL_AGILITY          0x0080

/* IEEE802.11 tags */
#define TAG_SSID           0x00
#define TAG_SUPP_RATES     0x01
#define TAG_FH_PARAMETER   0x02
#define TAG_DS_PARAMETER   0x03
#define TAG_CF_PARAMETER   0x04
#define TAG_TIM            0x05
#define TAG_IBSS_PARAMETER 0x06
#define TAG_CHALLENGE_TEXT 0x10

#ifdef _BIG_ENDIAN
typedef struct frame_control_t {
  unsigned subtype:4;
  unsigned type:2;
  unsigned version:2;

  unsigned order:1;
  unsigned wep:1;
  unsigned more_data:1;
  unsigned powermgmt:1;
  unsigned retry:1;
  unsigned more_frag:1;
  unsigned from_ds:1;
  unsigned to_ds:1;
} frame_control_t;

#else

typedef struct frame_control_t {
  unsigned version:2;
  unsigned type:2;
  unsigned subtype:4;

  unsigned to_ds:1;
  unsigned from_ds:1;
  unsigned more_frag:1;
  unsigned retry:1;
  unsigned powermgmt:1;
  unsigned more_data:1;
  unsigned wep:1;
  unsigned order:1;
} frame_control_t;
#endif /* _BIG_ENDIAN */

typedef struct f80211_mac_t {
  unsigned char fc[2];
  unsigned char id[2];
  unsigned char address1[6];
  unsigned char address2[6];
  unsigned char address3[6];
  unsigned char seq[2];
} f80211_mac_t;

typedef struct beacon_header_t {
  unsigned char timestamp[8];
  unsigned char interval[2];
  unsigned short capability;
  unsigned char ssid_element_id;
  unsigned char ssid_length;
  char ssid[1]; // actually, it's ssid_length bytes long.
} beacon_header_t;

typedef struct f80211_t {
  unsigned char ssid[f80211_LINELEN];  
  unsigned char mac[f80211_LINELEN];
  unsigned char bss[f80211_LINELEN];
  unsigned char dest[f80211_LINELEN];
  unsigned char manufacturer[f80211_LINELEN];
  int channel;
  int type;
  int subtype;
  int wepcapable;
  int wepused;
  int ap;
  f80211_mac_t f_mac;
} f80211_t;

#endif /* _80211_H */
