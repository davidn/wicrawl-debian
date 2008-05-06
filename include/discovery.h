#ifndef _DISCOVERY_H
#define _DISCOVERY_H

/** 
 * The number of channels each apcore instance is capable of
 * scanning. 
 */
#define MAX_CHANNELS 256U

/**
 * The IPC message buffer size.
 */
#define IPC_MSGBUF_SIZE 2048

/** Symbolic type for channels. */
typedef unsigned char channel_t;

/** A symbolic type for a BSSID. */
typedef unsigned char bssid_t[6];

typedef enum encryption_types
{
  ENC_NONE = 0,
  ENC_WEP = 1,
  ENC_WPA = 2
} encryption_type;

enum radio_hdr_fields
{
  F_CHANNEL = 1,
  F_SIGNAL_DBM = 2,
  F_RATE_KBPS = 4
};

/**
 * Hardware-neutral radio header info.
 *
 * Each capture source fills out one of these when feeding captured
 * frames to the discovery engine core.
 */
typedef struct radio_hdr_info {
  enum radio_hdr_fields fields;

  /** The 802.11 channel number we received the packet on. */
  unsigned long channel;

  /**
   * The signal strength in decibels relative to one milliwatt.
   *
   * Formula: dBm(x) = 10 * log_10(x / 1 milliwatt)
   */
  long signal_dBm;  

  /**
   * The rate the packet was transmitted at, in kilobits/sec.
   */
  unsigned long rate_kbps;
} radio_hdr_info_t;

/**
 * A radio header cracker.
 *
 * @return >0: The size of the radio header.  The 802.11 header begins
 *             after this many bytes.
 *
 *         <=0: Something went wrong during header parsing.  Drop the frame.
 */
typedef int (* rhdr_cracker)(const unsigned char * pkt, unsigned long pktlen, radio_hdr_info_t * rhdr);

/** SSID types. */
enum ssid_type 
{
  SSID_TYPE_AP = 1,
  SSID_TYPE_PROBE = 2
};

enum cos_state
{
  NO_COS = 0,
  COS_INITIAL = 1,
  COS_PRESENT = 2
};

/**
 * wlan-ng / prism AVS header.  Stolen from kismet.  Fields in network
 * byte order.
 */
typedef struct {
  uint32_t version;
  uint32_t length;
  uint64_t mactime;
  uint64_t hosttime;
  uint32_t phytype;
  uint32_t channel;
  uint32_t datarate;
  uint32_t antenna;
  uint32_t priority;
  uint32_t ssi_type;
  int32_t ssi_signal;
  int32_t ssi_noise;
  uint32_t preamble;
  uint32_t encoding;
} avs_80211_1_header;

/** 
 * One of the wlan-ng elements in the wlan-ng header.
 */
typedef struct {
  uint32_t did __attribute__ ((packed));
  uint16_t status __attribute__ ((packed));
  uint16_t len __attribute__ ((packed));
  uint32_t data __attribute__ ((packed));
} p80211item_uint32_t;

#define WLAN_DEVNAMELEN_MAX 16

/**
 * Prism 802.11 headers.  Stolen from kismet.
 */
typedef struct {
  uint32_t msgcode __attribute__ ((packed));
  uint32_t msglen __attribute__ ((packed));
  uint8_t devname[WLAN_DEVNAMELEN_MAX];
  p80211item_uint32_t hosttime;
  p80211item_uint32_t mactime;
  p80211item_uint32_t channel;
  p80211item_uint32_t rssi;
  p80211item_uint32_t sq;
  p80211item_uint32_t signal;
  p80211item_uint32_t noise;
  p80211item_uint32_t rate;
  p80211item_uint32_t istx;
  p80211item_uint32_t frmlen;
} wlan_ng_prism2_header;

/** Some layer-2 data about a SSID or STA we've seen broadcasting. */
typedef struct ssid_info
{
  /** The BSSID or source address of the device in question. */
  bssid_t bssid;
  /** Is there any unreported change of state on this node? */
  enum cos_state cos_state;
  /** Last power level seen, in dBm */
  long signal_dBm;
  /** How many broadcast packets have we seen from this src address? */
  unsigned int broadcasts;
  /** How many unicast packets have we seen? */
  unsigned int unicast;
  /** Is this an AP or a STA? */
  enum ssid_type type;
} ssid_info;

/**
 * An IPC update message from the frame cracker to the IPC manager.
 */
typedef struct ipc_update_msg
{
  /** The BSSID of the station we're talking about. */
  bssid_t bssid;
  /** The SSID of any SS the station belongs to.. */
  char ssid[32 + 1];
  encryption_type enc;
  radio_hdr_info_t radio_hdr;
  struct bssid_hash_ent * ent;
  struct ipc_update_msg * prev;
  struct ipc_update_msg * next;
} ipc_update_msg;

typedef struct apcore_s {
  char dev[PCAP_ERRBUF_SIZE];
  int hexdump;
  int infodump;
  // 1 = we're capturing pcap data from a file instead of a device, 0 otherwise
  int capture_from_file;
  int hopdelay;
  pcap_t *pd;
  FILE * xml_out;
  // fd of the IPC fifo
  int ipcfifo;
  // Pointer to list of IPC updates for the IPC manager.
  ipc_update_msg * ipc_update_head;
  // Pointer to last element in IPC update list
  ipc_update_msg * ipc_update_tail;
  int pcap_fd;
  // If we're channel hopping, this is the channel we're currently tuned to.
  int channel;
  // Offset to the 802.11 header in captured frames.
  // -1 means variable length, 0 means no radio header, >0 is the size of
  // the radio header in bytes.
  int offset;
  // 1 means user wants us to shut down, 0 otherwise.
  int shutdown;
  pthread_t channel_hopper;
  pthread_t ipc_handler;
  // 1 if we're speaking the IPC protocol, 0 if not.
  int ipc_flag;
  // File descriptor of the IPC pipe.
  int ipc_pipe_fd;
  // Socket for IPC v2, or 0 if none.
  int ipc2_socket;
  // 1 if we're dumping pcap packets, 0 otherwise.
  int dumping;
  // Pcap dumper object used for writing out the captured packets
  pcap_dumper_t * dumper;
  bssid_t ** bssid_list;
  rhdr_cracker cracker;
  // Number of channels we're scanning.
  unsigned int channel_count;
  // List of channels to scan.
  channel_t channels[MAX_CHANNELS];
  // 1 means the user doesn't want us to change the monitor mode setting,
  // 0 otherwise.
  int no_monitor;
  // Number of channels in the hardware channel list.
  unsigned int hw_channel_count;
  // List of channels supported by this driver, region, and hardware.
  channel_t hw_channels[MAX_CHANNELS];
  // Path to monitor script, which we can optionally call to change
  // the monitor state of the interface.
  char * monitor_script;
} apcore_s;

/** 
 * A description of how an instance of a channel hopper should act.
 */
typedef struct chanhop_request {
  /** 
   * Pointer to a character string with the name of the interface to
   * start channel hopping on.
   */
  char * iface;

  /** The number of microseconds between channel hops. */
  unsigned long delay_usecs;

  /** 
   * Pointer to a variable which the discovery core can use to shut
   * down the channel hopper.  This is initially zero, but will be set
   * to 1 when the discovery core wants the channel hopper to shut
   * down.
   */
   int * shutdown;
} chanhop_request_t;

extern apcore_s ap;

int parse(char * string, channel_t * channels);

// Each platform needs to implement the following interfaces.

/**
 * See if an interface is a wireless interface.
 *
 * @param iface [in] Pointer to the name of the interface to test.
 *
 * @return 1 if the interface is a wireless interface, 0 if not.
 */
int isWireless(const char * iface);

/**
 * Is the given interface associated with an access point?
 *
 * @param iface [in] A pointer to the name of the interface to test.
 *
 * @return 1 if the interface is associated, 0 otherwise.
 */
int isAssociated(char * iface);

/**
 * Put an interface into monitor mode.
 *
 * @param iface [in] Pbointer to a character string with the name of
 * the interface to put into monitor mode.
 *
 * @param enable [in] 1: enable monitor mode.  0: disable monitor
 * mode.
 *
 * @return 1 is returned if the interface is now in the requested
 * rfmon state.  0 is returned if the interface is not in the
 * requested rfmon state or the state is unknown due to an error.
 */
int setMonitorMode(char * iface, int enable);

/**
 * Cycle the radio hardware through its available channels.  The
 * discovery engine core will spawn this routine as an independent
 * thread.
 *
 * @param chanhop_request [in] A pointer to a chanhop_request_t which
 * the channel hopper will use to determine how to behave.
 */
void * channelHopper(void * chanhop_request);

#endif /* _DISCOVERY_H */
