#define PICOD_PORT 1234

struct picod_proto_s {
	unsigned char cmd;
#define PICOD_CMD_NUMCARDS	0x0
#define PICOD_CMD_READ		0x1
#define PICOD_CMD_WRITE		0x2
#define PICOD_CMD_TRYLOCK	0x3
#define PICOD_CMD_UNLOCK	0x4
#define PICOD_CMD_REBOOT	0x5
#define PICOD_CMD_ATTR		0x10
#define PICOD_CMD_MEM		0x20
#define PICOD_CMD_IO		0x30
	unsigned char num;
	unsigned short len;
	unsigned long addr;
	unsigned char buf[2048];
} __attribute__ ((packed));
