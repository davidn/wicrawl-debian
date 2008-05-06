CC = gcc -g -w 
OBJS = cmd.clearinfo.o cmd.dropline.o cmd.dhcp.o cmd.help.o cmd.interface.o cmd.list.o cmd.resolvegw.o cmd.settings.o cmd.spoof.o dropline.gotarp.o dropline.gottcp.o dropline.gotudp.o  dropline.tcp.o dropline.arp.o dropline.udp.o puldb.init.o dropline.addtarget.o pul.o
LIBS = -lpcap -lpthread
OFLAGS = -O3

pul: $(OBJS)
	$(CC) $(OFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	rm -f *.o pul

install: 
	cp -v pul /usr/sbin/

