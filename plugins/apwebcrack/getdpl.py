#!/usr/bin/python
# Get the default password list from phenoelit, and parse it out of the html.
# The script spits it out in this format    username:password

import socket
import re
import traceback

try:
    host = "www.phenoelit-us.org"
    port = 80
    path = "/dpl/dpl.html"
    print " [*] Connecting to [%s] for default password list" % host + path
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    addr  = (host,port)
    httpmsg = "GET "+path+" HTTP/1.0\r\nHost: www.phenoelit-us.org\r\n\r\n"
    print httpmsg
    sock.connect(addr)
    sock.send(httpmsg)
    lines = ""    
    while(1):
        rec = sock.recv(1024)
        if not rec: break
        lines += rec
    
    recArray = lines.split("<TR>")
    dpl=[]
    for line in recArray:   
	# explicitly set these so previous values aren't ever kept
        username=""
        password=""
        lineElements = line.split("</TD>")
        try:    
            # strip tags, etc.
            password = re.search(r"^\s*(<[^>]+>)+([^<>]*)(<[^>]+>)*$", lineElements[5]).group(2)
            username = re.search(r"^\s*(<[^>]+>)+([^<>]*)(<[^>]+>)*$", lineElements[4]).group(2)

            if ((username == "n/a") or (username == "(none)")): username = ""
            if ((password == "n/a") or (password == "(none)")): password = ""

            if not (password == "" and username == ""): 
              combo=username+":"+password
              # There are lots of repeats, get a unique list...
              if combo not in dpl: dpl.append(combo)
        except:
            pass 

    # print out all matches
    for line in dpl: print line
except:
    traceback.print_exc()
