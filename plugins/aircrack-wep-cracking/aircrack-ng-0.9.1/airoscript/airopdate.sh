#! /bin/bash

# Program:	Airopdate                                                          
# Authors:	Base Code by Daouid
# Date:	        15.05.2007

#The path where the data is stored (FOLDER MUST EXIST !)
DUMP_PATH="/wifi"

# leave this alone (if you edit this, it will screw up the menu)
CHOICES="1 2 3 4 5"


function chooseversion {
while true; do
  clear
  echo "#######################################"
  echo "###   Select aircrack-ng version    ###"
  echo "###                                 ###"
  echo "###   1) Latest 0.9 branch          ###"
  echo "###   2) Latest 1.0-dev             ###"
  echo "###   3) Specific revision          ###"
  echo "###   4) Latest Stable              ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) latest09 ; break ;;
    2 ) latest10 ; break ;;
    3 ) svnrev ; break ;;
    4 ) stable ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
function latest09 {
svn co http://trac.aircrack-ng.org/svn/trunk/ aircrack-ng-svn
cd aircrack-ng-svn
make clean
make uninstall
make
make install
cd $DUMP_PATH
}
function latest10 {
svn co http://trac.aircrack-ng.org/svn/branch/1.0-dev aircrack-ng-dev
cd aircrack-ng-dev
make clean
make uninstall
make
make install
cd $DUMP_PATH
}
function svnrev {
  echo "#######################################"
  echo "###     Input revision number       ###"
  echo "#######################################"
read rev
echo You typed: $rev
set -- ${rev}

svn co -r $rev http://trac.aircrack-ng.org/svn/trunk/ aircrack-ng-r"$rev"
cd aircrack-ng-rev
make clean
make uninstall
make
make install
cd $DUMP_PATH
}

function stable {
svn co http://trac.aircrack-ng.org/svn/tags/0.9 aircrack-ng-stable
cd aircrack-ng-stable
make clean
make uninstall
make
make install
cd $DUMP_PATH
}

function airoscript {
svn co http://trac.aircrack-ng.org/svn/branch/airoscript/ airoscript
cd airoscript
chmod +x airoscript.sh
cd $DUMP_PATH
}

function choosedriver {
while true; do
  clear
  echo "#######################################"
  echo "###  Select driver/chipset version  ###"
  echo "###                                 ###"
  echo "###   1) ASPj's rt2570 drivers      ###"
  echo "###   2) rt2500                     ###"
  echo "###   3) Madwifi-ng                 ###"
  echo "###   4) Prism54                    ###"
  echo "###   5) Hostap                     ###"
  echo "###   6) Wlanng                     ###"
  echo "###   7) rt61                       ###"
  echo "###   8) rt73                       ###"
  echo "###   9) r8180-sa2400               ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) rt2570 ; break ;;
    2 ) rt2500 ; break ;;
    3 ) madwifi ; break ;;
    4 ) prism54 ; break ;;
    5 ) hostap ; break ;;
    6 ) wlanng ; break ;;
    7 ) rt61 ; break ;;
    8 ) rt73 ; break ;; 
    9 ) r8180sa2400 ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}

function r8180sa2400 {
ifconfig wlan0 down
rmmod r8180
wget http://ovh.dl.sourceforge.net/sourceforge/rtl8180-sa2400/rtl8180-0.21.tar.gz
wget http://patches.aircrack-ng.org/rtl8180-0.21v2.patch
tar -xvzf rtl8180-0.21.tar.gz
cd rtl8180-0.21
patch -Np1 -i ../rtl8180-0.21v2.patch
make && make install
depmod -a
modprobe r8180
cd $DUMP_PATH
}

function rt61 {
wget http://rt2x00.serialmonkey.com/rt61-cvs-daily.tar.gz
tar xvfz rt61-cvs-daily.tar.gz
cd rt61-cvs-*
cd Module
make
make install
modprobe rt73
cd $DUMP_PATH
}

function rt73 {
wget http://rt2x00.serialmonkey.com/rt73-cvs-daily.tar.gz
tar xvfz rt73-cvs-daily.tar.gz
cd rt73-cvs-*
cd Module
make
make install
modprobe rt73
cd $DUMP_PATH
}

function hostap {
ifconfig wlan0 down
wlanctl-ng wlan0 lnxreq_ifstate ifstate=disable
/etc/init.d/CardBus stop
rmmod prism2_pci
rmmod hostap_pci
wget http://hostap.epitest.fi/releases/hostap-driver-0.4.9.tar.gz
tar -xvzf hostap-driver-0.4.9.tar.gz
cd hostap-driver-0.4.9
wget http://patches.aircrack-ng.org/hostap-driver-0.4.7.patch
patch -Np1 -i hostap-driver-0.4.7.patch
make && make install
mv -f /etc/pcmcia/wlan-ng.conf /etc/pcmcia/wlan-ng.conf~
/etc/init.d/pcmcia start
modprobe hostap_pci &>/dev/null
cd $DUMP_PATH
}

function wlanng {
ifconfig wlan0 down
wlanctl-ng wlan0 lnxreq_ifstate ifstate=disable
/etc/init.d/pcmcia stop
rmmod prism2_pci
rmmod prism2_usb
rmmod prism2_cs
rmmod p80211
rmmod hostap_pci
find /lib/modules \( -name p80211* -o -name prism2* \) -exec rm -v {} \;
wget ftp://ftp.linux-wlan.org/pub/linux-wlan-ng/linux-wlan-ng-0.2.8.tar.bz2
wget http://patches.aircrack-ng.org/linux-wlan-0.2.5.packet.injection.patch
tar -xjf wlanng-0.2.8.tar.bz2
cd linux-wlan-ng-0.2.8
patch -Np1 -i ../linux-wlan-0.2.5.packet.injection.patch
make autoconfig && make all && make install
mv /etc/pcmcia/hostap_cs.conf /etc/pcmcia/hostap_cs.conf~
/etc/init.d/pcmcia start
modprobe prism2_pci &>/dev/null
cd $DUMP_PATH
}

function rt2570 {
ifconfig rausb0 down
rmmod rt2570
wget http://homepages.tu-darmstadt.de/~p_larbig/wlan/rt2570-k2wrlz-1.6.0.tar.bz2
tar -xvjf rt2570-k2wrlz-1.6.0.tar.bz2
cd rt2570-k2wrlz-1.6.0/Module
make && make install
modprobe rt2570
cd $DUMP_PATH
}

function rt2500 {
ifconfig ra0 down
rmmod rt2500
wget http://rt2x00.serialmonkey.com/rt2500-cvs-daily.tar.gz
tar -xvzf rt2500-cvs-daily.tar.gz
cd rt2500-cvs-**********/Module
make && make install
modprobe rt2500
cd $DUMP_PATH
}

function madwifi {
ifconfig ath0 down
ifconfig wifi0 down
rmmod wlan_wep ath_rate_sample ath_rate_onoe ath_pci wlan ath_hal ath_rate_amrr 2>/dev/null
svn checkout http://svn.madwifi.org/trunk/ madwifi-ng
wget http://patches.aircrack-ng.org/madwifi-ng-r2277.patch
cd madwifi-ng
patch -Np1 -i ../madwifi-ng-r2277.patch
make
make install
depmod -ae
modprobe ath_pci
cd $DUMP_PATH
}

function prism54 {
ifconfig eth1 down
rmmod prism54
wget "http://svnweb.tuxfamily.org/dl.php?repname=prism54+%28prism54%29&path=%2Ftrunk%2F&rev=531&isdir=1" -O prism54_r531.tar.gz
wget http://patches.aircrack-ng.org/prism54-svn-20050724.patch
tar -xvzf prism54_r531.tar.gz
cd trunk
patch -Np1 -i ../prism54-svn-20050724.patch
make modules && make install
wget http://prism54.org/firmware/1.0.4.3.arm
mkdir -p /usr/lib/hotplug/firmware
mkdir -p /lib/firmware
cp 1.0.4.3.arm /usr/lib/hotplug/firmware/isl3890
mv 1.0.4.3.arm /lib/firmware/isl3890
depmod -a
modprobe prism54
cd $DUMP_PATH
}

function menufonction {
xterm $HOLD $TOPRIGHT -title "Fake function to jump to menu" -e echo "Aircrack-ng is a great tool, Mister_X ASPj HIRTE are GODS"
}
# menu listing command	
function menu {
  echo "###########################################"
  echo "### What do you want to do?             ###"
  echo "### 1) Aircrack-ng - Get aircrack-ng    ###"
  echo "### 2) Drivers     - Get drivers        ###"
  echo "### 3) Airoscript  - Get airoscript     ###"
  echo "### 4) Quit        - Exit this script   ###"		
}
#######################################################################
# script start
	
	mkdir $DUMP_PATH
	cd $DUMP_PATH
	menu	
select choix in $CHOICES; do					
	if [ "$choix" = "1" ]; then
	chooseversion
	menu			
	elif [ "$choix" = "2" ]; then
	choosedriver
	menu					
	elif [ "$choix" = "3" ]; then
	airoscript
	menu	
	elif [ "$choix" = "4" ]; then
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

