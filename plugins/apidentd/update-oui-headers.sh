#!/bin/bash
# This updates the oui headers from the IEEE site

basedir=`dirname $0`
headers="$basedir/oui-headers.txt"

if [ -f $headers ] ; then
	echo "Moving old headers out of the way" 
	mv $headers $headers.bak
fi

echo "Getting OUI Database list from http://standards.ieee.org/regauth/oui/oui.txt"
wget -nd http://standards.ieee.org/regauth/oui/oui.txt -O - | grep '(hex)' > $headers

echo "Done."

exit 0
