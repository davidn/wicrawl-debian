#!/usr/bin/perl -w
#
# APIdentd - AP manufacturer identification plug-in for Wicrawl
# Initial version By: Matthew Benenati <dk.mak0[at]gmail.com>
# Updated by Aaron Peterson <aaron@midnightresearch.com>
#
# It now takes an updated version of of the oui database directly.
# Just grab the headers (so we don't use as much space).
#
# You can get the updated version here: 
# 	wget -nd http://standards.ieee.org/regauth/oui/oui.txt
#   cat oui.txt | grep hex > oui-headers.txt

use strict;
use Getopt::Std;
use File::Basename;
$Getopt::Std::STANDARD_HELP_VERSION='1';

my $basedir=dirname($0);
my $oui=$basedir . "/oui-headers.txt";
my $debug=0;

my $bssid; my $encryption=""; my $ssid=0; my $interface=0; my $nick=0; my $version=0; my $run=0; 

our($opt_b, $opt_e, $opt_i, $opt_s, $opt_n, $opt_r, $opt_v);
getopts ("b:e:i:n:r:s:v:");

$bssid =      $opt_b if(defined $opt_b);
$encryption = $opt_e if(defined $opt_e);
$ssid =       $opt_s if(defined $opt_s);
$interface =  $opt_i if(defined $opt_i);
$nick =       $opt_n if(defined $opt_n);
$run =        $opt_r if(defined $opt_r);
$version =    $opt_v if(defined $opt_v);

if((!defined($bssid)) || ($bssid eq "")) {
	print " [*] usage: $0 -b <bssid>\n";
	exit 1;
}

if(! -f $oui) {
	my $bzip;
	if(-f $oui . ".bz2") {
		$bzip=`which bunzip2 2>/dev/null`;
		chomp($bzip);
		if (! -f $bzip) {
			print " [!!] Can't find bunzip2, please decompress [${oui}.bz2]\n";
			exit 1;
		} 

		print "  [*] Uncompressing [${oui}.bz2]\n";
		`$bzip ${oui}.bz2 >/dev/null 2>&1`;

	} else {
		print " [!!] Can't find [$oui]\n";
		exit 1;
	}
}

my $bssid2=uc(substr($bssid,0,8));
$bssid2=~s/:/-/g;
my $vendor="UNKNOWN";

open(OUI, "<$oui") || die " [!!] Can't open [$oui]\n";
foreach my $line (<OUI>) {

	$line =~ m/^([^\s]+)\s+[^\s]+\s+([^\s]+)/i;
	my $mac=$1;
	my $mfgr=$2;

	$debug && print " [*] Checking mac [$mac] part [$bssid2] mfgr [$mfgr]\n";

	next if ( (!defined($mac)) || (!defined($mfgr)) );
	
	if($bssid2 =~ m/$mac/) {
		$vendor=$mfgr;
		last;
	}
}

print "  ============ < APIdentd > ==============\n";
print "  * BSSID:     [$bssid]\n";
print "  * Vendor:    [$vendor]\n";
print "  ============ </APIdentd > ==============\n";

exit 0;

# vim:ts=2:sw=2:sts=0
