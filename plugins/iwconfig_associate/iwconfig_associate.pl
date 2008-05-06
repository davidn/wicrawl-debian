#!/usr/bin/perl -w
#
# This is a template plugin script for wicrawl
# http://midnightresearch.com/projects/wicrawl

use strict;
use Getopt::Std;
use File::Basename;
$Getopt::Std::STANDARD_HELP_VERSION='1';

my $bssid=0; my $encryption=""; my $ssid=0; my $interface=0; my $nick=0; my $version=0;
our($opt_b, $opt_e, $opt_i, $opt_s, $opt_n, $opt_v);
my $tries=2;
my $rc;
my $delay=3;
my $iwconfig;
my $apcore=dirname($0) . "/../../discovery/apcore";

#####################################################################
# functions
sub isassociated() {

	my $rc=system($apcore, "-A", $interface);

	if($rc==-1) {
		print " [!!] Failed to execute $apcore\n\t$!\n";
	}

	$rc=$rc >> 8;

	return $rc;
}

# /end functions
#####################################################################

print "  ============ <iwconfig associate plugin> ==============\n";

getopts ("b:e:i:n:r:s:v:");
if(    (!defined $opt_b) || (!defined $opt_i) 
    || (!defined $opt_n) || (!defined $opt_s) 
		|| (!defined $opt_v) || (!defined $opt_e)) {
	print "  [!] This is intended to be run as a wicrawl plugin...\n";
	print "  [!] usage $0 <options>\n";
	print "\t-b <bssid>\n";
	print "\t-e <encryption>\n";
	print "\t-i <interface>\n";
	print "\t-n <nickname>\n";
	print "\t-s <ssid>\n";
	print "\t-v <version>\n";
	exit 1;
}

$bssid =      $opt_b if(defined $opt_b);
$encryption = $opt_e if(defined $opt_e);
$ssid =       $opt_s if(defined $opt_s);
$interface =  $opt_i if(defined $opt_i);
$nick =       $opt_n if(defined $opt_n);
$version =    $opt_v if(defined $opt_v);

# TODO Actually Do WEP check once discovery engine supports it
#if($encription=~){
#}

if(! -x $apcore) {
	$apcore=`which apcore 2>/dev/null`;
	chomp($apcore);
	if($apcore eq "" ) {
		  print "  [!] Can't find apcore [$apcore] exiting...\n";
			exit 1;
	}
}

# verify we can find iwconfig
$iwconfig=`which iwconfig 2>/dev/null`;
chomp($iwconfig);
if($iwconfig eq "" ) {
	print "  [!] Can't find iwconfig in path... exiting...\n";
	exit 1;
}

for(my $i=1; $i<=$tries; $i++) {
	my $msg="  [*] Attempting association\n\t";
	$msg.="$iwconfig $interface essid '$ssid' nick '$nick'\n";

	print $msg;
	print `$iwconfig $interface essid \"$ssid\" nick $nick`;

	sleep $delay;
	$rc = isassociated();
	last if($rc == 0); # 0 means no error

	print "  [*] Trying again [try $i of $tries]...\n";
}

my $lastmsg="  =========== </iwconfig associate plugin > ==============\n";
if($rc==0) {
	print "  [*] Associate worked!...\n";
	print $lastmsg;
	exit 8;
} else {
	print "  [!] Associate failed...\n";
	print $lastmsg;
	exit 1;
}

exit 0;
# vim:ts=2:sw=2:sts=0
