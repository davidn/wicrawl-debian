#!/usr/bin/perl -w
#
# Text to speech announcement for wicrawl events
# http://midnightresearch.com/projects/wicrawl
#
# Author: Aaron Peterson
#
# Requires 'flite' to be installed

use strict;
use Getopt::Std;

$Getopt::Std::STANDARD_HELP_VERSION='1';

my $bssid=0; my $encryption=""; my $ssid=0; my $interface=0; my $nick=0; my $version=0;
our($opt_b, $opt_e, $opt_i, $opt_s, $opt_n, $opt_v, $opt_r);
getopts ("b:e:i:n:r:s:v:");

my $lockfile="/tmp/wicrawl-tts.lock";

if(!defined $opt_s) {
  print "  [!] usage $0 <options>\n";
  print "\t-s <ssid>\n";
	exit 1;
}

# This means it's already running
if(-f $lockfile) {
	exit 0;
} else {
	`touch $lockfile`;
}

$bssid =      $opt_b if(defined $opt_b);
$encryption = $opt_e if(defined $opt_e);
$ssid =       $opt_s if(defined $opt_s);
$interface =  $opt_i if(defined $opt_i);
$nick =       $opt_n if(defined $opt_n);
$version =    $opt_v if(defined $opt_v);

# check for flite
my $flite=`which flite 2>/dev/null`;
chomp($flite);
if($flite eq "" ) {
  print "  [!] Can't find flite in path... exiting...\n";
  exit 1;
}

my $eventlvl=$ENV{'WICRAWL_EVENTLVL'};
my $msg;

$eventlvl="" if (!defined($eventlvl));

# messages for most event levels 
if($eventlvl eq "have-internet") {
	$msg="Wicrawl found internet access through Access Point $ssid";

} elsif ($eventlvl eq "discovery") {
	$msg="Wicrawl found new Access Point $ssid";

} elsif ($eventlvl eq "associated") {
	$msg="Wicrawl associated to Access Point $ssid";

} elsif ($eventlvl eq "have-ip") {
	$msg="Wicrawl got an ip address from Access Point $ssid";

} else {
	$msg="Wicrawl unknown event level occured in text to speech plug in";
}

print `echo $msg | $flite`;
unlink($lockfile) if (-f $lockfile);

exit 0;

# vim:ts=2:sw=2:sts=0
