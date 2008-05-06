#!/usr/bin/perl -w
#
# This is a plugin to see how fast is our internet connectivity
# it simply measures average ping time for the specified host.
# http://midnightresearch.com/projects/wicrawl

use strict;
use Getopt::Std;
$Getopt::Std::STANDARD_HELP_VERSION='1';

my $bssid=0; my $encryption; my $ssid=0; my $interface=0; my $nick=0; my $version=0;
our($opt_b, $opt_e, $opt_i, $opt_s, $opt_n, $opt_v);

my $host="4.2.2.1";
my $ping;
my $average = 0;
my $line;
my $rc;


print "  ============ <internet speed check plugin> ==============\n";
getopts ("b:e:i:n:s:r:v:");
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


$bssid =     $opt_b if(defined $opt_b);
$encryption =$opt_e if(defined $opt_e);
$ssid =      $opt_s if(defined $opt_s);
$interface = $opt_i if(defined $opt_i);
$nick =      $opt_n if(defined $opt_n);
$version =   $opt_v if(defined $opt_v);

# TODO TODO TODO need to use a better interface dependent "ping"

# verify we can find ping
$ping=`which ping 2>/dev/null`;
chomp($ping);
if($ping eq "" ) {
	print "  [!] Can't find ping in path... exiting...\n";
	exit 1;
}

#print "  [*] Attempting internet check to host [$host]\n";

# Get ping responses
my $counter = 0;
my $sum = 0;

foreach $line (`$ping -c 4 -I $interface $host`)  {
	if($line =~ /time=(\d{2,10}\.?\d?)\sms/) {
		print "\t$1 milliseconds\n";
		$sum += $1;
		$counter++;
	}
}
if($sum and $counter) {
	$average = $sum/$counter;
}

my $lastmsg="  =========== <internet speed check plugin > ==============\n";
if($average gt 0) {
	print "  [*] Internet Connection Speed is $average milliseconds!...\n";
	print $lastmsg;
	exit 10;
} else {
	print "  [!] Can't measure Internet Connection Speed...\n";
	print $lastmsg;
	exit 1;
}

exit 0;
# vim:ts=2:sw=2:sts=0
