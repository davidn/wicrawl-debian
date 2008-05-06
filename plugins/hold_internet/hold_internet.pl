#!/usr/bin/perl -w
#
# This is a plugin to see if we have internet connectivity
# http://midnightresearch.com/projects/wicrawl

use strict;
use Getopt::Std;
$Getopt::Std::STANDARD_HELP_VERSION='1';

my $bssid=0; my $encryption; my $ssid=0; my $interface=0; my $nick=0; my $version=0;
our($opt_b, $opt_e, $opt_i, $opt_s, $opt_n, $opt_v);

my $host="64.71.137.162";
my $timeout = 5;
my $tries = 3;
my $ping;

print "  ============ <Hold Internet plugin> ==============\n";
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

# check for ping
$ping=`which ping 2>/dev/null`;
chomp($ping);
if($ping eq "" ) {
	print "  [!] Can't find ping in path... exiting...\n";
	exit 1;
}

print "  [*] Attempting internet check to host [$host] through [$interface]\n";

my $atries=1;

while( $atries <= $tries ) {
	my $rc=system($ping, "-q", "-c", "4", "-I", $interface, $host); 
	$rc=$rc >> 8;
	$atries++;

	if($rc==0) {
		print " [*] Internet Check passed, holding connection to internet open\n";
		$have_internet=1;

		# reset tries count
		$atries=1;

		# sleep for a bit
		sleep 8;
	} else {
		print " [*] Internet Check failed, will try again [$atries] of [$tries] tries\n";
		sleep 2;
	}
}


print "  [!] Internet hold check failed, exiting now...\n";
print "  =========== <Hold Internet plugin > ==============\n";

exit 0;
# vim:ts=2:sw=2:sts=0
