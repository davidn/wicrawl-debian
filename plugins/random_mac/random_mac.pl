#!/usr/bin/perl -w
#
# This is a random mac address plugin script for wicrawl
# http://midnightresearch.com/projects/wicrawl

use strict;
use Getopt::Std;
$Getopt::Std::STANDARD_HELP_VERSION='1';

my $bssid=0; my $encryption; my $ssid=0; my $interface=0; my $nick=0; my $version=0;
our($opt_b, $opt_e, $opt_i, $opt_s, $opt_n, $opt_v);
my $rc;
my $ifconfig;
my $newmac;

#####################################################################
# functions
sub randmac() {

	# TODO: Make Random MACs generated more realistic
	my $rand_mac = sprintf("00:0%x:%.2x:%.2x:%.2x:%.2x", rand(16), rand(256), rand(256),rand(256),rand(256));
	my $rand_mac_command = "ifconfig $interface hw ether $rand_mac";

	`$rand_mac_command`;

	$newmac=`$ifconfig $interface | grep "HWaddr " 2>/dev/null`;
	$newmac=~s/^.*HWaddr (\d.*\d)\s*$/$1/;
	chomp($newmac);
	#print "New MAC: $newmac\n";
	if($newmac =~ /$rand_mac/i) {
		return 1;
	} else {
		return 0;
	}
}

# /end functions
#####################################################################

print "  ============ <ifconfig random mac plugin> ==============\n";

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


$bssid =     $opt_b if(defined $opt_b);
$encryption =$opt_e if(defined $opt_e);
$ssid =      $opt_s if(defined $opt_s);
$interface = $opt_i if(defined $opt_i);
$nick =      $opt_n if(defined $opt_n);
$version =   $opt_v if(defined $opt_v);

# verify we can find ifconfig
$ifconfig=`which ifconfig 2>/dev/null`;
chomp($ifconfig);
if($ifconfig eq "" ) {
	print "  [!] Can't find ifconfig in path... exiting...\n";
	exit 1;
}

#generate and set random MAC address
$rc = &randmac;

my $lastmsg="  =========== </ifconfig random mac plugin > ==============\n";
if($rc==1) {
	print "  [*] mac address for $interface changed to $newmac !...\n";
	print $lastmsg;
	exit 8;
} else {
	print "  [!] failed to change mac address for $interface...\n";
	print $lastmsg;
	exit 1;
}

exit 0;
