#!/usr/bin/perl  -w
#
# This is a dhcp plugin for wicrawl
# http://midnightresearch.com/projects/wicrawl
#
# TODO TODO
# This plugin relies on just one type of dhcp client. This will need to be fixed
# after a more reasonable alternative will be found
#
# DHCP Clients we need to support:
# [+] dhclient
# [+] pump
# [-] dhcpcd
# [+] dhcpcd-bin
# [-] dhcdbd
# [+] dhcp3-client
# 
#

use strict;
use Getopt::Std;
use File::Basename;
$Getopt::Std::STANDARD_HELP_VERSION='1';

my $bssid=0; my $encryption; my $ssid=0; my $interface=0; my $nick=0; my $version=0;
our($opt_b, $opt_e, $opt_i, $opt_s, $opt_n, $opt_v);

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

print "  =========== <dhcp plugin > ==============\n";

$bssid =     $opt_b if(defined $opt_b);
$encryption =$opt_e if(defined $opt_e);
$ssid =      $opt_s if(defined $opt_s);
$interface = $opt_i if(defined $opt_i);
$nick =      $opt_n if(defined $opt_n);
$version =   $opt_v if(defined $opt_v);


my $rc = 0;
my $ip;
my $dhcp;
my $timeout = 30;

my ($basedir, undef) = split(/\/\//, dirname $0);

print "  [*] Running DHCP...\n";
# check whether dhcp client exists
if(-e "$basedir/util/dhcp/dhclient") {	
	$dhcp = `$basedir/util/dhcp/dhclient $interface 2>&1`;
		if($dhcp =~ /(bound to )(\d+\.\d+\.\d+\.\d+)/) {
			print "  [*] Your ip is: $2 on interface: $interface\n";
			$rc = 1;
		}
}
else {
	print "  [!] Can't find any dhcp clients in path... exiting...\n";
}

my $lastmsg="  =========== </dhcp plugin > ==============\n";
if($rc==1) {
	print "  [*] DHCP worked!...\n";
	print $lastmsg;
	exit 9;
} else {
	print "  [!] DHCP failed...\n";
	print $lastmsg;
	exit 1;
}

exit 0;
# vim:ts=2:sw=2:sts=0
