#!/usr/bin/perl -w
#
# this generates a list of APs to a given fifo for testing 

use lib "/usr/local/wicrawl/include/perl";

use strict;
use AccessPoint;

if(@ARGV != 2) {
	print "usage: $0 <num_of_APs_to_create> <ipc fifo>\n";
	exit 1;
}

my $ap_num=$ARGV[0];
my $ipc=$ARGV[1];

print " [*] Creating [$ap_num] APs, and sending them to [$ipc]\n";

for my $i (1 .. $ap_num) {
	my $ap=AccessPoint->new();

	$ap->ssid("testAP_$i");
	$ap->bssid("de:ad:be:ef:00:" . $i % 100);
	$ap->packets($i);
	$ap->encryption("None");
	$ap->power($i);
	$ap->channel($i % 12);

	my $return=$ap->to_ipc($ipc);
	if($return==0) {
		print " [!] IPC message failed...\n";
	}
}

exit 0;
