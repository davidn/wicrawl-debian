#!/usr/bin/perl -w
#
# nmap plugin script for wicrawl
# http://midnightresearch.com/projects/wicrawl

use strict;
use Getopt::Std;
use XML::Smart;
$Getopt::Std::STANDARD_HELP_VERSION='1';

my $bssid=0; my $encryption=0; my $ssid=0; my $interface=0; my $nick=0; my $version=0;
our($opt_b, $opt_e, $opt_i, $opt_s, $opt_n, $opt_v);
my $rc;
my $nmap;

my $ip;
my $counter=0;
my $time = time;

my $targets="network";
my $scan_type="-sS";
my $extra_options="";

# Get the config passed into the env from the config file
if(defined($ENV{'nmap_scan_targets'})) {
	$targets=$ENV{'nmap_scan_targets'};
}
if(defined($ENV{'nmap_scan_type'})) {
	$scan_type=$ENV{'nmap_scan_type'};
}
if(defined($ENV{'nmap_extra_options'})) {
	$extra_options=$ENV{'nmap_extra_options'};
}

# TODO, remove bad assumption of /24 for network
if($targets ne "gateway") {
	$targets="24";
} else {
	$targets="32";
}

#####################################################################
# functions
sub get_ip() {
	my $ip = `ifconfig $interface | grep "inet addr"`;
	$ip =~ /(inet addr:)(\d+\.\d+\.\d+\.\d+)/;
	if($2) {print "  [*] Your IP is: $2\n";}
	return $2;
}

sub nmap_exec() {

	print "  [*] Scanning Local Network on [$ip/$targets]\n";

	# TODO figure out why '-e $interface' isn't working, and add it back in
	#my $system="$nmap -e $interface $scan_type $extra_options $ip/$targets";
	my $system="$nmap $scan_type $extra_options $ip/$targets";
	print "  [*] Executing [$system]\n";

	# Do this so we can get unbuffered input
	open(NMAP, "$system |") || die "  [!] Can't start nmap [$system]\n";
	while(readline(NMAP)) {
		print "  [-] $_";
	}

	close(NMAP);
	return 0;
}

# /end functions
#####################################################################

print "  ============ <nmap plugin> ==============\n";

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

# TODO: get lan ip from the plugin-engine
$ip = &get_ip;

if($ip) {
	# verify we can find nmap
	$nmap=`which nmap 2>/dev/null`;
	chomp($nmap);
	if($nmap eq "" ) {
		print "  [!] Can't find nmap in path... exiting...\n";
		exit 1;
	}

	nmap_exec();
} else {
	print " [!] Can't find local IP address... exiting..\n";
}


print "\n  [*] Finished nmap on [$ip/$targets]\n";
print "  =========== </nmap plugin > ==============\n";

exit 0;
