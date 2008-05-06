#!/usr/bin/perl -w
#
# This plugin will try to get AP's external IP address. 
# It should work for WEP encrypted (easside-ng) and 
# unencrypted APs (norsside-ng)

use strict;
use Getopt::Std;
use File::Basename;
$Getopt::Std::STANDARD_HELP_VERSION='1';

my $bssid=0; my $encryption=""; my $ssid=0; my $interface=0; my $nick=0; my $version=0; my $run=0;
our($opt_b, $opt_e, $opt_i, $opt_s, $opt_n, $opt_r, $opt_v);
getopts ("b:e:i:n:r:s:v:");

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

my $external_ip = "0.0.0.0";

my $buddy_ip = "192.168.1.100";
my $channel = 6;

if(defined($ENV{'WICRAWL_CHANNEL'})) {
	$channel=$ENV{'WICRAWL_CHANNEL'};
}
if(defined($ENV{'buddy_ip'})) {
	$buddy_ip = $ENV{'buddy_ip'};
}

my $basedir=dirname($0);
my $aircrackdir=$basedir . "/aircrack-ng-1.0";
my $airmon=$aircrackdir . "/airmon-ng";

my $easside=$aircrackdir . "/src/easside-ng";
my $norside=$basedir."/norside/norside";

my $default_program = $norside;

# Add execute privs if we don't have it already
if(( -e $airmon ) && ( ! -x $airmon )) {
	chmod "0755", $airmon;
}


print "  ============ <get external ip plugin > ==============\n";


# REMOVE OLD PRGA.LOG EVERY RUN!!!!

if( ( ! -x $airmon) || ( ! -x $easside) ) {
	print " [!!] An aircrack file is missing or not executable, looking for:\n";
	print "\t[$airmon]\n";
	print "\t[$easside]\n";
	print " Exiting now..\n";
	exit 1;
}

# Set in monitor mode:
print "  * Puting interface [$interface] in monitor mode\n";

# madwifi-ng is trouble so we will use custom command and rely
# on airmon script for everything else
if($interface =~ /ath/) {
	`$airmon stop $interface 2>/dev/null`;
	`$airmon start wifi0 2>/dev/null`;
} else {
	`$airmon start $interface 2>/dev/null`;
}

my $rc=$? >> 8;

if($rc != 0) {
	lprint(2, 0, "Monitor mode enabling failed for aircrack plugin\n\t(warn: $!)\n");
	exit 1;
}

if( ! -x $norside) {
	print " [!!] Norside file is missing or not executable, looking for:\n";
	print "\t[$norside]\n";
	exit 1;
}

# Check to see if network is encrypted and adjust executable
# easside - for encrypted networks
# norside - for unencrypted networks
if($encryption eq "WEP") {
	print "  * Running easside...\n";
	if( -e "prga.log") { unlink("prga.log") }
	if( -e "own.log" ) { unlink("own.log" ) }
	# still requires tunnel interface
	`modprobe tun`;
	open EXE, "$easside -n -v $bssid -f $interface -s $buddy_ip |" or die "Couldn't execute $easside";
} else {
	print "  * Running norside...\n";
	if( -f "$basedir/norside/scapy.pyc") { unlink("$basedir/norside/scapy.pyc") }
	open EXE, "$norside -v $bssid -f $interface -s $buddy_ip 2>/dev/null|" or die "Couldn't execute $norside";
}

# Output is the same for both easside and norside
while(<EXE>) {
	if(/Internet w0rx.  Public IP (.*)/) {
		$external_ip = $1;
		last;
	}
}
close(EXE);

if($external_ip ne "0.0.0.0") {
	print "  * External IP:[$external_ip]\n";
} else {
	print "  * Couldn't get external IP\n";
}

print "  =========== </get external ip plugin > ==============\n";

exit 0;

# vim:ts=2:sw=2:sts=0
