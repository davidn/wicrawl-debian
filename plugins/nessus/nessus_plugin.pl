#!/usr/bin/perl -w
#
# Nessus plugin script for wicrawl
# http://midnightresearch.com/projects/wicrawl
#
# Written by: Aaron Peterson
#   (skeleton from the nessus plugin)
#
# Nessus: nessus.org
#
# Requires nessus already installed and configured
# Also needs to have the username and password configured in the plugin.conf

use strict;
use Getopt::Std;
use XML::Smart;
$Getopt::Std::STANDARD_HELP_VERSION='1';

my $bssid=0; my $encryption=0; my $ssid=0; my $interface=0; my $nick=0; my $version=0;
our($opt_b, $opt_e, $opt_i, $opt_s, $opt_n, $opt_v);
my $rc;

my $ip;
my $counter=0;
my $time = time;
my $output =`umask 077 && mktemp -q "/tmp/nessus.XXXXXX" 2>/dev/null`;
my $targets =`umask 077 && mktemp -q "/tmp/nessus_target.XXXXXX" 2>/dev/null`;
chomp($targets);
chomp($output);
my $nessus_user;
my $nessus_pass;
my $nessus;

#####################################################################
# functions
sub get_ip() {
	my $ip = `route -n | grep "^0.0.0.0"`;
	$ip =~ /^(\d+\.\d+\.\d+\.\d+)\s*(\d+\.\d+\.\d+\.\d+)/;
	return $2;
}
#####################################################################

print "  ============ <nessus plugin> ==============\n";

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

$ip = &get_ip;
if($ip) {print "Gateway IP is: $ip\n";}

# verify we can find nessus
if( -x "/opt/nessus/bin/nessus" ) {
    $nessus="/opt/nessus/bin/nessus";
} else {
    $nessus=`which nessus 2>/dev/null`;
    chomp($nessus);
    if($nessus eq "" ) {
	print "  [!] Can't find nessus in path... exiting...\n";
	exit 1;
    } 
}

if(defined($ENV{"nessus_user"})) { 
    $nessus_user=$ENV{"nessus_user"};
} 

if(defined($ENV{"nessus_pass"})) { 
    $nessus_pass=$ENV{"nessus_pass"};
} 

if((!defined($nessus_user)) || (!defined($nessus_pass))) {
    print "  [!] Can't find nessus user or password, did you configure the nessus plugin.conf?\n";
    exit 1;
}

if($ip) {
    open(TARGET, ">>$targets") || die "Can't open [$targets]\n\t$!\n";
    print TARGET "$ip\n";
    close(TARGET) || die "Can't close [$targets]\n\t$!\n";

    my $system="$nessus -q -T txt localhost 1241 $nessus_user $nessus_pass $targets $output";
    my $runout=`$system`;
    $rc=$? >> 8;

    print "  [*] Nessus non-report output is:\n\t[$runout]\n";

} else {
	print " [!] Can't find local IP address... exiting..\n";
	$rc = 0;
}

unlink($targets);

my $lastmsg="  =========== </nessus plugin > ==============\n";
if($rc==0) {
	print "  [*] Completed nessus scan:...\n";
	print "  [*] Nessus report is:\n";
	open(OUT, $output) || die "Can't open [$output]\n\t$!\n";

	foreach(<OUT>) {
	    print;
	}

	close(OUT) || die "Can't close [$output]\n\t$!\n";
	#unlink($output);

	print $lastmsg;
	exit 8;
} else {
	print "  [!] failed to perform scan on [$ssid]...\n";
	print $lastmsg;

	#unlink($output);
	exit 1;
}


exit 0;
