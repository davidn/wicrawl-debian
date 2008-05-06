#!/usr/bin/perl -w
#
# This plugin checks our external ip address
# http://midnightresearch.com/projects/wicrawl

# TODO This plugin still needs to be interface specific

use strict;
use Getopt::Std;
$Getopt::Std::STANDARD_HELP_VERSION='1';

my $bssid=0; my $encryption; my $ssid=0; my $interface=0; my $nick=0; my $version=0;
our($opt_b, $opt_e, $opt_i, $opt_s, $opt_n, $opt_v);

# midnightresearch.com
my $check_page="http://64.71.137.162/wicrawl.php";
my $timeout = 5;
my $tries = 3;

my $wget;
my $time = time;

#####################################################################
# functions
sub get_ext_ip() {
	
	my $page=`$wget --quiet -T $timeout --tries=$tries -O - $check_page`;
	my $rc=$? >> 8;

	if ($rc != 0) {
		print "  [!] wget failed.\n";
		return 0;
	} else {
		print $page;
		return 1;
	}
}

# /end functions

print "  ============ <external ip check plugin> ==============\n";
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


# verify we can find wget
$wget=`which wget `;
chomp($wget);
if($wget eq "") {
    print "  [!] Can't find wget in path.  Exiting.\n";
    exit 1;
}

$check_page.="?version=$version";
print "  [*] Attempting external ip check\n";
my $rc = &get_ext_ip();

my $lastmsg="  =========== <external ip check plugin > ==============\n";
if($rc==1) {
	print "  [*] Got our external IP!...\n";
	print $lastmsg;
	exit 0;
} else {
	print "  [!] Failed to get our external IP...\n";
	print $lastmsg;
	exit 1;
}

exit 0;

# vim:ts=2:sw=2:sts=0
