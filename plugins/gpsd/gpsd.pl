#!/usr/bin/perl -w
#
# This is the GPSD hook for wicrawl - !!UNTESTED!!
#
# It sends a formated update message to IPC for wicrawl, which will update the
# longitude and latitude meta-tags in the XML.  Requires Net::GPSD
#
# In order to be "enabled", this file must be set executable
#
# http://midnightresearch.com/projects/wicrawl

use strict;
use Getopt::Std;
use MIME::Base64;
use Net::GPSD;
# /usr/local/share/perl/5.8.7/Net/GPSD.pm
# /usr/local/share/perl/5.8.7/Net/GPSD/Point.pm
# /usr/local/share/perl/5.8.7/Net/GPSD/Satellite.pm
# /usr/local/share/perl/5.8.7/Net/GPSD/Report/http.pm

$Getopt::Std::STANDARD_HELP_VERSION='1';

# Hard-coding for now until we have a global config
my $ipc="/var/log/wicrawl/ipc";

my $bssid=0; my $encryption=""; my $ssid=0; my $nick=0; my $version=0;
our($opt_b, $opt_e, $opt_i, $opt_s, $opt_n, $opt_v);
getopts ("b:e:i:n:r:s:v:");

if(    (!defined $opt_b) || (!defined $opt_e)
    || (!defined $opt_n) || (!defined $opt_s)
    || (!defined $opt_v)) {
  print "  [!] usage $0 <options>\n";
  print "\t-b <bssid>\n";
  print "\t-e <encryption type>\n";
  print "\t-n <nickname>\n";
  print "\t-s <ssid>\n";
  print "\t-v <version>\n";
	exit 1;
}

$bssid =      $opt_b if(defined $opt_b);
$encryption = $opt_e if(defined $opt_e);
$ssid =       $opt_s if(defined $opt_s);
$nick =       $opt_n if(defined $opt_n);
$version =    $opt_v if(defined $opt_v);

my $gps=new Net::GPSD;
my $point=$gps->get;

if ($point->fix) {
	my $lat=$point->lat;
	my $long=$point->lon;

	print "  [*] Found GPS coodinates: [$lat], [$long] \n";
	
	my $update="update|bssid:";

	# convert it into the value that the ipc handler is expecting
	$bssid=~s/://g;
	$bssid=pack("H12", $bssid);
	$bssid=encode_base64($bssid);
	chomp($bssid);

	$update .= $bssid;
	
	$lat=encode_base64($lat);
	$long=encode_base64($long);
	chomp($lat);
	chomp($long); 

	$update .= "|latitude:" . $lat;
	$update .= "|longitude:" . $long . "\n";

	open(IPC, ">$ipc") || die " [!!] Can't open IPC [$ipc]\n\t$!\n";
	print IPC $update;
	close(IPC) || die " [!!] Can't close IPC [$ipc]\n\t$!\n";

} else {
	print "  [!] No Satellite fix, or can't find GPSD\n";
	exit 1;
}

exit 0;

# vim:ts=2:sw=2:sts=0
