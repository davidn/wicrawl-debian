#!/usr/bin/perl -w
#
# This is a template plugin script for wicrawl
# http://midnightresearch.com/projects/wicrawl

use strict;
use Getopt::Std;
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

# This comes from the plugin config
# It is a way to configure plugins from the plugin.config
# rather than from the plugins themselves...
my $envvar=$ENV{'my_example_val'};

print "  ============ <example perl plugin > ==============\n";
print "  * Hi, I'm a plugin.  Here is what I know so far:\n";
print "  * The SSID of the AP I want is:     [$ssid]\n";
print "  * The BSSID of the AP I want is:    [$bssid]\n";
print "  * The nick I'll use to associate is:[$nick]\n";
print "  * The interface I should use is:    [$interface]\n";
print "  * The encryption type is:           [$encryption]\n";
print "  * The of wicrawl that called me is: [$version]\n";
print "  * The of plugin-engine run number:  [$run]\n";
print "  * The env config var in plugin.conf:[$envvar]\n";
print "  * I'll sleep for a second for you to absorb all that....\n";
sleep 2;
print "  * OK, See ya...\n";
print "  =========== </example perl plugin > ==============\n";

exit 0;

# vim:ts=2:sw=2:sts=0
