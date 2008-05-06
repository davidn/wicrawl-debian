#!/usr/bin/perl -w
#
# This is a plugin to see if we have internet connectivity
# http://midnightresearch.com/projects/wicrawl

use strict;
use Getopt::Std;
$Getopt::Std::STANDARD_HELP_VERSION='1';

my $bssid=0; my $encryption; my $ssid=0; my $interface=0; my $nick=0; my $version=0;
our($opt_b, $opt_e, $opt_i, $opt_s, $opt_n, $opt_v);

my $lastmsg="  =========== <internet check plugin > ==============\n";
my $check_page="http://64.71.137.162/wicrawl.php";
my $host="64.71.137.162";
my $hostbin;
my $timeout = 5;
my $tries = 3;
my $wget;
my $ping;

# This will hold whether we are successful or not:
# 0: Not successful
# 1: Successful
# 2: Partiall successful
my $success=0;

print "  ============ <internet check plugin> ==============\n";
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

$bssid =      $opt_b if(defined $opt_b);
$encryption = $opt_e if(defined $opt_e);
$ssid =       $opt_s if(defined $opt_s);
$interface =  $opt_i if(defined $opt_i);
$nick =       $opt_n if(defined $opt_n);
$version =    $opt_v if(defined $opt_v);


################################################################################
#  Start functions
################################################################################
sub http_check() {
	
	print "  [*] Attempting HTTP external check to [$host]\n";

	my $page=`$wget --quiet -T $timeout --tries=$tries -O - $check_page`;
	my $rc=$? >> 8;

	if ($rc != 0) {
		print "  [!] HTTP Check failed.\n";
		return 1;

	} else {

		if($page !~ m/Courtesy of Midnight Research Labs/) {
			print "  [*] It looks like the page we requested is not the page we expected\n";
			print "      There is probably a captive proxy page in the way...\n";
			return 1;
		}

		print "  [*] HTTP Check successful!\n";

		return 0;
	}
}
################################################################################
#  function icmp_check
################################################################################
sub icmp_check() {
	print "  [*] Attempting ICMP check to host [$host] through [$interface]\n";

	my $return=system($ping, "-q", "-c", "4", "-I", $interface, $host); 
	$return=$return >> 8;

	if($return!=0) {
		print "  [!] ICMP Check Failed!\n";
	} else {
		print "  [*] ICMP Check Successful\n";
	}

	return $return;
}
################################################################################
#  function dns_check
################################################################################
sub dns_check() {
	# 
	# DNS check uses a text record so we can make sure that it's not the
	# captive proxy server that's returning for everything
	#
	print "  [*] Attempting DNS TXT check to host [$host] \n";

	my $dns=`$hostbin -t TXT midnightresearch.com | grep TXT `;

	if($dns =~ m/Midnight Research Labs/) {
		print "  [!] DNS Check Successful!\n";
		return 0;
	} else {
		print "  [!] DNS Check Failed!\n";
		return 1;
	}
}
################################################################################
#  End functions
################################################################################

# check for ping
$ping=`which ping 2>/dev/null`;
chomp($ping) if(defined($ping));
if((!defined($ping)) || ($ping eq "" )) {
	print "  [!] Can't find ping in path... exiting...\n";
	print $lastmsg;
	exit 1;
}

# check for host
$hostbin=`which host 2>/dev/null`;
chomp($hostbin) if(defined($hostbin));
if((!defined($hostbin)) || ($hostbin eq "" )) {
	print "  [!] Can't find 'host' in path... exiting...\n";
	print $lastmsg;
	exit 1;
}

# check for wget
$wget=`which wget 2>/dev/null`;
chomp($wget) if(defined($wget));
if((!defined($wget)) || ($wget eq "" )) {
	print "  [!] Can't find wget in path... exiting...\n";
	print $lastmsg;
	exit 1;
}

################################################################################
#  End setup
################################################################################

# Start ICMP check
my $rc=icmp_check();
$success=1 if($rc==0);

# Start HTTP Check
$rc=http_check();

# Set the success level
if(($success==1) && ($rc!=0)) {
	# partial success
	$success=2;
} elsif (($success==0) && ($rc==0)) {
	# More partial success
	$success=2;
} 

# Start DNS Check
$rc=dns_check();

# Set the success level
if(($success==1) && ($rc!=0)) {
	# partial success
	$success=2;
} elsif (($success==0) && ($rc==0)) {
	# More partial success
	$success=2;
} 


if($success==1) {
	print "  [*] Internet check for ICMP/DNS/HTTP worked!...\n";

	print $lastmsg;

	# return 10 to increase the event level
	exit 10;

} elsif ($success==2) {
	print "  [*] Internet check for ICMP/DNS/HTP partiall succeeded...\n";
	print "      This means that not all methods worked, but you should be able\n";
	print "      to get out to the internet\n";

	print $lastmsg;
	# return 10 to increase the event level
	exit 10;

} else {
	print "  [!] Internet check for ICMP/DNS/HTTP failed!!\n";

	print $lastmsg;
	exit 1;
}
	

exit 0;
# vim:ts=2:sw=2:sts=0
