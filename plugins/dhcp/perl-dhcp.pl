#!/usr/bin/perl
# DHCP Client for Net::DHCP::Session

use Sys::Hostname;
use Socket;
use Net::DHCP::Session;
use Getopt::Long;
use strict;

#################################################################################
# usage()                                                                       #
#                                                                               #
#################################################################################
sub usage {
	"Usage: dhc.pl -d <IP DHCP server> [-l <local IP addr>] [-m <mac>] [-h hostname] [-i]\n" .
	" -d <IP DHCP server> = IP adress of DHCP server to use.\n".
	" -l <local IP addr> = If your local host has several addresses, \n" .
	"		specify the address to use. Optional.\n".
	" -m <mac> = Client MAC address for DHCP requests. Format : ex. 00065B011AAA.\n" .
	" -h <host> = hostname (DHCP Option 12)" .
	" -i = interactive mode\n";
}

my $DHCPserver = undef;
my $localaddr =undef;
my $interactive = undef;
my $mac = undef;
my $hostname = 'dhcFake';

GetOptions (
'dhcpserver=s' => \$DHCPserver,
'localaddr=s' => \$localaddr,
'mac=s' => \$mac,
'hostname=s' => \$hostname,
'interactive' => \$interactive
) || die usage();

$DHCPserver || die usage();
$mac = Net::DHCP::Session::genMAC() unless defined ($mac);
$localaddr = inet_ntoa ( scalar ( gethostbyname(hostname()) ) ) unless defined ($localaddr);

print "using mac $mac...\n";
print "using localaddr $localaddr...\n";

my $dhc = new Net::DHCP::Session(Hostname => $hostname, 
		Localaddr => $localaddr, 
		Server_ip => $DHCPserver,
		Chaddr => $mac);

print "Doing Discovery...\n";

$dhc->discover();
$dhc->await_offer();
$dhc->request();
$dhc->await_ack();

print $dhc->dumpoptions();


