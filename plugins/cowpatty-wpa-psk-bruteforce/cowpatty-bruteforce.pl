#!/usr/bin/perl -w
#
# This is a plugin that will bruteforce wpa pre-shared keys based on a
# dictionary attack.  It uses cowpatty, and requires that john the ripper is
# already installed.
#
# http://midnightresearch.com/projects/wicrawl
#
# Plugin Written by: Aaron Peterson 
# CoWPAtty Written by: Josh Wright
# CoWPAtty with FPGA support by h1kari
# 
# CoWPAtty available here: http://www.churchofwifi.org/default.asp?PageLink=Project_Display.asp?PID=95
#
# Check into cowpatty with FPGA support at the openciphers project:
# http://openciphers.sf.net
#
# For good FPGA's check out picocomputing.com
#
# Thanks to Josh Wright and h1kari for doing all the hard work, :)
#

$|=1;
use strict;
use Getopt::Std;
use File::Basename;
use POSIX ":sys_wait_h";
use Fcntl;
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


my $basedir=dirname($0);
my $channel;
my $cowpatty=$basedir . "/cowpatty/cowpatty";
my $cowpatty_fpga=$basedir . "/cowpatty-fpga/cowpatty";
my $cowpatty_opts="";
my $debug=0;
# Note, for now we only support one fpga card...
my $fpga_checkfile="/dev/pico0c";
my $handshake_wait=10;
my $pcapfile=$ENV{'WICRAWL_PCAPFILE'};
my $runtime=time;
my $tcpdumpout=`umask 077 && mktemp -q "/tmp/cowpatty-tcpdump.XXXXXX" 2>/dev/null`;
my $use_fpga=0;
my $try_existing_pcap=1;
my %pids=( "tcpdump" => 0 );
my $john;
my $tcpdump;
chomp($tcpdumpout);

#######################################################################
#
#  Start functions...
#
#######################################################################
# function cleanup - run to cleanup on sigint, etc
####################
sub cleanup() {
	my $msg = shift(@_);

	if((defined($msg)) && ($msg eq "INT")) {
		print("  [*] Process [$$] received interrupt, cleaning up\n");
	} else {
		print("  [*] Process [$$] was told to clean up\n");
	}

  wait_children(1);
  #unlink($tcpdumpout);
  print("  [*] CoWPAtty wicrawl plugin done.\n");
  exit 0;

}
#######################################################################
# function wait_children - cleans up after the kids.
#   Arugments:  0 to cleanup children (but not blocking wait), 
#               1 to kill children, and make sure their gone.
#   Returns: 0
#####################
sub wait_children {
  my $iskill=shift(@_);

	if($iskill eq "CHLD") {
		print "  [*] Received SIGCHLD, checking the forked children\n";
		$iskill=0;
	}

	if(!defined($iskill)) {
		$iskill=0;
	}

  my $kid; my $pid;

  foreach my $key (keys %pids) {
    $pid=$pids{$key};

    # no child
    next if ($pid <= 0);

    if($iskill!=1) {

			# Don't block
      $kid=waitpid($pid, WNOHANG);

			if($kid > 0 ) {
				print "  [*] Child [$key] pid [$pid] finished. (wait returned [$kid])\n";
				$pids{"$key"}=0;
			}
    } else {
      print "  [*] Killing child [$key] pid [$pid]\n";
      kill_pid($pid);
			$pids{$key}=0;
    }

  }

  return 0;
}
#######################################################################
# function kill_pid - kill the given pid.
#   Arguments:  pid
####################
sub kill_pid {
  my $child=shift(@_);

  my $have_child=1;
  my $count=0;

	# this is what the pgroup is set to
	$child="-" . $child;
  while($have_child) {
    my $kid=waitpid($child, WNOHANG);
    last if($kid > 0);

    kill(2, $child);
    sleep 1;
		$count++;
		if($count>=3) {
			print("  [!] Child [$child] not dying, killing with force..\n");
			kill(9, $child);
			last;
		}
  }

	print("  [*] Child [$child] was killed\n");

  return 0;
}
#######################################################################
# start_tcpdump() function
#######################################################################
sub start_tcpdump() {

	my $pid;
	if(($pid=fork) > 0) {
		# is parent -- We'll fork and (almost) forget this one

		print "  [*] Spawned tcpdump'ing process [$pid] from parent [$$]\n";
		$pids{"tcpdump"}=$pid;

	} elsif($pid==0) {
		# is child

		setpgrp($$, $$) || die " [!!] Can't set process group for [$$]\n";

		my $system=$tcpdump . " -nnn -s0 -w $tcpdumpout -i $interface 2>/dev/null";

		print "  [*] Starting tcpdump [$system]\n";
		# Start this off, and as long as it doesn't fail, we're good
		# and don't need the output.
		`$system`;

		my $rc= $? >> 8;
		if($rc != 0) {
			print "  [!] It appears that tcpdump failed... we probably won't get a handshake...\n";
			exit 1;
		}

		$SIG{'TERM'}='DEFAULT';


		exit 0;

	} else {
		print "  [!] tcpdump fork failed..\n";
		return 1;
	} 

	while(! -f $tcpdumpout) {
		print "  [-] tcpdump outputfile isn't there yet... waiting until it's written to continue\n";
		sleep 4;
	}

	return 0;

}
#######################################################################
#
# End functions
# 
#######################################################################

$SIG{'INT'}= \&cleanup;

 
$john=`which john 2>/dev/null`;
chomp($john);
if($john eq "") {
    print " [!!] Can't find john (from john the ripper) in the path\n";
		print "      please install it and try again.\n";
    exit 1;
}
$john="$john -incremental -stdout";

$tcpdump=`which tcpdump 2>/dev/null`;
chomp($tcpdump);
if($tcpdump eq "") {
    print " [!!] Can't find tcpdump in the path, please install and try again\n";
    exit 1;
}

print "  [*] CoWPAtty WPA-PSK Dictionary Brute force Wicrawl plugin\n";

# Get the channel from the environment
if(defined($ENV{'WICRAWL_CHANNEL'})) {
	$channel=$ENV{'WICRAWL_CHANNEL'};

	print "  [*] Setting channel to [$channel]\n";
	`iwconfig $interface channel $channel 2>/dev/null`;
}

print "  [*] Putting into monitor mode\n";
`iwconfig $interface mode monitor 2>/dev/null`;

if(-e $fpga_checkfile) {
	$use_fpga=1;
	$cowpatty=$cowpatty_fpga;

	# For now we only support one FPGA card
	# TODO: Support more, :)
	$cowpatty_opts="-F 0";
	print "  [*] Found Pico FPGA, will use it for CoWPAtty acceleration\n";
}

# Check for cowpatty
if(($cowpatty eq "") || (! -x $cowpatty)) {
	print "  [!] CoWPAtty binary [$cowpatty] wasn't found or isn't executable\n";
	print "  [!] Did you compile wicrawl?  Exiting now..\n";
	exit 1;
}

# We get the pcap file from the environment (plugin-engine), need to
# make sure it's set and exists
if((!defined($pcapfile)) || ($pcapfile eq "") || (! -f$pcapfile)) {
	print "  [!] It doesn't appear that the pcapfile is set, or does not exist\n";
	print "      Are you running this from the plugin-engine? or have\n";
	print "      an old version? (we're expecting WICRAWL_PCAPFILE set in the env)\n\n";
	print "      We'll continue with running with tcpdump instead..\n";
	$try_existing_pcap=0;
}

# Set it up with everything but the pcap file...
$cowpatty="$john | $cowpatty -f - -s \"$ssid\" $cowpatty_opts -r ";

my $success=0;
my $wpapsk="";
my $system;

while($success==0) {

	# Set the pcap file depending on what scan we're in
	if($try_existing_pcap==1) {

		# This is the pcapfile passed in from wicrawl
		$system=$cowpatty . $pcapfile;

		# Setting this back to 0 since we don't need to try this again
		$try_existing_pcap=0;

	# Used for debug purposes only
	} elsif ($debug==1) {
		$system="cat $basedir/cowpatty/dict | $basedir/cowpatty-fpga/cowpatty -f - -s linksys $cowpatty_opts -r $basedir/cowpatty/wpapsk-linksys.dump";

	} else {

		# This is the pcap file we create with tcpdump
		$system=$cowpatty . $tcpdumpout;

		# If tcpdump isn't already started, we'll start it now..
		if($pids{"tcpdump"}==0) {
			my $rc=start_tcpdump();
			if($rc!=0) {
				print "  [!] Could not start tcpdump to gather WPA handshake.. exiting now..\n";
				exit 1;
			}
		}
	}
	
	print "  [*] Running [$system]\n";
	open(COWPATTY, "$system |") || die "  [!] Can't open [$system]\n";
	foreach my $output (readline(COWPATTY)) {

		chomp($output);
		next if ($output eq "");

		if($output =~ m/The PSK is "(.*)"./) {
			$wpapsk=$1;
			print "  [*] Good News Everyone! CoWPAtty says [$output]\n";
			$success=1;

		} elsif ($output =~ m/incomplete TKIP four-way exchange/) {
			print "  [!] Failed. PCAP file does not contain a TKIP four-way exchange\n";
			last;

		} elsif ($output =~ m/Empty pcap file/) {
			print "  [!] Failed. PCAP file does not contain a TKIP four-way exchange\n";
			last;

		} elsif ($output =~ m/^key no./) {
			print "  [*] We're on [$output]\n";

		} elsif ($output =~ m/passphrases tested in/) {
			print "  [*] $output\n";

		} elsif ($output =~ m/cowpatty 4.0 - WPA-PSK dictionary attack/) {
			next;

		} elsif ($output =~ m/Usage: cowpatty /) {
			last;

		} else {
			print "  [*] Received unknown message from CoWPAtty [$output]\n";
		}
	}

	close(COWPATTY);
	
	if($success!=1) {
		print "  [!] Looks like coWPAtty failed, trying again in [$handshake_wait]\n";
		sleep $handshake_wait;
	}

}

my $note="";
$note=" with Pico FPGA Acceleration." if($use_fpga==1);

$runtime=(time-$runtime) / 60;

if($success==1) {
	# pretty fireworks
	print("  ---------------------------------------------------------------------------------------\n");
	print("  !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! ***\n");
	print("  !!! Wicrawl CoWPAtty plugin successfully cracked [$ssid], PSK is [$wpapsk]\n");
	print("  !!! Runtime was [$runtime] minutes$note\n");
	print("  !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! ***\n");
	print("  ---------------------------------------------------------------------------------------\n");
	cleanup();
	exit 8;
} else {
	print("CoWPAtty failed to crack [$ssid]. Runtime was [$runtime] minutes\n");
	cleanup();
	exit 1;
}


# TODO
# Need to actually try to associate with this key now that we found it.

exit 0
# vim:ts=2:sw=2:sts=0:ai:si
