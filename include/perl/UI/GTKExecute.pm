package UI::GTKExecute;

use POSIX ":sys_wait_h";

# Set basedir here so we can set the lib path dynamically.
my $basedir="/usr/local/wicrawl/";

my $wicrawl = "$basedir/plugins/plugin-engine";

# used to open a pipe to a command to the plugin engine
my $fh;
my $pid;

# timer used for periodic checks of APs and Plugins
my $timer;

#######################################################################
#function start
#	Arguments: None
#		Returns: None
####################
sub start {
	shift;
	my $args_pt = UI::Common->generate_command;
	my @args = @$args_pt;
	if(@args) {
		UI::GTKOutput->lprint(1,3, "Wicrawl execution command line: @args\n");

		# Get output from wicrawl
		$pid=open($fh, "-|", "@args") or UI::GTKOutput->lprint(0,3,"\nCouldn't open wicrawl pipe\n");

		# set the process group id so we can kill all children
		setpgrp($pid, $pid);

		# add watcher for plugin-engine output
		$helper_tag = Gtk2::Helper->add_watch(fileno $fh, 'in', sub {
			&watch_callback($fh);
		});

		# periodically refresh discovered APs
		$timer = Glib::Timeout->add(3000,sub{
			UI::GTKWarbar->show_data;
			UI::GTKBasic->show_data;
			UI::GTKAdvanced->show_data;
			UI::GTKOutput->show_data;
			return TRUE;
		});		
	}
}

#######################################################################
#function watch_callback
#	Arguments: None
#		Returns: None
####################
sub watch_callback {
	my ($fh) = @_;
	my $line;
	# read 1000 characters of the buffer		

	$fh->sysread($line, 500);

	if($fh->error) {
		UI::GTKOutput->lprint(2,0,"FileHandler had problems");
	}

	if($line) {
		UI::GTKOutput->lprint(0,2,"$line");
	}

	else {
		# the connected pipe was closed
		UI::GTKOutput->lprint(0,1,"Wicrawl is finished\n");
		Gtk2::Helper->remove_watch($helper_tag) or UI::GTKOutput->lprint(2,0,"\nCouldn't Remove Watch Callback\n");

		UI::GTKOutput->lprint(0,3, "Killing child [$pid]\n");
		kill(2, $pid);
		my $kid=waitpid($pid, WNOHANG);
		if($kid <= 0) {
			waitpid($pid, 0);
		}
		UI::GTKOutput->lprint(0,3, "Child [$pid] dead\n");
		UI::GTKOutput->lprint(1,1, "Discovery and plugin-engine finished\n");

		close($fh);
	}

	# Return TRUE so we can loop again
	return TRUE;
}

#######################################################################
#function stop
#	Arguments: None
#	Returns: None
####################
sub stop {
	UI::GTKOutput->lprint(0,1,"Stopping...\n");

	# Remove periodic checks for updated APs
	# Note: callback returning FALSE does not seem
	# to properly stop execution so I used 
	# Glib::Source->remove as a workaround
	if(defined $timer) { Glib::Source->remove($timer); }

	# Remove plugin-output watcher
	if(defined $helper_tag) { Gtk2::Helper->remove_watch($helper_tag); }

	# Kill plugin-engine and close filehandle
	if($pid) {
		kill(2, $pid);
		my $kid=waitpid($pid, WNOHANG);
		if($kid <= 0) {
			waitpid($pid, 0);
		}
	
		UI::GTKOutput->lprint(0,3, "Child [$pid] dead\n");
		UI::GTKOutput->lprint(1,1, "Discovery and plugin-engine finished\n");
	
		close($fh);
	}
}

1;
