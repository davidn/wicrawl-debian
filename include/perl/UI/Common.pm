package UI::Common;

use strict;
use XML::Smart;

use AccessPoint;

use Data::Dumper;
use MIME::Base64;

use UI::COutput;
use UI::GTKOutput;

my $basedir="/usr/local/wicrawl";

# Wicrawl variables
my $cutroot = 1;
my $guitype = 'gtk';
my $wicrawl = "$basedir/plugins/plugin-engine";

# Use external discovery interface
my $external = 0;

# Profile variables
my $profiledir="$basedir/profiles";
my $default_profile="default";
my $profileext=".conf";

# Location of plugins
my $plugins_dir = "$basedir/plugins";

# Location of databases
my $outputdir = "/var/log/wicrawl";
my $apcoredb;
my $plugincoredb;

# Use filter for ap discovery
my $filter = "";
my $filter_file = "";

# Pointer to interface hash
my $interface;

#######################################################################
#function generate_command - Generates command to start plugin-engine
#	Arguments: none
#	Returns: none
###################
sub generate_command {
	shift;
	my @args;
	lprint(0,1,"Initializing...\n");

	# scan through interfaces to find at least one
	# that could be used for the scan or for the
	# monitor mode
	my $flag = 0;
	foreach (keys %$interface) {
		if($$interface{$_} eq "1") {
			$flag = 1;
			last;
		}
	}

	# make sure at least one interface was selected
	if($flag) {
		my $int = $$interface{monitor};
		foreach my $key (sort keys %$interface) {
			if($$interface{$key} && $key ne $$interface{monitor} && $key ne 'monitor') { $int .= ",$key"; }

		}
	
		lprint(0,1,"Starting wi-crawl...\n");
	
		my $verbosity_pe = 2;
	
		my $sessionid = time;
		$apcoredb = "$outputdir/wicrawl_discovery-$sessionid.xml";
		$plugincoredb = "$outputdir/wicrawl_plugins-output-$sessionid.xml";
	
		@args=($wicrawl, "-i", $int,"-d",$outputdir,"-f", "wicrawl_discovery-$sessionid.xml","-P wicrawl_plugins-output-$sessionid.xml","-s", $sessionid, "-v", $verbosity_pe);			
	
		# Check for SSID Filter
		if($filter ne "") {
			push @args, "-F \"$filter\"";
		}
	
		# Check for SSID Filter File
		if($filter_file ne "") {
			push @args, "-I \"$filter_file\"";
		}

		# Check for Profile
		push @args, "-p ".$default_profile;

		# Check for external discovery
		if($external) {
			push @args, "-K";
		}

	} else {
		lprint(2,0,"No Interfaces were selected, please select at 
				least one interface for wicrawl to begin the scan.\n");
	}
	return \@args;
}

#######################################################################
#function get_interfaces - Checks available interfaces on the system
#	Arguments: none
#	Returns: interfaces hash
#	0 - Disabled
#	1 - Used for scanning
#	Special {monitor} entry is used to enable first available
#	interface as an ap monitor
###################
sub get_interfaces {
	#print "Finding Available Interfaces\n";
	my @args=("$basedir/discovery/apcore", "-l");
	
	my %interfaces;

	# this flag is used to set the first interface
	# as the monitor
	my $flag = 1;

	foreach( `@args`) {
		my($id, $interface_name) = /(\S+) (\S+)/;
		$interfaces{$interface_name} = 0;
		if($flag) {
			$interfaces{'monitor'} = $interface_name;
			$flag = 0;
		}
	}
		
	return %interfaces;
}

#######################################################################
#function get_profiles - Checks available profiles on the system
#	Arguments: none
#	Returns: profiles array
###################
sub get_profiles {
	#print "Getting Profiles\n";	
	my $profiles_dir = "$basedir/profiles";
	
	my @profiles;

	# push default and discovery profiles first
	push @profiles, "default", "discovery";
	
	opendir SOMEDIR, $profiles_dir or lprint(2,0,"Could not open $profiles_dir");
	while (my $profile = readdir SOMEDIR) {
		next if $profile =~ /^\./;	# skip over dot files
		if($profile =~ /.*\.conf/) {
			$profile =~ s/\.conf//;
			if($profile ne "default" && $profile ne "custom" && $profile ne "discovery") { push @profiles, $profile; }
		}
	}

	# push custom profile last
	push @profiles, "custom";
	
	return @profiles;
}

#######################################################################
# function get_ap - Get the APs to use
#		Arguments: none
#		Returns @ap (@array of AccessPoints.pm)
#
###########################
sub get_ap {
	my(@wireless, @APS);
	my $XML; 
	my $count=0;

	$XML = XML::Smart->new($apcoredb);
	if($cutroot) {
		$XML = $XML->cut_root;
	}
	@wireless = @{$XML->{"wireless-network"}};
	foreach(@wireless) {

		# Don't want to get APs with no ssid for now
		next if((!defined($_->{SSID})) || ($_->{SSID} eq ""));
		
		my $ap=AccessPoint->new();
		$ap->ssid	($_->{SSID});
		$ap->bssid	($_->{BSSID}); 
		$ap->time	(0); # TODO get from meta-tags
		$ap->packets	(0); # TODO get from meta-tags
		$ap->plugin	($_->{plugin});
		$ap->event	($_->{event}); 
		$ap->timestamp	($_->{timestamp}); 
		$ap->encryption	($_->{encryption}); 
		$ap->power	($_->{power}); # TODO where from?
		$ap->channel	($_->{channel});
		$ap->longitude	($_->{longitude});
		$ap->latitude	($_->{latitude});

		$APS[$count]=$ap;		
		$count++;
	}

	return @APS;
}

#######################################################################
# function get_plugin - create plugin objects from plugincoredb
#	Arguments: none
#	Returns @plugin
###################
sub get_plugin {
	shift;
	my(@accesspoint, @PLUGINS);
	my $XML; 
	my $count=0;

	my $size=(stat("$plugincoredb"))[7];

	# We only want to search through the xml file if it exists
	# Otherwise it will create an empty entry
	if ((defined($size)) && ($size >= 122)) {

		$XML = XML::Smart->new($plugincoredb);
		if($cutroot) {
			$XML = $XML->cut_root;
		}

		@accesspoint = @{$XML->{"accesspoint"}};

		foreach(@accesspoint) {
			#my $name = $_->{ssid};
			my $name = $_->{ssid}."\n(".$_->{bssid}.")";
			my @plugin = @{$_->{"plugin"}};

			# Collection of all plugins belonging to an AP
			my @plugin_collection;

			# First entry in the plugin collection is the name
			# of AP followed by a list of plugins associated with
			# the AP
			push @plugin_collection, $name;

			foreach (@plugin) {	
				# Array used to store plugin data
				# [0] - name of the plugin
				# [1] - runtime
				# [2] - plugin output
				my @plugin_data;

				$plugin_data[0] = $_->{name};
				$plugin_data[1] = $_->{run};
 				$plugin_data[2] = decode_base64($_->{output});

				push @plugin_collection, \@plugin_data;
			}
	
			push @PLUGINS, \@plugin_collection;		
			$count++;
		}

	} else {
		#print "Couldn't open $plugincoredb";
	}

	return @PLUGINS;
}

#######################################################################
# function default_profile - sets and returns default profile
# 	Arugments: profile name
#	Returns: profile object
####################
sub default_profile {
	shift;
	if(@_) { $default_profile = shift; }
	else   { return $default_profile;  }
}

#######################################################################
# function apcoredb - sets and returns AP xml database
# 	Arugments: db path
#	Returns: db path
####################
sub apcoredb {
	shift;
	if(@_) { $apcoredb = $outputdir.shift;}
	else   { return $apcoredb;  }
}

#######################################################################
# function plugincoredb - sets and returns Plugin xml database
# 	Arugments: db path
#	Returns: db path
####################
sub plugincoredb {
	shift;
	if(@_) { $plugincoredb = $outputdir.shift; }
	else   { return $plugincoredb;  }
}

#######################################################################
# function filter - sets and returns ap filter
# 	Arugments: filter string
#	Returns: filter string
####################
sub filter {
	shift;
	if(@_) { $filter = shift; }
	else   { return $filter;  }
}

#######################################################################
# function filter_file - sets and returns ap filter file
# 	Arugments: filter path string
#	Returns: filter path string
####################
sub filter_file {
	shift;
	if(@_) { $filter_file = shift; }
	else   { return $filter_file;  }
}

#######################################################################
# function outputdir - sets and returns output directory for the plugin-engine
# 	Arugments: path string
#	Returns: path string
####################
sub outputdir {
	shift;
	if(@_) { $outputdir = shift; }
	else   { return $outputdir;  }
}

#######################################################################
# function interface - sets and returns pointer to interface hash
# 	Arugments: interface hash pointer
#	Returns: interface hash pointer
####################
sub interface {
	shift;
	if(@_) { $interface = shift; }
	else   { return $interface;  }
}

#######################################################################
# function guitype - sets and returns gui type used
# 	Arugments: gui type ('curses' or 'gtk')
#	Returns: gui type
####################
sub guitype {
	shift;
	if(@_) { $guitype = shift; }
	else   { return $guitype;  }
}

#######################################################################
# function lprint - forwards lprint command to appropriate ui
# 	Arugments: lprint input
#	Returns: 
####################
sub lprint {
	if($guitype eq 'gtk') {
		UI::GTKOutput->lprint(@_);
	}
	elsif($guitype eq 'curses') {
		UI::COutput->lprint(@_);
	}
}

#######################################################################
# function external - sets external discovery engine property
# 	Arugments: boolean
#	Returns: boolean
####################
sub external {
	shift;
	if(@_) { $external = shift; }
	else   { return $external;  }
}


#######################################################################
#function find_plugins - finds available plugins
#	Arguments: none
#	Returns: none
###################
sub find_plugins {	
	my $plugins_dir = "$basedir/plugins";
	my @plugins;
	
	opendir DIR, $plugins_dir or lprint(1,0,"Could not open $plugins_dir");
	while (my $plugin_name = readdir DIR) {
		next unless (-e "$basedir/plugins/$plugin_name/plugin.conf");
		push @plugins, $plugin_name;
		
	}

	return @plugins;
}
1;
