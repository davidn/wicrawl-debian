#
#   wicrawl - A modular and thorough wi-fi scanner
#   http://midnightresearch.com/projects/wicrawl - for details
#
#   Original Code:  Aaron Peterson
#   Contributors:
#   $Id: AccessPoint.pm,v 1.8 2007-12-14 07:48:05 sith Exp $
#
#   Copyright (C) 2005-2006 Midnight Research Laboratories
#
#   THIS SOFTWARE IS PROVIDED "AS IS". NO WARRANTY IS ASSUMED.
#   NO LIABILITY OF ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING
#   FROM THE USE OF THIS SOFTWARE WILL BE ACCEPTED. IT CAN BURN
#   YOUR HARD DISK, ERASE ALL YOUR DATA AND BREAK DOWN YOUR
#   MICROWAVE OVEN. YOU ARE ADVISED.
#
#   wicrawl is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.  For details see doc/LICENSE.

package AccessPoint;
use strict;
use MIME::Base64;

my $VERSION=0.1;

sub new {
	my $class = shift;
	my $self  = {
		SSID       => undef,
		BSSID      => undef,
		TIME       => undef,
		PACKETS    => undef,
		PLUGIN     => undef,
		PLUGINPATH => [],
		EVENT      => undef,
		TIMESTAMP  => undef,
		ENCRYPTION => undef,
		POWER      => undef,
		CHANNEL	   => undef,
		LONGITUDE => undef,
		LATITUDE => undef
	};
	bless ($self, $class);
	return $self;
}

sub ssid {
	my $self = shift;
	if (@_) { $self->{SSID} = shift }
	return $self->{SSID};
}

sub bssid {
	my $self = shift;
	if (@_) { $self->{BSSID} = shift }
	return $self->{BSSID};
}

# This is a timestamp in seconds
sub time {
	my $self = shift;
	if (@_) { $self->{TIME} = shift }
	return $self->{TIME};
}

sub packets {
	my $self = shift;
	if (@_) { $self->{PACKETS} = shift }
	return $self->{PACKETS};
}

sub plugin {
	my $self = shift;
	if (@_) { $self->{PLUGIN} = shift }
	return $self->{PLUGIN};
}

sub setpluginpath {
	my $self = shift;
	my $lvl = shift;
	my $name = shift;
	$self->{PLUGINPATH}[$lvl] = $name;
	return 0;
}

sub getpluginpath {
	my $self = shift;
	my $lvl = shift;
	my $name=$self->{PLUGINPATH}[$lvl];
	return $name;
}

sub timestamp {
	my $self = shift;
	if (@_) { $self->{TIMESTAMP} = shift }
	return $self->{TIMESTAMP};
}

sub event {
	my $self = shift;
	if (@_) { $self->{EVENT} = shift }
	return $self->{EVENT};
}

# text: WEP, WPA, NONE
sub encryption {
	my $self = shift;
	if (@_) { $self->{ENCRYPTION} = shift }
	return $self->{ENCRYPTION};
}

# In what?
sub power {
	my $self = shift;
	if (@_) { $self->{POWER} = shift }
	return $self->{POWER};
}

sub channel {
	my $self = shift;
	if (@_) { $self->{CHANNEL} = shift }
	return $self->{CHANNEL};
}

sub latitude {
	my $self = shift;
	if (@_) { $self->{LATITUDE} = shift }
	return $self->{LATITUDE};
}

sub longitude {
	my $self = shift;
	if (@_) { $self->{LONGITUDE} = shift }
	return $self->{LONGITUDE};
}

# This is a mechanism to serialize AccessPoint data to the IPC for
# the plugin-engine.  See the IPC document in /docs for more details.
sub to_ipc {
	my $self = shift;
	my $ipcfile = shift;

	my $msg;
	if(! -w $ipcfile) {
		print "ERR: AccessPoint.pm: file [$ipcfile] is not writable\n";
		return 0;
	}

	# Messages have to be of type "new" so that the plugin-engine will actually 
	# register them.
	$msg="new|ssid:";
	$msg.=encode_base64($self->{SSID});
	chomp($msg);

	my $bssid=$self->{BSSID};
	$bssid =~ s/://g;
	# Get the binary "encoded" bssid
	$bssid=pack("H12", $bssid);
	$msg.="|bssid:";
	$msg.=encode_base64($bssid);
	chomp($msg);

	$msg.="|encryption:";
	$msg.=encode_base64($self->{ENCRYPTION});
	chomp($msg);

	$msg.="|channel:";
	$msg.=encode_base64(pack("C", $self->{CHANNEL}));
	chomp($msg);
	
	# These are the non-mandatory fields
	if((defined($self->{POWER})) && ($self->{POWER} ne "")) {
		$msg.="|power:";
		$msg.=encode_base64($self->{POWER});
		chomp($msg);
	}

	if((defined($self->{LONGITUDE})) && ($self->{LONGITUDE} ne "")) {
		$msg.="|longitude:";
		$msg.=encode_base64($self->{LONGITUDE});
		chomp($msg);
	}

	if((defined($self->{LATITUDE})) && ($self->{LATITUDE} ne "")) {
		$msg.="|latitude:";
		$msg.=encode_base64($self->{LATITUDE});
		chomp($msg);
	}
		
	if((defined($self->{PACKETS})) && ($self->{PACKETS} ne "")) {
		$msg.="|packets:";
		$msg.=encode_base64($self->{PACKETS});
		chomp($msg);
	}

	open(IPC, ">$ipcfile") || print "ERR: AccessPoint.pm: file [$ipcfile] can not be open for writing\n";
	print IPC $msg . "\n";
	close(IPC) || print "ERR: AccessPoint.pm: file [$ipcfile] can not be closed\n";

	return 1;
}

1;
