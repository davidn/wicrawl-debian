#
#   wicrawl - A modular and thorough wi-fi scanner
#   http://midnightresearch.com/projects/wicrawl - for details
#
#   Original Code:  Aaron Peterson
#   Contributors:
#   $Id: Plugin.pm,v 1.5 2006-09-28 08:01:19 sith Exp $
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

package Plugin;
use strict;

my $VERSION=0.1;

sub new {
    my $class = shift;
    my $self  = {
	NAME         => "Default plugin name",
	BIN          => "plugin",
	DESCRIPTION  => "Verbose Description",
	VERSION	     => "0.1",
	MONITOR      => "no",
	RUNLENGTH    => "medium",
	OFFLINE	     => "no",
	RUNLEVEL     => "50",
	PLUGINDIR    => undef,
	TIMEOUT      => 30,
	TYPE         => "scheduled",
	EVENT        => undef,
	IS_SYNCHRONOUS => "1",
	PLUGIN_ENV   => {},
	EVENTNUM     => {
	    "new-ap"        => 0,
	    "newap"         => 0,
	    "associated"    => 1,
	    "have-ip"       => 2,
	    "haveip"        => 2,
	    "have-internet" => 3,
	    "haveinternet"  => 3,
	    "discovery"     => 4,
	    "pre-discovery" => 5,
	    "prediscovery"  => 5,
	    "post-discovery"=> 6,
	    "postdiscovery" => 6,
	    "pre-ap"        => 7,
	    "preap"         => 7,
	    "post-ap"       => 8,
	    "postap"        => 8 
	},
	RUNLENGTHNUM => {
	    "short"         => 0,
	    "medium"        => 1,
	    "long"          => 2
	}
    };
    bless ($self, $class);
    return $self;
}

sub populate {
    my $self = shift;
    my ($name, $bin, $description, $version, $monitor, $runlength, $offline, $runlevel, $event, $plugindir, $timeout, $type, $is_synchronous)=@_;
    $self->{NAME}           = $name;
    $self->{BIN}            = $bin;
    $self->{DESCRIPTION}    = $description;
    $self->{VERSION}        = $version;
    $self->{MONITOR}        = $monitor;
    $self->{RUNLENGTH}      = $runlength;
    $self->{OFFLINE}        = $offline;
    $self->{RUNLEVEL}       = $runlevel;
    $self->{PLUGINDIR}      = $plugindir;
    $self->{TIMEOUT}        = $timeout;
    $self->{TYPE}           = $type;
    $self->{EVENT}          = $event;
    $self->{IS_SYNCHRONOUS} = $is_synchronous;
    return 0;
}

sub name {
    my $self = shift;
    if (@_) { $self->{NAME} = shift }
    return $self->{NAME};
}

sub description {
    my $self = shift;
    if (@_) { $self->{DESCRIPTION} = shift }
    return $self->{DESCRIPTION};
}

sub bin {
    my $self = shift;
    if (@_) { $self->{BIN} = shift }
    return $self->{BIN};
}

sub version {
    my $self = shift;
    if (@_) { $self->{VERSION} = shift }
    return $self->{VERSION};
}

sub monitor {
    my $self = shift;
    if (@_) { $self->{MONITOR} = shift }
    return $self->{MONITOR};
}

sub runlength {
    my $self = shift;
    if (@_) { $self->{RUNLENGTH} = shift }
    return $self->{RUNLENGTH};
}

sub offline {
    my $self = shift;
    if (@_) { $self->{OFFLINE} = shift }
    return $self->{OFFLINE};
}

sub runlevel {
    my $self = shift;
    if (@_) { $self->{RUNLEVEL} = shift }
    return $self->{RUNLEVEL};
}

sub plugindir {
    my $self = shift;
    if (@_) { $self->{PLUGINDIR} = shift }
    return $self->{PLUGINDIR};
}

sub type {
    my $self = shift;
    if (@_) { $self->{TYPE} = shift }
    return $self->{TYPE};
}

sub timeout {
    my $self = shift;
    if (@_) { $self->{TIMEOUT} = shift }
    return $self->{TIMEOUT};
}

sub event {
    my $self = shift;
    if (@_) { $self->{EVENT} = shift }
    return $self->{EVENT};
}

sub eventnum {
    my $self = shift;
    my $event=$self->{EVENT};
    my $en=$self->{EVENTNUM};
    return $en->{$event};
}

sub runlengthnum {
    my $self = shift;
    return $self->{RUNLENGTHNUM}->{$self->{RUNLENGTH}};
}

sub is_synchronous {
    my $self = shift;
    if (@_) { $self->{IS_SYNCHRONOUS} = shift }
    return $self->{IS_SYNCHRONOUS};
}

sub setpluginenv {
    my $self  = shift;
    my $key   = shift;
    my $value = shift;

    $self->{PLUGIN_ENV}->{$key}=$value;
    return 0;
}

# return just the key if it's set, otherwise return a reference to the whole
# hash
sub getpluginenv {
    my $self  = shift;

    if(@_) {
	my $key = shift;
	return $self->{PLUGIN_ENV}->{$key};
    } else { 
	return \%{$self->{PLUGIN_ENV}};
    }
}

1;
