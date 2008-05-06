#
#   wicrawl - A modular and thorough wi-fi scanner
#   http://midnightresearch.com/projects/wicrawl - for details
#
#   Original Code:  cybernmd
#   Contributors:
#   $Id: Preferences.pm,v 1.2 2006-04-14 08:33:33 sith Exp $
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

package Preferences;
use strict;

sub new {
	my $class = shift;
	my $self  = {
		THEME => undef,
		VERBOSITY_PLUGINENGINE => undef,
		VERBOSITY_UI => undef
	};
	bless ($self, $class);
	return $self;
}

sub theme {
	my $self = shift;
	if (@_) { $self->{THEME} = shift }
	return $self->{THEME};
}

sub verbosity_pluginengine {
	my $self = shift;
	if (@_) { $self->{VERBOSITY_PLUGINENGINE} = shift }
	return $self->{VERBOSITY_PLUGINENGINE};
}

sub verbosity_ui {
	my $self = shift;
	if (@_) { $self->{VERBOSITY_UI} = shift }
	return $self->{VERBOSITY_UI};
}

1;
