#
#   wicrawl - A modular and thorough wi-fi scanner
#   http://midnightresearch.com/projects/wicrawl - for details
#
#   Original Code:  Aaron Peterson
#   Contributors:
#   $Id: Profile.pm,v 1.5 2006-09-28 08:01:19 sith Exp $
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

package Profile;
use strict;

my $VERSION=0.1;

sub new {
	my $class = shift;
	my $self  = {
		SCHEDULING => undef,
		RUNLENGTHS => undef,
		PLUGINS	   => undef,
		KILLDISC   => undef,
		TIMEOUT    => undef
	};
	bless ($self, $class);
	return $self;
}

sub scheduling {
	my $self = shift;
	if (@_) { $self->{SCHEDULING} = shift }
	return $self->{SCHEDULING};
}

sub runlengths {
	my $self = shift;
	if (@_) { $self->{RUNLENGTHS} = shift }
	return $self->{RUNLENGTHS};
}

sub plugins {
	my $self = shift;
	if (@_) { $self->{PLUGINS} = shift }
	return $self->{PLUGINS};
}

sub killdisc {
	my $self = shift;
	if (@_) { $self->{KILLDISC} = shift }
	return $self->{KILLDISC};
}

sub timeout {
	my $self = shift;
	if (@_) { $self->{TIMEOUT} = shift }
	return $self->{TIMEOUT};
}

1;
