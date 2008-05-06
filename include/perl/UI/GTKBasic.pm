package UI::GTKBasic;

my $basic; # pointer to hold content generated by this object

my $basic_list;

my $basic_index;

sub generate {
	$basic = Gtk2::ScrolledWindow->new(undef, undef);
	$basic->set_shadow_type('etched-out');
	$basic->set_policy('automatic', 'automatic');
	$basic->set_size_request(780,300);

	# Note: some of the fields are hidden because they are
	# not yet implemented, simply uncomment when ready
	$basic_list = Gtk2::SimpleList->new (
		' '	=> 'bool',
		'SSID'	=> 'markup',
		'BSSID' => 'markup',
		'Plugin' => 'markup',
		'Event' => 'markup',
		'Timestamp' => 'markup',
		'Encryption' => 'markup',
		'Channel' => 'markup',
		'Power' => 'markup',
		'Packets' => 'markup',
	#	'Time' => 'markup',
		'Latitude' => 'markup',
		'Longitude' => 'markup',
	);	

	 # make it searchable
   	$basic_list->set_search_column(1);  	

	# Connect signal to selection
	$basic_list->get_selection->signal_connect (changed => sub {
		my @index = $basic_list->get_selected_indices;
		# only set selection when something is actually selected
		if(@index) { $basic_index = $index[0]; }
	});
	  
	$basic->add($basic_list);
	return $basic;
}

#######################################################################
#function show-data - gets AP and displays them in AP frame
#	Arguments:
#	Returns: None
####################
sub show_data {

	# adding rows with APs
	my @APS = UI::Common->get_ap;

	# backup selected aps
	my @selected_aps;
	foreach my $ap (@{$basic_list->{data}}) {
		push @selected_aps, $$ap[0];
	}

	# clear current list only if new non-empty list is coming
	if(@APS) {
		@{$basic_list->{data}} = undef;
		pop @{$basic_list->{data}};
	}

	foreach (@APS) {

		#get correct color for the row
		my $color = "black";
		my $event = $_->{EVENT};
		if ($event eq "new-ap") { $color = "red";}
		elsif ($event eq "associated") { $color = "orange"; }
		elsif ($event eq "have-internet") { $color = "darkgreen"; }
		else { $color = "black"; }

		my $timestamp = $_->{TIMESTAMP};

		#make sure we are not fixing an already readable timestamp
		unless($timestamp =~ /:/) {
			my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($timestamp);
			$year += 1900;
			$timestamp = "$mon-$mday-$year $hour:$min:$sec";
		}

		# Note: some of the fields are hidden because they are
		# not yet implemented, simply uncomment when ready
		push @{$basic_list->{data}}, [ 1,
					"<span foreground='$color'>$_->{SSID}</span>",
					"<span foreground='$color'>$_->{BSSID}</span>",
					"<span foreground='$color'>$_->{PLUGIN}</span>",
					"<span foreground='$color'>$_->{EVENT}</span>",
					"<span foreground='$color'>$timestamp</span>",
					"<span foreground='$color'>$_->{ENCRYPTION}</span>",
					"<span foreground='$color'>$_->{CHANNEL}</span>",
					"<span foreground='$color'>$_->{POWER}</span>",
					"<span foreground='$color'>$_->{PACKETS}</span>", 
		#			"<span foreground='$color'>$_->{TIME}</span>",
					"<span foreground='$color'>$_->{LATITUDE}</span>",
					"<span foreground='$color'>$_->{LONGITUDE}</span>",
		];
	}
	# restore selected aps
	my $index = 0;
	foreach my $ap (@{$basic_list->{data}}) {
		$$ap[0] = $selected_aps[$index];
		$index++;
		unless(defined $selected_aps[$index]) { last; }
	}	

	# restore previously selected aps
	if(defined $basic_index) { $basic_list->select($basic_index); }
}

#######################################################################
#function get_ap - generates an array of AccessPoints based on user selection
#	Arguments:
#	Returns: @APS
####################
sub get_ap {
	my @APS;

	my $count = 0;
	foreach my $row (@{$basic_list->{data}}) {
		if($$row[0]) {
			my $ap=AccessPoint->new();
			if($$row[1] =~ /.*>(.*)<\/span/) { $ap->ssid($1); }	
			if($$row[2] =~ /.*>(.*)<\/span/) { $ap->bssid($1); }	
			if($$row[3] =~ /.*>(.*)<\/span/) { $ap->plugin($1); }	
			if($$row[4] =~ /.*>(.*)<\/span/) { $ap->event($1); }	
			if($$row[5] =~ /.*>(.*)<\/span/) { $ap->timestamp($1); }	
			if($$row[6] =~ /.*>(.*)<\/span/) { $ap->encryption($1); }	
			if($$row[7] =~ /.*>(.*)<\/span/) { $ap->channel($1); }		
			if($$row[8] =~ /.*>(.*)<\/span/) { $ap->power($1); }		
			if($$row[9] =~ /.*>(.*)<\/span/) { $ap->packets($1); }		
			if($$row[10] =~ /.*>(.*)<\/span/) { $ap->latitude($1); }		
			if($$row[11] =~ /.*>(.*)<\/span/) { $ap->longitude($1); }	
			push @APS, $ap;
			$count++;
		 }
	}
	
	if($count == 0) {
		UI::GTKOutput->lprint(2,1,"No APs were selected! Add checkmarks next to APs you want to scan.\n");
	}

	return @APS;	

}

sub show {
	$basic->show_all;
}

sub hide {
	$basic->hide_all;

	# Perform window resizing
	my $window = $basic->get_parent->get_parent->get_parent->get_parent;
	my ($width, $height) = $window->get_size;
	$window->resize($width, $height - 300);
}

1;
