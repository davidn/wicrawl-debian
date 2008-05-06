package UI::CBasic;

my $win;
my $grid;

sub generate {
	shift;
	my ($cui) = @_;	

	# create grid window
	$win = $cui->add(
		'basic', 'Window',   
		-title  => "Basic",
		-titlereverse => 0,
		-border => 1,
		-y    => -11,
		-padtop => 1,
		-fg  => "blue",
		-bfg  => "blue",
	);

	$grid =$win->add(
		'basicgrid','Grid'
		,-editable=>0
		,-bg => "black"
	);

	$grid->add_cell("c",-width=>3,-label=>"   ");
	$grid->add_cell("ssid",-width=>15,-label=>"SSID");
	$grid->add_cell("bssid",-width=>17,-label=>"BSSID");
	$grid->add_cell("plugin",-width=>17,-label=>"Plugin");
	$grid->add_cell("event",-width=>10,-label=>"Event");
	$grid->add_cell("timestamp",-width=>15,-label=>"Timestamp");
	$grid->add_cell("encryption",-width=>5,-label=>"Crypt");
	$grid->add_cell("channel",-width=>2,-label=>"Ch");

	$grid->layout_content;

}

#######################################################################
#function show-data - gets AP and displays them in AP frame
#	Arguments:
#	Returns: None
####################
sub show_data {	
	# adding rows with APs
	my @APS = UI::Common->get_ap;

	# clear current list only if new non-empty list is coming
	if(@APS) { while($grid->del_row) {} }

	foreach (@APS) {

		#get correct color for the row
		my $color = "black";
		my $event = $_->{EVENT};
		if ($event eq "new-ap") { $color = "red";}
		elsif ($event eq "associated") { $color = "yellow"; }
		elsif ($event eq "have-internet") { $color = "green"; }

		#fix timestamp
		my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($_->{TIMESTAMP});
		$year += 1900;
		my $timestamp = "$mon-$mday-$year $hour:$min:$sec";

		# Note: some of the fields are hidden because they are
		# not yet implemented, simply uncomment when ready
		my %row_hash = (
			c=>"[x]",
			ssid=>"$_->{SSID}",
			bssid=>"$_->{BSSID}",
		#	time=>"$_->{TIME}",
		#	packets=>"$_->{PACKETS}",
			plugin=>"$_->{PLUGIN}",
			event=>"$_->{EVENT}",
			timestamp=>"$timestamp",
			encryption=>"$_->{ENCRYPTION}",
		#	power=>"$_->{POWER}",
			channel=>"$_->{CHANNEL}",
		#	latitude=>"$_->{LATITUDE}",
		#	longitude=>"$_->{LONGITUDE}" 
		);

		$grid->add_row(undef,
		    ,-fg=>"$color"
		    ,-cells=>{ %row_hash } );

	}		

}

sub show {
	$win->focus;
}
1;
