package UI::COutput;

use strict;

use UI::Common;

my $textviewer;
my $win;

sub generate {
	shift;
	my ($cui) = @_;

	# create text viewer window
	$win = $cui->add(
		'wintextviewer', 'Window',     
		-title  => "Output",
		-titlereverse => 0,
		-border => 1,
		-y    => -1,
		-height => 10,
		-bfg  => "blue",
	);

	# add textviewer to the window
	$textviewer = $win->add(
	   'textviewer', 'TextViewer',
	   -vscrollbar => 1,
	   -wrapping   => 1,
	);



}
#######################################################################
# function lprint - log print function
# 	Arugments: type of buffer, message (int), loglevel (int), string of $msg
#		Returns: 0
#		Notes:  
#			Loglevels are:
#				0 = Errors and fatal  (Always shown, -q for quiet)
#				1 = Default logging   (default log level)
#				2 = More info  				(-v)
#				3 = All info          (-vv)
#			Message Types are:
#				0 = Info (black)
#				1 = Notice (orange)
#				2 = Error (red)
####################
sub lprint {
	shift;
	my ($type,$loglevel,$msg) = @_; 	

	my $color="white";

	# set the prefix character: '!' is err, '*' is notice
	if ($type == 1) {
		$color="cyan";
	}	elsif ($type == 2) {
		$color="red";
	}

	#$textviewer->{'-fg'} = 'red';

	my $verbosity = 3;

	# print if loglevel is high enough
	if($loglevel <= $verbosity) {
		$textviewer->text($textviewer->get.$msg);
		$textviewer->cursor_to_end;
		$textviewer->event_keypress("<end>");	

		# NOTE: need to layout the window in order to update
		# curses content
		$win->layout;
	}
	   	
}

1;
