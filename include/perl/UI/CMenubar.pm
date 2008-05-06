package UI::CMenubar;

use strict;

use UI::Common;
use UI::COutput;
use UI::CExecute;
use Data::Dumper;

my $menu;

sub generate {
	shift;
	my ($cui) = @_;

	#####################################################
	# Prepare available interfaces
	my %interface = UI::Common->get_interfaces;
	my $interface_submenu;

	########################## Scanning ###################################
	push @$interface_submenu, {-label => "Use Interfaces" };
	foreach my $name (keys %interface) {
		if($name eq 'monitor') { next; }

		# prefix is used to simulate checkboxes and radios
		my $prefix;
		if($interface{$name}) { $prefix = "[x]"; }
		else { $prefix = "[ ]"; }

		push @$interface_submenu, {-label => "$prefix $name", -value => sub{
			UI::COutput->lprint(0,2,"Interface $name was selected\n");
			
			# Update interface hash
			if($interface{$name}) { $interface{$name} = 0; }
			else { $interface{$name} = 1; }

			UI::Common->interface(\%interface);

			# Update interface menu
			foreach (@$interface_submenu) {
				if($_->{-label} =~ /] $name/) {
					if($interface{$name}) {
						$_->{-label} = "[x] $name";
					} else {
						$_->{-label} = "[ ] $name";
					}
				}
			}
		}};
	}
	######################## Monitor Mode #################################
	push @$interface_submenu, {-label => "" };
	push @$interface_submenu, {-label => "Monitor Mode"};
	
	my $interface_flag = 1;

	foreach my $name (keys %interface) {
		if($name eq 'monitor') { next; }

		# prefix is used to simulate checkboxes and radios
		my $prefix; 		
		if($interface_flag) { $prefix = "<o>"; $interface_flag = 0; }
		else { $prefix = "< >"; }

		push @$interface_submenu, {-label => "$prefix $name", -value => sub{
			UI::COutput->lprint(0,1,"Setting $name as monitor interface\n");
			$interface{monitor} = $name;
			UI::Common->interface(\%interface);

			# Now update profile menu according to user selection
			foreach (@$interface_submenu) {
				if($_->{-label} =~ /> $name/) {
					$_->{-label} = "<o> $name";
				} else {
					$_->{-label} =~ s/<o>/< >/;
				}
			}
		}};

		

	}

	#####################################################
	# Prepare available profiles
	my @profiles = UI::Common->get_profiles;
	my $profile_submenu;

	# flag to set initial radio button
	my $profile_flag = 1;

	foreach my $profile (@profiles) {
		# prefix is used to simulate checkboxes and radios
		my $prefix; 		
		if($profile_flag) { $prefix = "<o>"; $profile_flag = 0; }
		else { $prefix = "< >"; }

	   	push @$profile_submenu, {-label => "$prefix $profile", -value => sub{
			UI::COutput->lprint(0,1,"Setting $profile as default profile\n");
			UI::Common->default_profile($profile);

			# Now update profile menu according to user selection
			foreach (@$profile_submenu) {
				if($_->{-label} =~ /$profile/) {
					$_->{-label} = "<o> $profile";
				} else {
					$_->{-label} =~ s/<o>/< >/;
				}
			}
		}};
	}

	#####################################################
	# Prepare menubar
	my $menu_data = [
	  { -label => 'Wicrawl', 
	    -submenu => [
	      { -label => 'Start in Automatic Mode', 
		-value => sub{
			UI::Common->external(0); 
			UI::CExecute->start($cui); 
			}   
	      },
	      { -label => 'Start in Discovery Mode', 
		-value => sub{ 
			UI::Common->external(0);
			UI::Common->default_profile("discovery");			
			UI::CExecute->start($cui); 
			}   
	      },
	      { -label => 'Start in Manual Mode', 
		-value => sub{ 
			UI::Common->external(1);
			UI::CExecute->start($cui); 
			}   
	      },
	      { -label => 'Stop', -value => sub{ UI::CExecute->stop($cui);  }  },
	      { -label => 'Exit', -value => sub{ UI::CExecute->stop($cui); exit(0); }  }
	    ]
	  },
	  { -label => 'Interfaces',  -submenu => $interface_submenu },
	  { -label => 'Profiles',    -submenu => $profile_submenu },
	  { -label => 'Filter',
	    -submenu => [
	      { -label => 'Set SSID Filter...', -value => sub{} },
	      { -label => 'Load SSID Filter File...', -value => sub{} },
	    ]  
	  },
	  { -label => 'View',
	    -submenu => [
	      { -label => 'Warbar', -value => sub{} },
	      { -label => 'Basic', -value => sub{ UI::CBasic->show; } },
	      { -label => 'Advanced', -value => sub{ UI::CAdvanced->show; } },
	      { -label => 'Output', -value => sub{} },
	    ]  
	  },
	  { -label => 'Help', 
	    -submenu => [
	      { -label => 'About', -value => sub{} }
	    ]
	  } 
	];

	$menu = $cui->add(
		'menubar','Menubar', 
		-menu => $menu_data,
		-bg  => 'blue',
		-fg  => "white",
	);

	# Focus on menu
	$cui->set_binding(sub { $menu->focus }, "\cX");
}

#######################################################################
#function focus - Brings focus on the menubar. This method is used
#		  during execution to avoid disappearing menus
#	Arguments: none
#	Returns: none
###################
sub focus {
	$menu->focus;
}

1;
