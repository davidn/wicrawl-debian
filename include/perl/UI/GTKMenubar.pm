package UI::GTKMenubar;

use UI::GTKExecute;
use Data::Dumper;

my $basedir = "/usr/local/wicrawl";
my $outputdir = "/var/log/wicrawl/";
my $fifo="$outputdir/ipc";

my $menu_bar;

# collection of all profiles stored in radiomenuitem
my $profile_group;

# plugins item in the menubar
my $menu_item_plugins;	

sub generate {
	my @profiles = UI::Common->get_profiles;
	my %interface = UI::Common->get_interfaces;
	my $monitor_interface;

	$menu_bar = Gtk2::MenuBar->new;
	$menu_bar->set_border_width(0);

	# Menu Bar data declaration

	#######################################################
	# Top Menu - Wicrawl
	my $menu_item_wicrawl = Gtk2::MenuItem->new('_Wicrawl');
	my $wicrawl_menu = Gtk2::Menu->new();

	# Start in Automatic Mode Menu Item
	$wicrawl_menu_start = Gtk2::MenuItem->new_with_mnemonic("Start in _Automatic Mode");
	$wicrawl_menu_start->signal_connect('activate' => sub {
		# Use discovery engine
		UI::Common->external(0);

		UI::GTKExecute->start;
	});
	$wicrawl_menu->append($wicrawl_menu_start);

	# Start in Discovery Mode Menu Item
	$wicrawl_menu_startdisc = Gtk2::MenuItem->new_with_mnemonic("Start in _Discovery Mode");
	$wicrawl_menu_startdisc->signal_connect('activate' => sub {
		# Use discovery engine
		UI::Common->external(0);

		# Switch to profile with no plugins
		UI::Common->default_profile("discovery");

		UI::GTKExecute->start;

		# select discovery profile in the ui
		my $size = @$profile_group;
		my $discovery_profile = @$profile_group[$size - 2];
		$discovery_profile->activate;
	});
	$wicrawl_menu->append($wicrawl_menu_startdisc);

	# Start in Manual Mode Menu Item
	$wicrawl_menu_startman = Gtk2::MenuItem->new_with_mnemonic("Start in _Manual Mode");
	$wicrawl_menu_startman->signal_connect('activate' => sub {
		# Collect selected APs
		my @APS = UI::GTKBasic->get_ap;	
		
		# Use external discovery engine
		UI::Common->external(1);

		UI::GTKExecute->start;

		# sleep a bit to allow ipc pipe to open
		sleep 1;

		# send APS to ipc pipe
		foreach my $ap (@APS) {
			$ap->to_ipc($fifo);
		}
	});
	$wicrawl_menu->append($wicrawl_menu_startman);
	

	# Stop Menu Item
	$wicrawl_menu_stop = Gtk2::MenuItem->new_with_mnemonic("S_top");
	$wicrawl_menu_stop->signal_connect('activate' => sub {
		UI::GTKExecute->stop;
	});
	$wicrawl_menu->append($wicrawl_menu_stop);

	# Exit Menu Item
	my $wicrawl_menu_exit = Gtk2::MenuItem->new_with_mnemonic("_Exit");
	$wicrawl_menu_exit->signal_connect('activate' => sub {
		UI::GTKExecute->stop;
		Gtk2->main_quit; 
	});
	$wicrawl_menu->append($wicrawl_menu_exit);
	$menu_item_wicrawl->set_submenu($wicrawl_menu);
	$menu_bar->append($menu_item_wicrawl);
	#######################################################

	#######################################################
	# Top Menu - Interfaces
	my $menu_item_int = Gtk2::MenuItem->new('_Interfaces');
	my $int_submenu = Gtk2::Menu->new();

	# check if there are any wireless interfaces available
	if(!%interface) {
		my $int = Gtk2::MenuItem->new("None");
		$int_submenu->append($int);

		# Display warning dialog
		my $warning_dialog = Gtk2::Dialog->new('Attention', $window,'destroy-with-parent','gtk-ok' => 'none');
	
	        my $label = Gtk2::Label->new;		
		my $msg="No wireless interfaces found\n";
		$msg.="Maybe you need to bring them up?\n";
		$msg.="(hint: \"ifconfig ath0 up\" or similar and restart)\n";
	        $label->set_markup($msg);

	        $warning_dialog->vbox->add($label);
		$warning_dialog->signal_connect (response => sub { $_[0]->destroy });
		$warning_dialog->show_all;

	}
	else {
		########################## Scanning ###################################
		$int_submenu->append(Gtk2::MenuItem->new_with_label ('Use Interfaces'));
		$int_submenu->append(Gtk2::SeparatorMenuItem->new);
		foreach my $name (keys %interface) {
			if($name eq 'monitor') { next; }
			my $int = Gtk2::CheckMenuItem->new($name);
			$int->signal_connect('toggled' => sub {
				my $self = shift;			
				if ($self->get_active) {
					UI::GTKOutput->add_page("$name");
					$interface{$name} = 1;
				} else {
					UI::GTKOutput->remove_page("$name");
					$interface{$name} = 0;
				}
				UI::Common->interface(\%interface);
			});

			$int_submenu->append($int);	
		}

		$int_submenu->append(Gtk2::MenuItem->new_with_label (''));

		######################## Monitor Mode #################################
		$int_submenu->append(Gtk2::MenuItem->new_with_label ('Monitor Mode'));
		$int_submenu->append(Gtk2::SeparatorMenuItem->new);
							
		my $interface_group;

		foreach my $name (keys %interface) {
			if($name eq 'monitor') { next; }
  			my $interface = Gtk2::RadioMenuItem->new($interface_group, "$name");
  			$interface->signal_connect('toggled' => sub { 
				$interface{'monitor'} = $name;
				UI::Common->interface(\%interface); 
			});
  			$interface_group = $interface->get_group;
  			$int_submenu->append($interface);	
  		}
	}
	$menu_item_int->set_submenu($int_submenu);
	$menu_bar->append($menu_item_int);

	#######################################################

        #######################################################
	# Top Menu - Profiles
	my $menu_item_profiles = Gtk2::MenuItem->new('_Profiles');
	my $wicrawl_menu_profile_submenu = Gtk2::Menu->new();

	foreach my $name (@profiles) {
		my $profile = Gtk2::RadioMenuItem->new($profile_group, "$name");
		$profile->signal_connect('toggled' => sub { 
			UI::Common->default_profile($name); 
			#if($profile->get_active) { &custom_profile($name);}
			&display_plugins($name);
		});
		$profile_group = $profile->get_group;

		$wicrawl_menu_profile_submenu->append($profile);	
	}

	$menu_item_profiles->set_submenu($wicrawl_menu_profile_submenu);
	$menu_bar->append($menu_item_profiles);
	#######################################################	

        #######################################################
	# Top Menu - Plugins
	$menu_item_plugins = Gtk2::MenuItem->new('Pl_ugins');
	
	# display default plugins
	&display_plugins('default');

	$menu_bar->append($menu_item_plugins);
	#######################################################	


	#######################################################
	# Top Menu - Filters
	my $menu_item_filter = Gtk2::MenuItem->new('_Filter');
		my $filter_menu = Gtk2::Menu->new();

		my $filter_entry = Gtk2::MenuItem->new_with_mnemonic("Set SSID _Filter...");
		$filter_entry->signal_connect('activate' => sub {
			my $ssid_dialog = Gtk2::Dialog->new('SSID Filter', $window,'destroy-with-parent',
							'gtk-ok' => 'none');
			my $filter_label = Gtk2::Label->new("Please enter SSID filter\n ie \"linksys\"");
			$ssid_dialog->vbox->add($filter_label);

			my $filter_entry = Gtk2::Entry->new();
			$filter_entry->append_text(UI::Common->filter);
			$filter_entry->signal_connect ('changed' => sub {
				UI::Common->filter($filter_entry->get_text);
			});
			$ssid_dialog->vbox->add($filter_entry);

			$ssid_dialog->signal_connect (response => sub { $_[0]->destroy });
			$ssid_dialog->show_all;
		});
		$filter_menu->append($filter_entry);

		my $filter_file = Gtk2::MenuItem->new_with_mnemonic("_Load SSID Filter File...");
		$filter_file->signal_connect('activate' => sub {

			my $file_chooser = Gtk2::FileChooserDialog->new (
			'Save', undef, 'save',
			'gtk-cancel' => 'cancel',
			'gtk-ok' => 'ok'
			);

			$file_chooser->set_current_name(UI::Common->filter_file);

			my $filename;
			if ('ok' eq $file_chooser->run) {
				$filename = $file_chooser->get_filename;
			}

			$file_chooser->destroy;

			if (defined $filename) {
				UI::Common->filter_file($filename);
			}
		});
		$filter_menu->append($filter_file);

		$menu_item_filter->set_submenu($filter_menu);
	$menu_bar->append($menu_item_filter);
	#######################################################

	#######################################################
	# Top Menu - View
	my $menu_item_view = Gtk2::MenuItem->new('_View');
		my $view_menu = Gtk2::Menu->new();

		my $warbar = Gtk2::CheckMenuItem->new_with_mnemonic("_Warbar");
		$warbar->set_active(1);
		$warbar->signal_connect('toggled' => sub {
				my $self = shift;			
				if ($self->get_active) { UI::GTKWarbar->show(); }
				else { UI::GTKWarbar->hide();	}
		});
		$view_menu->append($warbar);

		my $ap_view = Gtk2::CheckMenuItem->new_with_mnemonic("_AP/Plugin View");
		$ap_view->set_active(1);
		$ap_view->signal_connect('toggled' => sub {
				my $self = shift;			
				if ($self->get_active) { UI::GTKView->show(); }
				else { UI::GTKView->hide();	}
		});
		$view_menu->append($ap_view);

		my $output = Gtk2::CheckMenuItem->new_with_mnemonic("_Output");
		$output->set_active(1);
		$output->signal_connect('toggled' => sub {
				my $self = shift;			
				if ($self->get_active) { UI::GTKOutput->show(); }
				else { UI::GTKOutput->hide();	}
		});
		$view_menu->append($output);

		$menu_item_view->set_submenu($view_menu);

	$menu_bar->append($menu_item_view);

	#######################################################	

	#######################################################
	# Top Menu - Reports
	my $menu_item_reports = Gtk2::MenuItem->new('_Reports');

		my $reports_menu = Gtk2::Menu->new();

		my $xml_report = Gtk2::MenuItem->new_with_mnemonic("Generate XML Report...");
		$xml_report->signal_connect('activate' => sub {
			&save_output('xml');
		});
		$reports_menu->append($xml_report);

		my $html_report = Gtk2::MenuItem->new_with_mnemonic("Generate HTML Report...");
		$html_report->signal_connect('activate' => sub {
			&save_output('html');
		});
		$reports_menu->append($html_report);

		my $txt_report = Gtk2::MenuItem->new_with_mnemonic("Generate TXT Report...");
		$txt_report->signal_connect('activate' => sub {
			&save_output('txt');
		});
		$reports_menu->append($txt_report);

		$menu_item_reports->set_submenu($reports_menu);

	$menu_bar->append($menu_item_reports);
	#######################################################	


	#######################################################
	# Top Menu - Help
	my $menu_item_help = Gtk2::MenuItem->new('_Help');
	my $help_menu = Gtk2::Menu->new();

	# Help Menu Item
	my $help_menu_content = Gtk2::ImageMenuItem->new_from_stock('gtk-help',undef);
	$help_menu_content->signal_connect('activate' => sub {
	my $help_dialog = Gtk2::Dialog->new('Wicrawl Help', $window,'destroy-with-parent','gtk-ok' => 'none');

	my $hbox = Gtk2::HBox->new;
	my $buffer;

	######################################################
	# Help Selection
	


	######################################################
	# Output Frame

	my $help_text = "Common Wicrawl Use:

1) Open submenu 'Interfaces' and select which interface(s) to use when crawling networks as well as a single monitor interface used for network discovery.

2) Open submenu 'Profiles' to choose one of the predefined profiles or fine tune wicrawl's operation by selecting custom profile and choosing which plugins to run.

3) Apply filters as necessary in 'Filter' submenu

4) Launch wicrawl by selecting 'Wicrawl' submenu and choosing appropriate mode:
	* Automatic mode - discovers available networks and
	  runs plugins from selected profile
	* Discovery mode - only discovers networks (equivalent 
	  to selecting discovery profile)
	* Manual mode - allows for external network discovery

5) Once wicrawl is launched immediate information about discovered networks will be available in 'Basic View' and detailed plugin engine output will be displayed in the output window. Select 'Advanced View' to review output of each plugin.

6) At any moment you can generate and save reports of discovered networks and outputs of plugins. Wicrawl is capable of generating XML, HTML, and TXT reports.
";

	my $frame = Gtk2::Frame->new;
	$frame->set_size_request (500,500);

	# Output Scrolled Window
	my $sw = Gtk2::ScrolledWindow->new (undef, undef);
	$sw->set_shadow_type ('etched-out');
	$sw->set_policy ('automatic', 'automatic');

	# Creates view window and sets properties
	my $tview = Gtk2::TextView->new();
	$tview->set_editable(0);
	$tview->set_cursor_visible(0);
	$tview->set_wrap_mode("word");

	# Set initial view window content
	$buffer = $tview->get_buffer();
	$buffer->set_text($help_text);	

	$sw->add($tview);
	$frame->add($sw);
		
	$hbox->pack_start($frame, TRUE,TRUE,5);
	#######################################################

        $help_dialog->vbox->add($hbox);
	$help_dialog->signal_connect (response => sub { $_[0]->destroy });
	$help_dialog->show_all;
	});
	$help_menu->append($help_menu_content);			
		
	$help_menu->append(Gtk2::SeparatorMenuItem->new());
	
	# About Menu Item
	my $help_menu_about = Gtk2::ImageMenuItem->new_from_stock('gtk-about',undef);
	$help_menu_about->signal_connect('activate' => sub {
	my $about_dialog = Gtk2::Dialog->new('About Wicrawl', $window,'destroy-with-parent','gtk-ok' => 'none');
	
	my $hbox = Gtk2::HBox->new;


	my $mrl_logo = Gtk2::Image->new_from_file("$basedir/ui/pix/Mrl_Big.jpg");
	$mrl_logo->set_pixel_size(-5);
	$hbox->pack_start($mrl_logo,FALSE,FALSE,0);
	

        my $label = Gtk2::Label->new;
        $label->set_markup("
<span><big>Wicrawl</big>

Wi-Fi (802.11x) Access Point auditor with a simple
and flexible plugin architecture.

Visit http://www.midnightresearch.com for latest
releases and news on wicrawl.

<big>Developers:</big>

o Aaron Peterson - Project Manager and Developer
o Jason Spence - Developer
o Peter Kacherginsky - Developer
o Brian Johnson - Developer
</span>");

	$hbox->pack_start($label,TRUE,TRUE,5);

        $about_dialog->vbox->add($hbox);
	$about_dialog->signal_connect (response => sub { $_[0]->destroy });
	$about_dialog->show_all;
	});
	$help_menu->append($help_menu_about);
	$menu_item_help->set_submenu($help_menu);
	$menu_bar->append($menu_item_help);

	#######################################################
	return $menu_bar;
}

#######################################################################
# function save_output - collect filename and report type
#	Arguments: Output type

sub save_output {
	my $type = shift;

	my $file_chooser = Gtk2::FileChooserDialog->new (
		'Save', undef, 'save',
		'gtk-cancel' => 'cancel',
		'gtk-ok' => 'ok'
	);

	# suggest default save file
	my $timestamp = time;
	$file_chooser->set_current_name("wicrawl-report-$timestamp.$type");


	# extra save type selector
	my $hbox = Gtk2::HBox->new(FALSE,0);

	my $label = Gtk2::Label->new("Select Type:      ");
	$hbox->pack_start($label,FALSE,FALSE,0);

	my $cb = Gtk2::ComboBox->new_text;
	$cb->append_text("xml");
	$cb->append_text("html");
	$cb->append_text("txt");
	$cb->signal_connect('changed' =>sub {
		$type = $cb->get_active_text;
		$file_chooser->set_current_name("wicrawl-report-$timestamp.$type");
	});

	# set appropriate report type depending on user selection
	if($type eq "xml") { $cb->set_active(0); }
	elsif($type eq "html") {$cb->set_active(1); }
	elsif($type eq "txt") {$cb->set_active(2); }

	$hbox->pack_start($cb,TRUE,TRUE,0);
	$hbox->show_all;

	$file_chooser->set_extra_widget($hbox);

	my $filename;
	if ('ok' eq $file_chooser->run){
		$filename = $file_chooser->get_filename;
		UI::GTKOutput->lprint (1,1,"Saving filename $filename\n");
	}

	$file_chooser->destroy;

	if (defined $filename) {
		if (-f $filename) {
			my $overwrite = show_message_dialog( $window, 'question',
				'Overwrite existing file:'."<b>\n$filename</b>",
				'yes-no'
				);
			return if($overwrite eq 'no');
		}
	}
	
	my $apcoredb = UI::Common->apcoredb;
	my $plugincoredb = UI::Common->plugincoredb;


	if(defined $apcoredb) {
		if(-f $apcoredb) {
	  		if($type eq "xml") {
	  			UI::Reports->xml_report($filename);
			}
			elsif($type eq "html") {
				UI::Reports->html_report($filename);
			}
			elsif($type eq "txt") {
				UI::Reports->txt_report($filename);	
			}
		}
	}

}

#######################################################################
# function custom_profile - helps user select which plugins to run
#	Arguments: profile name to open
#	Returns: flag indicating whether anything was changed in the profile
sub custom_profile {
	my ($name) = @_;

	my $flag=0;

	# get already selected plugins in user profile
	my $selected_plugins = "";
	my $custom_profile = "";

	open (CUSTOM, "$basedir/profiles/$name.conf") || UI::GTKOutput->lprint(2,1, "Couldn't load $name profile\n");
	while(<CUSTOM>) {
		if(/\$enabled_plugins=\"(.*)\"\;/) { $selected_plugins = $1;}
		$custom_profile .= $_;

	}
	close CUSTOM;

	# display all plugins and select ones from custom profile
	my $dialog = Gtk2::Dialog->new("$name profile", $menu_bar->get_parent->get_parent,
					'destroy-with-parent',
					'gtk-ok' => 'ok');

	$dialog->vbox->add (Gtk2::Label->new ("Active plugins:\n"));

	my $hbox = Gtk2::HBox->new(FALSE,0);
	my $row1 = Gtk2::VBox->new(FALSE,0);
	my $row2 = Gtk2::VBox->new(FALSE,0);
	
	my @plugins = UI::Common->find_plugins;
	
	my $counter = 1;
	foreach my $name (sort @plugins) {
		# create new checkbutton
		my $plugin = Gtk2::CheckButton->new($name);
		if($selected_plugins =~ $name) {$plugin->set_active(1); }
		$plugin->signal_connect('toggled' => sub {
			my $self = shift;
			if($self->get_active) {
				$selected_plugins .= " $name";
			} else {
				$selected_plugins =~ s/$name//;
			}
			#remove accumulated white spaces
			$selected_plugins =~ s/\s{2,}/ /g;

			#something changed
			$flag = 1;			
		});

		if($counter % 2) { $row2->pack_start($plugin,FALSE,FALSE,0); }
		else { $row1->pack_start($plugin, FALSE, FALSE, 0); }
		$counter++;
	}
	$hbox->pack_start($row1,FALSE,FALSE,0);
	$hbox->pack_start($row2,FALSE,FALSE,0);
	$dialog->vbox->add($hbox);

	my $notice = Gtk2::Label->new;
	$notice->set_markup("\n<sub><span color='red'>NOTE: All changes will be saved to custom profile</span></sub>");

	$dialog->vbox->add ($notice);

	# Ensure that the dialog box is destroyed when the user responds.
	$dialog->signal_connect (response => sub { 
		if($flag) {
			# apply changes to custom profile and save to file
			UI::GTKOutput->lprint(1,1,"Saving changes to custom profile");
			$custom_profile =~ s/\$enabled_plugins.*/\$enabled_plugins=\"$selected_plugins\"\;/;
			open (CUSTOM, "> $basedir/profiles/custom.conf") || UI::GTKOutput->lprint(2,1, "Couldn't save custom profiles\n");
			print CUSTOM $custom_profile;
			close CUSTOM;

			# select custom profile in the ui
			my $custom_profile = @$profile_group[0];
			$custom_profile->activate;
			&display_plugins('custom');	
		}
		$dialog->destroy;
	});

	$dialog->show_all;
}

sub display_plugins {
	my ($name) = @_;

	my $selected_plugins = "";

	open (CUSTOM, "$basedir/profiles/$name.conf") || UI::GTKOutput->lprint(2,1, "Couldn't load $name profile\n");
	while(<CUSTOM>) {
		if(/\$enabled_plugins=\"(.*)\"\;/) { $selected_plugins = $1;}
	}
	close CUSTOM;

	my @plugins = UI::Common->find_plugins;

	my $plugins_submenu = Gtk2::Menu->new();

	my $add_plugins = Gtk2::ImageMenuItem->new_with_label("Edit active plugins");
	$add_plugins->set_image(Gtk2::Image->new_from_stock('gtk-preferences','menu'));
	$add_plugins->signal_connect('activate' => sub {
		&custom_profile($name);
	});
	$plugins_submenu->append($add_plugins);


	$plugins_submenu->append(Gtk2::SeparatorMenuItem->new());

	foreach my $name (@plugins) {
		my $plugin = Gtk2::ImageMenuItem->new_with_label("$name");
		if($selected_plugins =~ $name) { $plugin->set_image(Gtk2::Image->new_from_stock('gtk-add','menu')); }

		$plugins_submenu->append($plugin);	
	}

	$menu_item_plugins->set_submenu($plugins_submenu);
	$menu_item_plugins->show_all;

	
}

1;
