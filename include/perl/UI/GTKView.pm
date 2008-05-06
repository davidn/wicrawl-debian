package UI::GTKView;

use UI::GTKBasic;
use UI::GTKAdvanced;

my $nb;

sub generate {
	$nb = Gtk2::Notebook->new;
	$nb->set_tab_pos('left');
	
	my $basic_label = Gtk2::Label->new("Basic");
	$basic_label->set_angle(90);

	my $advanced_label = Gtk2::Label->new("Advanced");
	$advanced_label->set_angle(90);

	$nb->append_page(UI::GTKBasic->generate, $basic_label);
	$nb->append_page(UI::GTKAdvanced->generate, $advanced_label);
	return $nb;
}

sub show {
	$nb->show_all;
}

sub hide {
	$nb->hide_all;

	# Perform window resizing
	my $window = $nb->get_parent->get_parent->get_parent;
	my ($width, $height) = $window->get_size;
	$window->resize($width, $height - 300);
}

1;
