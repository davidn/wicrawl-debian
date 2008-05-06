ETCDIR = /etc/wicrawl
INSTALLDIR = /usr/local/wicrawl
BINDIR = /usr/sbin
DOCDIR = /usr/share/doc/wicrawl
INSTALL = /usr/bin/install
PACKAGE = wicrawl
VERSION = cvs
DISTDIR = $(PACKAGE)-$(VERSION)
PACKAGEFILE = $(DISTDIR).tgz

include config.mk

all: clean deps wicrawl

deps:
	@cd util && $(MAKE) .deps
	@cd discovery && $(MAKE) .deps

wicrawl:
	@cd util && $(MAKE)
	@cd plugins && $(MAKE)
	@cd discovery && $(MAKE)
	@cd util/dhcp && ./configure && $(MAKE)

clean:
	@cd util && $(MAKE) clean
	@cd discovery && $(MAKE) clean
	@cd plugins && $(MAKE) clean
	@cd util/dhcp && $(MAKE) clean
	@rm -rf $(DISTDIR)
	@rm -f $(PACKAGEFILE)

install:
	@echo
	@echo -e "Starting wicrawl installation:"
	@echo
	@echo "Installing base files in:   [$(INSTALLDIR)]"
	@echo "Installing binaries in:     [$(BINDIR)]"
	@echo "Installing config files in: [$(ETCDIR)]"
	@echo "Installing docs in:         [$(DOCDIR)]"
	@echo
	# Directories, perl modules, and conf files
	@$(INSTALL) -d $(INSTALLDIR)/plugins $(INSTALLDIR)/ui $(INSTALLDIR)/profiles
	@$(INSTALL) -d $(INSTALLDIR)/include/perl
	@$(INSTALL) include/perl/*.pm $(INSTALLDIR)/include/perl/
	@$(INSTALL) -d $(INSTALLDIR)/include/perl/Text/
	@$(INSTALL) include/perl/Text/*.pm $(INSTALLDIR)/include/perl/Text/
	@$(INSTALL) -d $(INSTALLDIR)/include/perl/UI/
	@$(INSTALL) include/perl/UI/*.pm $(INSTALLDIR)/include/perl/UI/
	@$(INSTALL) -D profiles/*.conf $(INSTALLDIR)/profiles/
	@$(INSTALL) -D discovery/apcore $(INSTALLDIR)/discovery/apcore
	@$(INSTALL) -D util/dhcp/work.linux-2.2/client/dhclient $(INSTALLDIR)/util/dhcp/dhclient
	# Docs
	@for file in `ls doc/ | grep -v CVS` ; do \
		install -D -m 644 doc/$$file $(DOCDIR)/$$file; \
	done
	# Plugins and plugin-engine
	@for dir in `ls plugins/ | grep -v CVS | grep -v plugin-engine` ; do \
		install -d $(INSTALLDIR)/plugins/$$dir; \
	done
	@for file in `find plugins/*/* | grep -v CVS` ; do \
		install -D -m 0755 $$file $(INSTALLDIR)/$$file; \
	done
	@cat plugins/plugin-engine | sed -e s_@@BASEDIR@@_$(INSTALLDIR)_ \
		> $(INSTALLDIR)/plugins/plugin-engine
	@chmod 755 $(INSTALLDIR)/plugins/plugin-engine
	# UI and themes
	@$(INSTALL) -D -m 0644 ui/wicrawl-gtk.conf $(ETCDIR)/wicrawl-gtk.conf
	@$(INSTALL) -D -m 0644 wicrawl.conf $(ETCDIR)/wicrawl.conf
	@for file in `find ui/ | grep -v CVS | grep -v wicrawl-gtk` ; do \
		if [ -f $$file ] ; then \
			install -D $$file $(INSTALLDIR)/$$file; \
		fi \
	done
	@cat ui/wicrawl-gtk | sed -e s_@@BASEDIR@@_$(INSTALLDIR)_ \
		> $(INSTALLDIR)/ui/wicrawl-gtk
	@cat ui/wicrawl-curses | sed -e s_@@BASEDIR@@_$(INSTALLDIR)_ \
		> $(INSTALLDIR)/ui/wicrawl-curses
	@cat ui/wicrawl | sed -e s_@@BASEDIR@@_$(INSTALLDIR)_ \
		> $(BINDIR)/wicrawl
	@chmod 755 $(INSTALLDIR)/ui/wicrawl-curses
	@chmod 755 $(INSTALLDIR)/ui/wicrawl-gtk
	@chmod 755 $(BINDIR)/wicrawl
	@echo
	@echo "Install Completed."
	@echo
	@echo "Run $(BINDIR)/wicrawl to get started"
	@echo

uninstall:
	@echo
	@echo -e "Sorry, not implemented yet, but here are the places we touched:"
	@echo
	@echo "Installed base files in:   [$(INSTALLDIR)]"
	@echo "Installed binaries in:     [$(BINDIR)]"
	@echo "Installed config files in: [$(ETCDIR)]"
	@echo "Installed docs in:         [$(DOCDIR)]"
	@echo

dist:
	@mkdir -p $(DISTDIR)
	@for file in `find . | grep -v CVS | grep -v ^.$$ | grep -v ^\./$(DISTDIR)` ; do \
		if [ -f $$file ] ; then \
			install -D $$file $(DISTDIR)/$$file; \
		fi \
	done
	@tar -czf $(PACKAGEFILE) $(DISTDIR)
	@echo -e "\nOutput package is in $(PACKAGEFILE)\n"

tags:
	find . -name \*.c -or -name \*.h | xargs etags
