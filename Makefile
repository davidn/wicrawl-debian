install = /usr/bin/install -c

prefix = /usr/local
exec_prefix = ${prefix}
datarootdir = ${prefix}/share
bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
datadir = ${datarootdir}
docdir = ${datarootdir}/doc/${PACKAGE_TARNAME}
includedir = ${prefix}/include
libdir = ${exec_prefix}/lib

pkgdatadir = $(datadir)/wicrawl
pkglibdir = $(libdir)/wicrawl
pkgincludedir = $(includedir)/wicrawl
pkgdocdir = $(docdir)/wicrawl

edit_files = ui/wicrawl ui/wicrawl-gtk ui/wicrawl-curses plugins/plugin-engine include/perl/UI/CExecute.pm include/perl/UI/Common.pm include/perl/UI/GTKExecute.pm include/perl/UI/GTKMenubar.pm include/perl/UI/GTKOutput.pm include/perl/UI/GTKWarbar.pm

edit = sed \
       -e 's|@datadir[@]|$(pkgdatadir)|g' \
       -e 's|@prefix[@]|$(prefix)|g' \
       -e 's|@libdir[@]|$(pkglibdir)|g'

all: not-plugins plugins

not-plugins: discovery/apcore discovery/hashtest $(edit_files)

plugins: plugins-stamp

plugins-stamp:
	cd plugins && make all
	touch plugins-stamp

discovery/apcore: discovery/.deps util/libutil.a
	cd discovery && make apcore

discovery/hashtest: discovery/.deps
	cd discovery && make hashtest

discovery/.deps: discovery/*.c
	cd discovery && make .deps

util/libutil.a: util/.deps
	cd util && make libutil.a

util/.deps: include/wicrawl.h util/errlib.c util/util.c util/associated.c
	cd util && make .deps

distclean: clean
	-rm config.status config.log
	-rm -r autom4te.cache
clean:
	cd discovery && make clean
	cd plugins && make clean
	cd util && make clean
	-rm $(edit_files)
	-rm plugins-stamp

$(edit_files): Makefile $@
	$(edit) '$@.in' > $@

ui/wicrawl: ui/wicrawl.in
ui/wicrawl-gtk: ui/wicrawl-gtk.in
ui/wicrawl-curses: ui/wicrawl-curses.in
plugin/plugin-eingine: plugin/plugin-engine.in
include/perl/UI/CExecute.pm: include/perl/UI/CExecute.pm.in
include/perl/UI/Common.pm: include/perl/UI/Common.pm.in
include/perl/UI/GTKExecute.pm: include/perl/UI/GTKExecute.pm.in
include/perl/UI/GTKMenubar.pm: include/perl/UI/GTKMenubar.pm.in
include/perl/UI/GTKOutput.pm: include/perl/UI/GTKOutput.pm.in
include/perl/UI/GTKWarbar.pm: include/perl/UI/GTKWarbar.pm.in

install: all
	for file in `find ui -type f ! -iname *.in`; do \
		$(install) -D $$file $(pkgdatadir)/$$file ;\
	done
	for file in `find include/perl -type f ! -iname *.in`; do \
		$(install) -D $$file $(pkgdatadir)/$$file ;\
	done
	$(install) -d $(pkgdatadir)/profiles
	$(install) profiles/*.conf $(pkgdatadir)/profiles
	for file in `find hooks -type f`; do \
		$(install) -D $$file $(pkgdatadir)/$$file;\
	done

	$(install) -d $(pkgdocdir)
	$(install) doc/* $(pkgdocdir)

	$(install) -D discovery/hashtest $(pkglibdir)/discovery/hashtest
	$(install) -D discovery/apcore $(pkglibdir)/discovery/apcore
	for plugin in `find plugins ! -iname Makefile ! -iname *.c ! -iname *.o ! -iname *.dump ! -iname *.h ! -iname README ! -iname CONTACTS ! -iname LICENCE ! -iname FAQ ! -iname INSTALL ! -iname COPYING ! -iname TODO ! -iname CHANGELOG ! -iname AUTHORS ! -iname WISHLIST ! -iname VERSION ! -iname HISTORY`; do \
		install -D $${plugin} $(pkglibdir)/$${plugin} ; \
	done
	$(install) -D ui/wicrawl $(sbindir)/wicrawl

.PHONY: all not-plugins distclean clean plugins install
