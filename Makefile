PACKAGENAME = norelaysmtpd
SNAPSHOT=0.`cat .timestamp`

DESTDIR=/
PREFIX=/usr
LIBDIR=$(PREFIX)/lib/$(PACKAGENAME)
SBINDIR=$(PREFIX)/sbin
SYSCONFDIR=/etc
MANDIR=$(PREFIX)/share/man

CC=cc
#CFLAGS=-g -Wall -DSQLITE=true
CFLAGS=-g -Wall
LDFLAGS=
#LIBS= -lsqlite3

OBJS = smtpd.o version.o
SRCS = $(OBJS:.o=.c)

#all: $(PACKAGENAME) $(PACKAGENAME).8
all: $(PACKAGENAME)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

$(PACKAGENAME): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(LIBS) $^

$(PACKAGENAME).8: $(PACKAGENAME).sgml
	docbook2man $<

install: all
	-mkdir -p $(DESTDIR)
	-mkdir -p $(DESTDIR)/$(SYSCONFDIR)
	cp $(PACKAGENAME).conf $(DESTDIR)/$(SYSCONFDIR)
	-mkdir -p $(DESTDIR)/$(LIBDIR)/$(PACKAGENAME)
	-mkdir -p $(DESTDIR)/$(SBINDIR)
	cp $(PACKAGENAME) $(DESTDIR)/$(SBINDIR)
	-mkdir -p $(DESTDIR)/$(MANDIR)/man8
	cp $(PACKAGENAME).8 $(DESTDIR)/$(MANDIR)/man8
	
clean:
	rm -f $(OBJS) $(PACKAGENAME) core Makefile.bak manpage.links manpage.refs

.timestamp:
	date --utc +%Y%m%d%H%M%S > $@
                                                                               
release:
	mkdir -p ../releases
	svn copy . `dirname ${PWD}`/releases/`cat .version`
	svn commit `dirname ${PWD}`/releases/`cat .version` -m "released version "`cat .version`" of "$(PACKAGENAME)
	rm -rf $(PACKAGENAME)-`cat .version`
	svn export ../releases/`cat .version` $(PACKAGENAME)-`cat .version`
	cat $(PACKAGENAME)-`cat .version`/$(PACKAGENAME).spec.in | sed -e "s/\@VERSION\@/`cat .version`/g" > $(PACKAGENAME)-`cat .version`/$(PACKAGENAME).spec
	tar cfz $(PACKAGENAME)-`cat .version`.tar.gz $(PACKAGENAME)-`cat .version`
	rm -rf $(PACKAGENAME)-`cat .version`

snapshot: .timestamp
	rm -rf $(PACKAGENAME)-$(SNAPSHOT)
	svn export -r HEAD . $(PACKAGENAME)-$(SNAPSHOT)
	cat $(PACKAGENAME)-$(SNAPSHOT)/$(PACKAGENAME).spec.in | sed -e "s/\@VERSION\@/$(SNAPSHOT)/g" > $(PACKAGENAME)-$(SNAPSHOT)/$(PACKAGENAME).spec
	tar cfz $(PACKAGENAME)-$(SNAPSHOT).tar.gz $(PACKAGENAME)-$(SNAPSHOT)
	rm -rf $(PACKAGENAME)-$(SNAPSHOT)
	rm -f .timestamp

depend:
	@makedepend -Y $(SRCS) 2> /dev/null > /dev/null

# DO NOT DELETE

popdns.o: config.h version.h
version.o: version.h

deb:
	strip norelaysmtpd
	cp norelaysmtpd ../package/deb/usr/local/sbin/
	sed -i ../package/deb/DEBIAN/control -e "s/^Version:.*/Version: `./norelaysmtpd -V`/"
	fakeroot dpkg-deb -b ../package/deb ../package/norelaysmtpd_`./norelaysmtpd -V`.deb

diff:
	diff -Nuw config.orig.h  config.h  > config.h.patch  || true
	diff -Nuw smtpd.orig.c   smtpd.c   > smtpd.c.patch   || true
	diff -Nuw version.orig.h version.h > version.h.patch || true
	diff -Nuw version.orig.c version.c > version.c.patch || true
