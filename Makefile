PACKAGENAME = norelaysmtpd
SNAPSHOT=0.`cat .timestamp`

DESTDIR=/
PREFIX=$(DESTDIR)usr/local
SBINDIR=$(PREFIX)/sbin
SYSCONFDIR=/etc
MANDIR=$(PREFIX)/share/man

CC=cc
DEBUG = 0
ifeq ($(MAKECMDGOALS),run-local)
override DEBUG = 1
endif
ENABLE_SQLITE=0

CFLAGS=-Wall
LDFLAGS=
ifeq ($(DEBUG),1)
 CFLAGS += -g -DSYSLOG_IS_STDERR
endif
ifeq ($(ENABLE_SQLITE),1)
 CFLAGS += -DSQLITE
 LDFLAGS += -lsqlite3
endif

OBJS = smtpd.o version.o
SRCS = $(OBJS:.o=.c)

.PHONY: all
#all: $(PACKAGENAME) $(PACKAGENAME).8
all: $(PACKAGENAME)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

$(PACKAGENAME): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(LIBS) $^

.PHONY: clean
clean:
	rm -f $(OBJS) $(PACKAGENAME) core Makefile.bak manpage.links manpage.refs

.timestamp:
	date --utc +%Y%m%d%H%M%S > $@

.PHONY: release
release:
	mkdir -p ../releases
	svn copy . `dirname ${PWD}`/releases/`cat .version`
	svn commit `dirname ${PWD}`/releases/`cat .version` -m "released version "`cat .version`" of "$(PACKAGENAME)
	rm -rf $(PACKAGENAME)-`cat .version`
	svn export ../releases/`cat .version` $(PACKAGENAME)-`cat .version`
	cat $(PACKAGENAME)-`cat .version`/$(PACKAGENAME).spec.in | sed -e "s/\@VERSION\@/`cat .version`/g" > $(PACKAGENAME)-`cat .version`/$(PACKAGENAME).spec
	tar cfz $(PACKAGENAME)-`cat .version`.tar.gz $(PACKAGENAME)-`cat .version`
	rm -rf $(PACKAGENAME)-`cat .version`

.PHONY: snapshot
snapshot: .timestamp
	rm -rf $(PACKAGENAME)-$(SNAPSHOT)
	svn export -r HEAD . $(PACKAGENAME)-$(SNAPSHOT)
	cat $(PACKAGENAME)-$(SNAPSHOT)/$(PACKAGENAME).spec.in | sed -e "s/\@VERSION\@/$(SNAPSHOT)/g" > $(PACKAGENAME)-$(SNAPSHOT)/$(PACKAGENAME).spec
	tar cfz $(PACKAGENAME)-$(SNAPSHOT).tar.gz $(PACKAGENAME)-$(SNAPSHOT)
	rm -rf $(PACKAGENAME)-$(SNAPSHOT)
	rm -f .timestamp

.PHONY: depend
depend:
	@makedepend -Y $(SRCS) 2> /dev/null > /dev/null

# DO NOT DELETE

popdns.o: config.h version.h
version.o: version.h

.PHONY: install-local
install-local: $(SBINDIR)/$(PACKAGENAME) $(SYSCONFDIR)/$(PACKAGENAME).conf $(MANDIR)/man8/$(PACKAGENAME).8.gz

$(SBINDIR)/$(PACKAGENAME): $(PACKAGENAME)
	mkdir -p $(dir $@)
	install $< $@

$(MANDIR)/man8/$(PACKAGENAME).8.gz: smtpd.8
	mkdir -p $(dir $@)
	cat $< | gzip > $@~
	mv $@~ $@

# do not overwrite config file if already exists
$(SYSCONFDIR)/$(PACKAGENAME).conf:
	mkdir -p $(dir $@)
	cp smtpd.conf $@

.PHONY: uninstall-local
uninstall-local:
	-rm $(SBINDIR)/$(PACKAGENAME) \
	    $(SYSCONFDIR)/$(PACKAGENAME).conf \
	    $(MANDIR)/man8/$(PACKAGENAME).8.gz

.PHONY: run-local
run-local: clean $(PACKAGENAME)
	REMOTE_HOST=127.0.0.1 rlwrap ./$(PACKAGENAME) -c smtpd-run-local.conf
