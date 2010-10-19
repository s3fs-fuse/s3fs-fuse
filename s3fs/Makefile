PACKAGE	    = s3fs
DESTDIR	    =
# prefix	    = /usr/local
prefix	    = /usr
exec_prefix = $(prefix)
man_prefix  = $(prefix)/share
mandir	    = $(man_prefix)/man
bindir	    = $(exec_prefix)/bin
sharedir    = $(prefix)/share

BINDIR	   = $(DESTDIR)$(bindir)
DOCDIR	   = $(DESTDIR)$(sharedir/doc
SHAREDIR   = $(DESTDIR)$(prefix)/share/$(PACKAGE)
LIBDIR	   = $(DESTDIR)$(prefix)/lib/$(PACKAGE)
SBINDIR	   = $(DESTDIR)$(exec_prefix)/sbin
ETCDIR	   = $(DESTDIR)/etc/$(PACKAGE)

# 1 = regular, 5 = conf, 6 = games, 8 = daemons
MANDIR	= $(DESTDIR)$(mandir)
MANDIR1	= $(MANDIR)/man1
MANDIR5	= $(MANDIR)/man5
MANDIR6	= $(MANDIR)/man6
MANDIR8	= $(MANDIR)/man8

INSTALL_OBJS_BIN   = $(PACKAGE)
INSTALL_OBJS_MAN1  = *.1
INSTALL_OBJS_SHARE =
INSTALL_OBJS_ETC   =

INSTALL	      = /usr/bin/install
INSTALL_BIN   = $(INSTALL) -m 755
INSTALL_DATA  = $(INSTALL) -m 644
INSTALL_SUID  = $(INSTALL) -m 4755

svnrev = $(shell svn log -q -l 1 | grep -e '^r[0-9]' | head -n 1 | awk '{print $$1}')

all: $(PACKAGE) 

$(PACKAGE) : $(PACKAGE).cpp
	g++ -ggdb -Wall $(shell pkg-config fuse --cflags --libs) $(shell pkg-config libcurl --cflags --libs) $(shell xml2-config --cflags --libs) -lcrypto $< -o $@ 

dist:
	tar -cvzf s3fs-$(svnrev)-source.tar.gz -C .. s3fs/COPYING s3fs/Makefile s3fs/s3fs.cpp


# When there is manual page, add this to 'install' target
install-man:
	# install-man
	$(INSTALL_BIN) -d $(MANDIR1)
	$(INSTALL_DATA) $(INSTALL_OBJS_MAN1) $(MANDIR1)

install-bin:
	# install-bin
	$(INSTALL_BIN) -d $(BINDIR)
	$(INSTALL_BIN) -s $(INSTALL_OBJS_BIN) $(BINDIR)

install: all install-bin

clean: 
	rm -f $(PACKAGE) $(PACKAGE).o
	rm -f $(PACKAGE)-r*.tar.gz
