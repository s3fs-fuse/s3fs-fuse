SUBDIRS=src test doc

EXTRA_DIST=doc

dist-hook:
	rm -rf `find $(distdir)/doc -type d -name .svn`
	rm -f `find $(distdir)/doc -type f -name Makefile`

release : dist ../utils/release.sh
	../utils/release.sh $(DIST_ARCHIVES)
