SUBDIRS=src test doc

EXTRA_DIST=doc

dist-hook:
	rm -rf `find $(distdir)/doc -type d -name .svn`

release : dist ../utils/release.sh
	../utils/release.sh $(DIST_ARCHIVES)
