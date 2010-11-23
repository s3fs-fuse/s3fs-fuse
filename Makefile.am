SUBDIRS=src test

release : dist 
	MD5SUM=`md5sum $(DIST_ARCHIVES) | awk '{print $$1}'`
	if test -d "../tarballs"; then \
	   cp $(DIST_ARCHIVES) ../tarballs;\
	   cd ../tarballs;\
	   ln -f -s  $(DIST_ARCHIVES) latest;\
	fi;
	if test -w "../wiki/InstallationNotes.wiki"; then \
	   sed -i -e "/Download:/s/s3fs-.*.gz/$(DIST_ARCHIVES)/" ../wiki/InstallationNotes.wiki ;\
	   sed -i -e "/ checksum:/s/ checksum:.*/ checksum: `sha1sum $(DIST_ARCHIVES) | awk '{print $$1}'`/" ../wiki/InstallationNotes.wiki ;\
	   sed -i -e "/ size:/s/ size:.*/ size: `/bin/ls -l $(DIST_ARCHIVES) | awk '{print $$5}'`/" ../wiki/InstallationNotes.wiki ;\
	   sed -i -e "/tar xvzf/s/s3fs-.*.gz/$(DIST_ARCHIVES)/" ../wiki/InstallationNotes.wiki ;\
	   sed -i -e "/cd s3fs/s/s3fs-.*/$(DIST_ARCHIVES)/" ../wiki/InstallationNotes.wiki ;\
	   sed -i -e "/cd s3fs/s/.tar.gz/\//" ../wiki/InstallationNotes.wiki ;\
	fi;
	cat ../wiki/InstallationNotes.wiki

