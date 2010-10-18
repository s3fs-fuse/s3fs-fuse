all: s3fs

s3fs : s3fs.cpp
	g++ -ggdb -Wall $(shell pkg-config fuse --cflags --libs) $(shell pkg-config libcurl --cflags --libs) $(shell xml2-config --cflags --libs) -lcrypto s3fs.cpp -o s3fs

install: all
	cp -f s3fs /usr/bin
	
dist: all
	tar -cvzf s3fs.tar.gz -C .. s3fs/COPYING s3fs/Makefile s3fs/s3fs.cpp
	
clean:
	rm -f s3fs s3fs.o
