all:
	g++ -ggdb -Wall $(shell pkg-config fuse --cflags --libs) $(shell pkg-config libcurl --cflags --libs) $(shell xml2-config --cflags --libs) -lcrypto s3fs.cpp -o s3fs
	@echo ok!

clean:
	rm -f s3fs s3fs.o
