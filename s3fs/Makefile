all:
	g++ -Wall $(shell pkg-config fuse --cflags --libs) -lcurl $(shell xml2-config --cflags --libs) -lssl -ggdb s3fs.cpp -o s3fs
	@echo ok!

clean:
	rm -f s3fs s3fs.o
