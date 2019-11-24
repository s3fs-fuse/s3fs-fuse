# Compilation from source code

These are generic instructions should work on almost any GNU/Linux, macOS, BSD, or similar.

If you want specific instructions for some distributions, check the [wiki](https://github.com/s3fs-fuse/s3fs-fuse/wiki/Installation-Notes).

Keep in mind using the pre-built packages when available.

1. Ensure your system satisfies build and runtime dependencies for:

* fuse >= 2.8.4
* automake
* gcc-c++
* make
* libcurl
* libxml2
* openssl
* pkg-config (or your OS equivalent)

2. Then compile from master via the following commands:

```
git clone https://github.com/s3fs-fuse/s3fs-fuse.git
cd s3fs-fuse
./autogen.sh
./configure
make
sudo make install
```
