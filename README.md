s3fs
====

s3fs allows Linux and Mac OS X to mount an S3 bucket via FUSE.
s3fs preserves the native object format for files, allowing use of other tools like [s3cmd](http://s3tools.org/s3cmd).  
[![Build Status](https://travis-ci.org/s3fs-fuse/s3fs-fuse.svg?branch=master)](https://travis-ci.org/s3fs-fuse/s3fs-fuse)

Features
--------

* large subset of POSIX including reading/writing files, directories, symlinks, mode, uid/gid, and extended attributes
* compatible with Amazon S3, Google Cloud Storage, and other S3-based object stores
* large files via multi-part upload
* renames via server-side copy
* optional server-side encryption
* data integrity via MD5 hashes
* in-memory metadata caching
* local disk data caching
* user-specified regions, including Amazon GovCloud
* authenticate via v2 or v4 signatures

Installation
------------

Ensure you have all the dependencies:

On Ubuntu 14.04:

```
sudo apt-get install automake autotools-dev g++ git libcurl4-gnutls-dev libfuse-dev libssl-dev libxml2-dev make pkg-config
```

On CentOS 7:

```
sudo yum install automake fuse fuse-devel gcc-c++ git libcurl-devel libxml2-devel make openssl-devel
```

Compile from master via the following commands:

```
git clone https://github.com/s3fs-fuse/s3fs-fuse.git
cd s3fs-fuse
./autogen.sh
./configure
make
sudo make install
```

Examples
--------

Enter your S3 identity and credential in a file `/path/to/passwd`:

```
echo MYIDENTITY:MYCREDENTIAL > /path/to/passwd
```

Make sure the file has proper permissions (if you get 'permissions' error when mounting) `/path/to/passwd`:

```
chmod 600 /path/to/passwd
```

Run s3fs with an existing bucket `mybucket` and directory `/path/to/mountpoint`:

```
s3fs mybucket /path/to/mountpoint -o passwd_file=/path/to/passwd
```

If you encounter any errors, enable debug output:

```
s3fs mybucket /path/to/mountpoint -o passwd_file=/path/to/passwd -d -d -f -o f2 -o curldbg
```

You can also mount on boot by entering the following line to `/etc/fstab`:

```
s3fs#mybucket /path/to/mountpoint fuse _netdev,allow_other 0 0

or

mybucket /path/to/mountpoint fuse.s3fs _netdev,allow_other 0 0
```

Note: You may also want to create the global credential file first

```
echo MYIDENTITY:MYCREDENTIAL > /etc/passwd-s3fs
chmod 600 /etc/passwd-s3fs
```

Note2: You may also need to make sure `netfs` service is start on boot


Limitations
-----------

Generally S3 cannot offer the same performance or semantics as a local file system.  More specifically:

* random writes or appends to files require rewriting the entire file
* metadata operations such as listing directories have poor performance due to network latency
* [eventual consistency](https://en.wikipedia.org/wiki/Eventual_consistency) can temporarily yield stale data
* no atomic renames of files or directories
* no coordination between multiple clients mounting the same bucket
* no hard links

References
----------

* [goofys](https://github.com/kahing/goofys) - similar to s3fs but has better performance and less POSIX compatibility
* [s3backer](https://github.com/archiecobbs/s3backer) - mount an S3 bucket as a single file
* [s3fs-python](https://fedorahosted.org/s3fs/) - an older and less complete implementation written in Python
* [S3Proxy](https://github.com/andrewgaul/s3proxy) - combine with s3fs to mount EMC Atmos, Microsoft Azure, and OpenStack Swift buckets
* [s3ql](https://bitbucket.org/nikratio/s3ql/) - similar to s3fs but uses its own object format
* [YAS3FS](https://github.com/danilop/yas3fs) - similar to s3fs but uses SNS to allow multiple clients to mount a bucket

Frequently Asked Questions
--------------------------
* [FAQ wiki page](https://github.com/s3fs-fuse/s3fs-fuse/wiki/FAQ)

License
-------

Copyright (C) 2010 Randy Rizun <rrizun@gmail.com>

Licensed under the GNU GPL version 2
