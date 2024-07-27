# Compilation from source code

These are generic instructions should work on almost any GNU/Linux, macOS, BSD, or similar.

If you want specific instructions for some distributions, check the [wiki](https://github.com/s3fs-fuse/s3fs-fuse/wiki/Installation-Notes).

Keep in mind using the pre-built packages when available.

## Compilation on Linux

### Ensure your system satisfies build and runtime dependencies for:

* fuse >= 2.8.4
* automake
* gcc-c++
* make
* libcurl
* libxml2
* openssl/gnutls/nss
    * Please prepare the library according to the OS on which you will compile.
    * It is necessary to match the library used by libcurl.
    * Install the OpenSSL, GnuTLS or NSS devel package.
* mime.types (the package providing depends on the OS)
	* s3fs tries to detect `/etc/mime.types` as default regardless of the OS
	* Else s3fs tries to detect `/etc/apache2/mime.types` if OS is macOS
	* s3fs exits with an error if these files are not exist
	* Alternatively, you can set mime.types file path with `mime` option without detecting these default files
* pkg-config (or your OS equivalent)

* NOTE  
    If you have any trouble about details on required packages, see `INSTALL_PACKAGES` in [linux-ci-helper.sh](https://github.com/s3fs-fuse/s3fs-fuse/blob/master/.github/workflows/linux-ci-helper.sh).

### Then compile from master via the following commands:
1. Clone the source code:
    ```sh
    git clone https://github.com/s3fs-fuse/s3fs-fuse.git
    ```
2. Configuration:
    ```sh
    cd s3fs-fuse
    ./autogen.sh
    ./configure
    ```
    Depending on the TLS library (OpenSSL/GnuTLS/NSS), add `--with-openssl`, `--with-gnutls` or `--with-nss` when executing `configure`. (If omitted, it is equivalent to `--with-openssl`.)
3. Building:
    ```sh
    make
    ```
4. Installing:
    ```sh
    sudo make install
    ```

### NOTE - The required libraries/components required to run s3fs are:

* fuse >= 2.8.4
* libcurl
* libxml2
* openssl/gnutls/nss
* mime.types (the package providing depends on the OS)


## Compilation on Windows (using MSYS2)

On Windows, use [MSYS2](https://www.msys2.org/) to compile for itself.

1. Install [WinFsp](https://github.com/billziss-gh/winfsp) to your machine.
2. Install dependencies onto MSYS2:

   ```sh
   pacman -S git autoconf automake gcc make pkg-config openssl-devel libcurl-devel libxml2-devel libzstd-devel
   ```

3. Clone this repository, then change directory into the cloned one.
4. Copy WinFsp files to the directory:

   ```sh
   cp -r "/c/Program Files (x86)/WinFsp" "./WinFsp"
   ```

5. Write `fuse.pc` to resolve the package correctly:

   ```sh
   cat > ./fuse.pc << 'EOS'
   arch=x64
   prefix=${pcfiledir}/WinFsp
   incdir=${prefix}/inc/fuse
   implib=${prefix}/bin/winfsp-${arch}.dll

   Name: fuse
   Description: WinFsp FUSE compatible API
   Version: 2.8.4
   URL: http://www.secfs.net/winfsp/
   Libs: "${implib}"
   Cflags: -I"${incdir}"
   EOS
   ```

6. Compile using the command line:

   ```sh
   ./autogen.sh
   PKG_CONFIG_PATH="$PKG_CONFIG_PATH:$(pwd)" ./configure
   make CXXFLAGS="-I/usr/include"
   ```

7. Copy binary files to distribute at one place:

   ```sh
   mkdir ./bin
   cp ./src/s3fs.exe ./bin/
   cp ./WinFsp/bin/winfsp-x64.dll ./bin/
   cp /usr/bin/msys-*.dll ./bin/
   ```

8. Distribute these files.
