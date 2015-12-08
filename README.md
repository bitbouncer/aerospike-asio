# aerospike-asio

This is a working but unfinished aerospike client library written as a single-threaded async boost::asio, it's based on the original aerospike libevent client

It still still needs libevent

## Windows x64 - Visual Studio 12

Get and build nessessary dependencies
```
Install Visual Studio, cmake, nasm, git and active perl manually, make sure active perl is before git in PATH

mkdir source
cd source
git clone https://github.com/bitbouncer/aerospike-asio.git
aerospike-asio\windows_x64_vc12_setup_3rd_part.bat
cd aerospike-asio
rebuild_win64_vc12.bat
cd ..
```

## Ubuntu 14 x64:

Install build tools
```
sudo apt-get update
sudo apt-get install -y automake autogen shtool libtool git wget cmake unzip build-essential g++ python-dev autotools-dev libicu-dev zlib1g-dev openssl libssl-dev libcurl4-openssl-dev libbz2-dev libcurl3 libpq-dev libevent-dev

```

Get and build necessary dependencies
```
mkdir source
cd source
git clone https://github.com/bitbouncer/aerospike-asio.git
bash aerospike-asio/linux_setup_3rd_part.sh
cd aerospike-asio
bash build_linux.sh
cd ..
```

## Centos 7 x64:

Install build tools (as root)
```
yum -y update
yum -y groupinstall 'Development Tools'
yum -y install automake autogen libtool git wget cmake unzip openssl redhat-lsb-core postgresql-devel openssl-devel bzip2-devel openldap  openldap-clients openldap-devel libidn-devel libevent-devel
```

Get and build necessary dependencies
```
mkdir source
cd source
git clone https://github.com/bitbouncer/aerospike-asio.git
bash aerospike-asio/linux_setup_3rd_part.sh
cd aerospike-asio
bash build_linux.sh
cd ..
```



