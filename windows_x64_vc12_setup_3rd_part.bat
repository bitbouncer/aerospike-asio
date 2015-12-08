REM need separate installation of git, nasm, active perl & visual studio
REM make sure that active perl is before any other perl - git's for example in PATH

set VISUALSTUDIO_VERSION=12.0
set VISUALSTUDIO_VERSION_MAJOR=12
set BOOST_VERSION=1_59_0
set BOOST_VERSION_DOTTED=1.59.0
set OPEN_SSL_VERSION=openssl-1.0.1j
set ZLIB_VERSION=1.2.8
set LIBEVENT_VERSION=2.0.21
set PTHREAD_VERSION=2-9-1

call "C:\Program Files (x86)\Microsoft Visual Studio %VISUALSTUDIO_VERSION%\VC\vcvarsall.bat" amd64

wget http://sourceforge.net/projects/boost/files/boost/%BOOST_VERSION_DOTTED%/boost_%BOOST_VERSION%.tar.gz/download -Oboost_%BOOST_VERSION%.tar.gz
gunzip boost_%BOOST_VERSION%.tar.gz
tar xf boost_%BOOST_VERSION%.tar
del boost_%BOOST_VERSION%.tar

wget --no-check-certificate https://github.com/libevent/libevent/archive/release-%LIBEVENT_VERSION%-stable.tar.gz -Olibevent-%LIBEVENT_VERSION%-stable.tar.gz
gunzip libevent-%LIBEVENT_VERSION%-stable.tar.gz
tar xf libevent-%LIBEVENT_VERSION%-stable.tar
del libevent-%LIBEVENT_VERSION%-stable.tar

wget  http://www.openssl.org/source/%OPEN_SSL_VERSION%.tar.gz 
gunzip %OPEN_SSL_VERSION%.tar.gz
tar xf %OPEN_SSL_VERSION%.tar
del %OPEN_SSL_VERSION%.tar
rmdir /s /q %OPEN_SSL_VERSION%\include

wget ftp://sourceware.org/pub/pthreads-win32/pthreads-w32-%PTHREAD_VERSION%-release.tar.gz
gunzip pthreads-w32-%PTHREAD_VERSION%-release.tar.gz
tar xf pthreads-w32-%PTHREAD_VERSION%-release.tar
del pthreads-w32-%PTHREAD_VERSION%-release.tar

wget http://zlib.net/zlib-%ZLIB_VERSION%.tar.gz
gunzip zlib-%ZLIB_VERSION%.tar.gz
tar xf zlib-%ZLIB_VERSION%.tar
del zlib-%ZLIB_VERSION%.tar

@ECHO BUILDING OPEN_SSL
cd %OPEN_SSL_VERSION%
start /WAIT perl Configure VC-WIN64A --prefix=/OpenSSL-Win64
call ms\do_win64a
nmake -f ms\nt.mak
mkdir include
xcopy /e /s inc32\* include
cd ..

@ECHO BUILDING ZLIB
cd zlib-%ZLIB_VERSION%
nmake -f win32/Makefile.msc
cd ..

@ECHO BUILDING PTHREADS
cd pthreads-w32-%PTHREAD_VERSION%-release
#nmake clean VC-static-debug
#nmake clean VC-static
#test
nmake clean VC
nmake clean VC-debug
cd ..

@ECHO BUILDING BOOST
cd boost_%BOOST_VERSION%
rmdir /s /q bin.v2
REM call "C:\Program Files (x86)\Microsoft Visual Studio %VISUALSTUDIO_VERSION%\VC\vcvarsall.bat" amd64
call bootstrap.bat
#b2 -j 4 -toolset=msvc-%VISUALSTUDIO_VERSION% address-model=64 --build-type=complete --stagedir=lib\x64 stage -s ZLIB_INCLUDE=%CD%\..\zlib-%ZLIB_VERSION% -s ZLIB_LIBPATH=%CD%\..\zlib-%ZLIB_VERSION%
b2 -j 8 -toolset=msvc-%VISUALSTUDIO_VERSION% address-model=64 --build-type=complete --stagedir=lib\x64 stage -s ZLIB_SOURCE=%CD%\..\zlib-%ZLIB_VERSION%
rmdir /s /q bin.v2
cd ..
