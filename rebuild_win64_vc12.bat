@ECHO OFF

REM git describe --always

rmdir /S /Q bin\x64
rmdir /S /Q lib\x64
rmdir /S /Q build64

ECHO ===== CMake for 64-bit ======
call "C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\vcvarsall.bat" amd64
mkdir build64 
cd build64
del CMakeCache.txt
cmake -G "Visual Studio 12 Win64" ..
msbuild ALL_BUILD.vcxproj /p:Configuration=Debug /p:Platform=x64 /maxcpucount:12
msbuild ALL_BUILD.vcxproj /p:Configuration=Release /p:Platform=x64 /maxcpucount:12
cd ..

