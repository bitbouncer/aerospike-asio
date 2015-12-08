export BOOST_VERSION=1_59_0
export BOOST_VERSION_DOTTED=1.59.0

wget http://sourceforge.net/projects/boost/files/boost/$BOOST_VERSION_DOTTED/boost_$BOOST_VERSION.tar.gz/download -Oboost_$BOOST_VERSION.tar.gz
tar xf boost_$BOOST_VERSION.tar.gz
rm -f boost_$BOOST_VERSION.tar.gz

cd boost_$BOOST_VERSION
./bootstrap.sh
./b2 -j 8
cd ..

