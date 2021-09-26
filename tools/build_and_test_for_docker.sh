#!/bin/sh

if [ -n "$CFD_SRC" ]; then
BASEDIR=$CFD_SRC
else
BASEDIR=`git rev-parse --show-toplevel`
fi

if [ -z "$BASEDIR" ]; then
exit 1
fi

cd $BASEDIR

if [ -n "$CFD_WORK" ]; then
WORKDIR=$CFD_WORK
else
WORKDIR=temp
fi

echo "BASEDIR=$BASEDIR"
echo "WORKDIR=$WORKDIR"

if [ -z "$WORKDIR" ]; then
exit 1
fi

rm -rf $WORKDIR/*
mkdir $WORKDIR
mkdir $WORKDIR/external
mkdir $WORKDIR/dist

cp CMakeLists.txt $WORKDIR/
cp VERSION $WORKDIR/
cp LICENSE $WORKDIR/
cp setup.* $WORKDIR/
cp *.toml $WORKDIR/
cp *.in $WORKDIR/
cp *.md $WORKDIR/
cp -rp cmake $WORKDIR/cmake
cp -rp external/CMakeLists.txt $WORKDIR/external
cp -rp external/template_CMakeLists.txt.in $WORKDIR/external
cp -rp local_resource $WORKDIR/local_resource
cp -rp cfd $WORKDIR/cfd
cp -rp tools $WORKDIR/tools
cp -rp tests $WORKDIR/tests
cp -rp tests $WORKDIR/tests

cd $WORKDIR
if [ $? -gt 0 ]; then
  echo "change directory NG."
  exit 1
fi

echo "configure start."

PATH=$PATH:/usr/local/bin

pip3 install wheel pipenv
if [ $? -gt 0 ]; then
  echo "pip3 install NG."
  exit 1
fi

pipenv install -d
if [ $? -gt 0 ]; then
  echo "pipenv install NG."
  exit 1
fi

# pipenv run build
python3 ./setup.py build
if [ $? -gt 0 ]; then
  echo "cmake build NG."
  exit 1
fi

# pipenv run test
python3 -m unittest discover -v tests
if [ $? -gt 0 ]; then
  echo "test NG."
  exit 1
fi
