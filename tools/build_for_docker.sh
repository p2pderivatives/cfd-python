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

pip3 wheel .
if [ $? -gt 0 ]; then
  echo "cmake build NG."
  exit 1
fi

VER=`cat VERSION`

mv ./*.whl $BASEDIR/cfd-$VER-py3-none-linux_x86_64.whl
rm -rf $BASEDIR/integration_test/*.whl
cp $BASEDIR/cfd-$VER-py3-none-linux_x86_64.whl $BASEDIR/integration_test/cfd-$VER-py3-none-linux_x86_64.whl
