#!/bin/bash -u

# while :; do sleep 10; done
export WORKDIR_ROOT=github
export WORK_DIR=workspace
export WORKDIR_PATH=/${WORKDIR_ROOT}/${WORK_DIR}

cd /${WORKDIR_ROOT}
if [ ! -d ${WORK_DIR} ]; then
  mkdir ${WORK_DIR}
fi

cd ${WORKDIR_PATH}
rm -rf bitcoind_datadir

mkdir bitcoind_datadir
chmod 777 bitcoind_datadir
# cp /root/.bitcoin/bitcoin.conf bitcoind_datadir/
cp ./integration_test/bitcoin.conf bitcoind_datadir/

# boot daemon
bitcoind --regtest -datadir=${WORKDIR_PATH}/bitcoind_datadir
bitcoin-cli --regtest -datadir=${WORKDIR_PATH}/bitcoind_datadir ping > /dev/null 2>&1
while [ $? -ne 0 ]
do
  bitcoin-cli --regtest -datadir=${WORKDIR_PATH}/bitcoind_datadir ping > /dev/null 2>&1
done
echo "start bitcoin node"

# load or create wallet
bitcoin-cli --regtest -datadir=${WORKDIR_PATH}/bitcoind_datadir createwallet wallet

set -e

python3 --version

pip3 install *.whl
pip3 install python-bitcoinrpc

cd integration_test

python3 tests/test_bitcoin.py -v
if [ $? -gt 0 ]; then
  cd ../..
  exit 1
fi
