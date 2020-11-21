# cfd-python integration test

## use app

   python-bitcoinrpc: lightweight rpc tool

## execute test

### install pipenv

    ```
    pip install --user pipenv
    ```

### setup pipenv

    use pipenv
    ```
    pipenv install

    (for developer):
    pipenv install -d
    ```

### install cfd

    1. create wheel file
    2. move to current directory
    3. `pipenv run pip_install (wheel file path)`

### run bitcoind & elementsd

    ```
    rm -rf localdata
    mkdir localdata
    mkdir localdata/bitcoind_datadir
    cp bitcoin.conf localdata/bitcoind_datadir/
    bitcoind --regtest -datadir=localdata/bitcoind_datadir

    mkdir localdata/elementsd_datadir
    cp elements.conf localdata/elementsd_datadir/
    elementsd --regtest -datadir=localdata/elementsd_datadir
    ```

### run test

    1. `pipenv run test` or `pipenv run test3`

### after test

    ```
    elements-cli -datadir=localdata/elementsd_datadir stop
    bitcoin-cli -datadir=localdata/elementsd_datadir stop
    ```

---

## Using docker (for Ubuntu)

   ```
   (need wheel file on this folder.)
   docker-compose build
   docker-compose up
   ```

