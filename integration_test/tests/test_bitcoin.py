import unittest
from helper import RpcWrapper, get_utxo
from cfd.address import AddressUtil
from cfd.key import SchnorrUtil, SigHashType, SchnorrPubkey, SignParameter
from cfd.hdwallet import HDWallet
from cfd.script import HashType, Script
from cfd.descriptor import parse_descriptor
from cfd.psbt import Psbt, PsbtAppendInputData, PsbtAppendOutputData
from cfd.taproot import TaprootScriptTree, TapBranch
from cfd.transaction import OutPoint, Transaction, TxIn, TxOut, UtxoData
from decimal import Decimal
from typing import List
import logging
import time

MNEMONIC = [
    'clerk', 'zoo', 'mercy', 'board', 'grab', 'service', 'impact', 'tortoise',
    'step', 'crash', 'load', 'aerobic', 'suggest', 'rack', 'refuse', 'can',
    'solve', 'become', 'upset', 'jump', 'token', 'anchor', 'apart', 'dog']
PASSPHRASE = 'Unx3HmdQ'
NETWORK = 'regtest'
ROOT_PATH = 'm/44h/0h/0h'
FEE_PATH = ROOT_PATH + '/1/0'
BTC_AMOUNT = 100000000
BTC_AMOUNT_BIT = 8


def convert_bitcoin_utxos(test_obj, utxo_list) -> List['UtxoData']:
    # {"txid": "f3c8453e1bda1366bc859532e27a829c8ce623b766ae699a0377b168993c44b5", "vout": 0, "address": "bcrt1qyq7xhec45m75m5nvhzuh47vsj3as7tqf8t8vkr", "label": "test_fee", "scriptPubKey": "0014203c6be715a6fd4dd26cb8b97af990947b0f2c09", "amount": 50.0, "confirmations": 101, "spendable": false, "solvable": false, "safe": true}  # noqa8
    utxos: List['UtxoData'] = []
    for utxo in utxo_list:
        desc = test_obj.desc_dic[utxo['address']]
        value = Decimal(str(utxo['amount']))
        value = value * BTC_AMOUNT
        data = UtxoData(txid=utxo['txid'], vout=utxo['vout'],
                        amount=int(value), descriptor=desc)
        utxos.append(data)
    return utxos


def search_utxos(test_obj, utxo_list, outpoint):
    for utxo in utxo_list:
        if utxo.outpoint == outpoint:
            return utxo
    test_obj.assertTrue(False, 'UTXO is empty. outpoint={}'.format(outpoint))


def create_bitcoin_address(test_obj: 'TestBitcoin'):
    root_pk = test_obj.hdwallet.ext_privkey.get_extpubkey().pubkey
    fp = root_pk.get_fingerprint()
    # fee address
    pk = str(test_obj.hdwallet.get_pubkey(path=FEE_PATH).pubkey)
    addr = AddressUtil.p2wpkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = FEE_PATH
    test_obj.addr_dic['fee'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'wpkh([{}{}]{})'.format(str(fp), FEE_PATH[1:], str(pk)),
        network=NETWORK)
    print('set fee addr: ' + str(addr))

    # wpkh main address
    path = '{}/0/0'.format(ROOT_PATH)
    pk = str(test_obj.hdwallet.get_pubkey(path=path).pubkey)
    addr = AddressUtil.p2wpkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = path
    test_obj.addr_dic['main'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'wpkh([{}{}]{})'.format(str(fp), path[1:], str(pk)),
        network=NETWORK)
    print('set main addr: ' + str(addr))
    # pkh address
    path = '{}/0/1'.format(ROOT_PATH)
    pk = str(test_obj.hdwallet.get_pubkey(path=path).pubkey)
    addr = AddressUtil.p2pkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = path
    test_obj.addr_dic['p2pkh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'pkh([{}{}]{})'.format(str(fp), path[1:], str(pk)),
        network=NETWORK)
    print('set p2pkh addr: ' + str(addr))
    # wpkh address
    path = '{}/0/2'.format(ROOT_PATH)
    pk = str(test_obj.hdwallet.get_pubkey(path=path).pubkey)
    addr = AddressUtil.p2wpkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = path
    test_obj.addr_dic['p2wpkh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'wpkh([{}{}]{})'.format(str(fp), path[1:], str(pk)),
        network=NETWORK)
    print('set p2wpkh addr: ' + str(addr))
    # p2sh-p2wpkh address
    path = '{}/0/3'.format(ROOT_PATH)
    pk = str(test_obj.hdwallet.get_pubkey(path=path).pubkey)
    addr = AddressUtil.p2sh_p2wpkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = path
    test_obj.addr_dic['p2sh-p2wpkh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'sh(wpkh([{}{}]{}))'.format(str(fp), path[1:], str(pk)),
        network=NETWORK)
    print('set p2sh-p2wpkh addr: ' + str(addr))

    # multisig_key
    path = '{}/0/'.format(ROOT_PATH)
    path_list = [path + str(i + 1) for i in range(3)]
    pk1 = str(test_obj.hdwallet.get_pubkey(path=path_list[0]).pubkey)
    pk2 = str(test_obj.hdwallet.get_pubkey(path=path_list[1]).pubkey)
    pk3 = str(test_obj.hdwallet.get_pubkey(path=path_list[2]).pubkey)
    pk_list = [pk1, pk2, pk3]
    req_num = 2
    desc_multi = 'multi({},{},{},{})'.format(req_num, pk1, pk2, pk3)
    addr = AddressUtil.multisig(
        req_num, pk_list, HashType.P2SH, network=NETWORK)
    test_obj.path_dic[str(addr)] = path_list
    test_obj.addr_dic['p2sh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'sh({})'.format(desc_multi), network=NETWORK)
    print('set p2sh addr: ' + str(addr))
    addr = AddressUtil.multisig(
        req_num, pk_list, HashType.P2WSH, network=NETWORK)
    test_obj.path_dic[str(addr)] = path_list
    test_obj.addr_dic['p2wsh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'wsh({})'.format(desc_multi), network=NETWORK)
    print('set p2wsh addr: ' + str(addr))
    addr = AddressUtil.multisig(
        req_num, pk_list, HashType.P2SH_P2WSH, network=NETWORK)
    test_obj.path_dic[str(addr)] = path_list
    test_obj.addr_dic['p2sh-p2wsh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'sh(wsh({}))'.format(desc_multi), network=NETWORK)
    print('set p2sh-p2wsh addr: ' + str(addr))


def test_import_address(test_obj: 'TestBitcoin'):
    btc_rpc = test_obj.conn.get_rpc()
    # fee address
    btc_rpc.importaddress(str(test_obj.addr_dic['fee']), 'test_fee', False)
    # pkh address
    btc_rpc.importaddress(str(test_obj.addr_dic['main']), 'test_main', False)
    btc_rpc.importaddress(str(test_obj.addr_dic['p2pkh']), 'test_pkh', False)
    btc_rpc.importaddress(str(test_obj.addr_dic['p2wpkh']), 'test_wpkh', False)
    btc_rpc.importaddress(
        str(test_obj.addr_dic['p2sh-p2wpkh']), 'test_sh_wpkh', False)
    # multisig_key
    btc_rpc.importaddress(str(test_obj.addr_dic['p2sh']), 'test_sh', False)
    btc_rpc.importaddress(str(test_obj.addr_dic['p2wsh']), 'test_wsh', False)
    btc_rpc.importaddress(
        str(test_obj.addr_dic['p2sh-p2wsh']), 'test_sh_wsh', False)


def test_generate(test_obj: 'TestBitcoin'):
    # generatetoaddress -> fee addresss
    print(test_obj.addr_dic)
    btc_rpc = test_obj.conn.get_rpc()
    addr = str(test_obj.addr_dic['fee'])
    btc_rpc.generatetoaddress(100, addr)
    btc_rpc.generatetoaddress(5, addr)
    time.sleep(2)
    resp = get_utxo(btc_rpc, [addr])
    print(resp)


def test_bitcoin_pkh(test_obj: 'TestBitcoin'):
    btc_rpc = test_obj.conn.get_rpc()
    # create tx (output wpkh, p2sh-segwit, pkh)
    txouts = [
        TxOut(100000000, str(test_obj.addr_dic['p2pkh'])),
        TxOut(100000000, str(test_obj.addr_dic['p2wpkh'])),
        TxOut(100000000, str(test_obj.addr_dic['p2sh-p2wpkh'])),
    ]
    tx = Transaction.create(2, 0, [], txouts)
    # fundrawtransaction
    fee_addr = str(test_obj.addr_dic['fee'])
    fee_desc = test_obj.desc_dic[fee_addr]
    fee_sk = test_obj.hdwallet.get_privkey(path=FEE_PATH).privkey
    utxos = get_utxo(btc_rpc, [fee_addr])
    utxo_list = convert_bitcoin_utxos(test_obj, utxos)
    tx.fund_raw_transaction([], utxo_list, fee_addr,
                            target_amount=0, effective_fee_rate=20.0,
                            knapsack_min_change=1)
    # add sign
    for txin in tx.txin_list:
        utxo = search_utxos(test_obj, utxo_list, txin.outpoint)
        tx.sign_with_privkey(txin.outpoint, fee_desc.data.hash_type, fee_sk,
                             amount=utxo.amount,
                             sighashtype=SigHashType.ALL)
    # broadcast
    print(Transaction.parse_to_json(str(tx), network=NETWORK))
    btc_rpc.sendrawtransaction(str(tx))
    # generate block
    btc_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)

    # create tx (output wpkh only, input tx1-3)
    txid = tx.txid
    txin_list = []
    txin_utxo_list = []
    for index, txout in enumerate(tx.txout_list):
        temp_addr = str(txout.get_address(network=NETWORK))
        if temp_addr == fee_addr:
            continue
        txin_list.append(TxIn(txid=txid, vout=index))
        if temp_addr not in test_obj.desc_dic:
            test_obj.assertTrue(False, 'addr not found. [{}]:[{}]'.format(
                index, temp_addr))
        desc = test_obj.desc_dic[temp_addr]
        txin_utxo_list.append(UtxoData(
            txid=txid, vout=index, amount=txout.amount, descriptor=desc))
    txouts2 = [
        TxOut(300000000, str(test_obj.addr_dic['main'])),
    ]
    tx2 = Transaction.create(2, 0, txin_list, txouts2)
    main_addr = test_obj.addr_dic['main']
    utxos = get_utxo(btc_rpc, [fee_addr])
    utxo_list = convert_bitcoin_utxos(test_obj, utxos)
    tx2.fund_raw_transaction(txin_utxo_list, utxo_list, fee_addr,
                             target_amount=0, effective_fee_rate=20.0,
                             knapsack_min_change=1)
    # add sign
    join_utxo_list: List['UtxoData'] = []
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = utxo_list
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = txin_utxo_list
    for txin in tx2.txin_list:
        utxo = search_utxos(test_obj, join_utxo_list, txin.outpoint)
        path = str(test_obj.path_dic[str(utxo.descriptor.data.address)])
        sk = test_obj.hdwallet.get_privkey(path=path).privkey
        tx2.sign_with_privkey(txin.outpoint, utxo.descriptor.data.hash_type,
                              sk, amount=utxo.amount,
                              sighashtype=SigHashType.ALL)
    # broadcast
    print(Transaction.parse_to_json(str(tx2), network=NETWORK))
    btc_rpc.sendrawtransaction(str(tx2))
    # generate block
    btc_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)
    utxos = get_utxo(btc_rpc, [str(main_addr)])
    print('UTXO: {}'.format(utxos))


def test_bitcoin_multisig(test_obj: 'TestBitcoin'):
    btc_rpc = test_obj.conn.get_rpc()
    # create tx (output multisig)
    txouts = [
        TxOut(100000000, str(test_obj.addr_dic['p2sh'])),
        TxOut(100000000, str(test_obj.addr_dic['p2wsh'])),
        TxOut(100000000, str(test_obj.addr_dic['p2sh-p2wsh'])),
    ]
    tx = Transaction.create(2, 0, [], txouts)
    # fundrawtransaction
    fee_addr = str(test_obj.addr_dic['fee'])
    fee_desc = test_obj.desc_dic[fee_addr]
    fee_sk = test_obj.hdwallet.get_privkey(path=FEE_PATH).privkey
    utxos = get_utxo(btc_rpc, [fee_addr])
    utxo_list = convert_bitcoin_utxos(test_obj, utxos)
    tx.fund_raw_transaction([], utxo_list, fee_addr,
                            target_amount=0, effective_fee_rate=20.0,
                            knapsack_min_change=1)
    # add sign
    for txin in tx.txin_list:
        utxo = search_utxos(test_obj, utxo_list, txin.outpoint)
        tx.sign_with_privkey(txin.outpoint, fee_desc.data.hash_type, fee_sk,
                             amount=utxo.amount,
                             sighashtype=SigHashType.ALL)
    # broadcast
    print(Transaction.parse_to_json(str(tx), network=NETWORK))
    btc_rpc.sendrawtransaction(str(tx))
    # generate block
    btc_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)

    # create tx (output wpkh only, input multisig tx1-3)
    txid = tx.txid
    txin_list = []
    txin_utxo_list = []
    for index, txout in enumerate(tx.txout_list):
        temp_addr = str(txout.get_address(network=NETWORK))
        if temp_addr == fee_addr:
            continue
        txin_list.append(TxIn(txid=txid, vout=index))
        if temp_addr not in test_obj.desc_dic:
            test_obj.assertTrue(False, 'addr not found. [{}]:[{}]'.format(
                index, temp_addr))
        desc = test_obj.desc_dic[temp_addr]
        txin_utxo_list.append(UtxoData(
            txid=txid, vout=index, amount=txout.amount, descriptor=desc))
    txouts2 = [
        TxOut(300000000, str(test_obj.addr_dic['main'])),
    ]
    tx2 = Transaction.create(2, 0, txin_list, txouts2)
    main_addr = test_obj.addr_dic['main']
    utxos = get_utxo(btc_rpc, [fee_addr])
    utxo_list = convert_bitcoin_utxos(test_obj, utxos)
    tx2.fund_raw_transaction(txin_utxo_list, utxo_list, fee_addr,
                             target_amount=0, effective_fee_rate=20.0,
                             knapsack_min_change=1)
    # add sign

    def multisig_sign(tx_obj, utxo, path_list):
        sighash = tx_obj.get_sighash(
            outpoint=utxo.outpoint,
            hash_type=utxo.descriptor.data.hash_type,
            amount=utxo.amount,
            redeem_script=utxo.descriptor.data.redeem_script)
        signature_list = []
        for path in path_list:
            sk = test_obj.hdwallet.get_privkey(path=path).privkey
            sig = sk.calculate_ec_signature(sighash)
            sig.related_pubkey = sk.pubkey
            signature_list.append(sig)
            if len(signature_list) == 2:
                break
        tx_obj.add_multisig_sign(
            utxo.outpoint, utxo.descriptor.data.hash_type,
            utxo.descriptor.data.redeem_script, signature_list)

    join_utxo_list: List['UtxoData'] = []
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = utxo_list
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = txin_utxo_list
    for index, txin in enumerate(tx2.txin_list):
        utxo = search_utxos(test_obj, join_utxo_list, txin.outpoint)
        if not utxo.descriptor.data.redeem_script:
            path = str(test_obj.path_dic[str(utxo.descriptor.data.address)])
            sk = test_obj.hdwallet.get_privkey(path=path).privkey
            tx2.sign_with_privkey(txin.outpoint,
                                  utxo.descriptor.data.hash_type,
                                  sk, amount=utxo.amount,
                                  sighashtype=SigHashType.ALL)
        else:
            path_list = test_obj.path_dic[str(utxo.descriptor.data.address)]
            multisig_sign(tx2, utxo, path_list)
    # broadcast
    print(Transaction.parse_to_json(str(tx2), network=NETWORK))
    btc_rpc.sendrawtransaction(str(tx2))
    # generate block
    btc_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)
    utxos = get_utxo(btc_rpc, [str(main_addr)])
    print('UTXO: {}'.format(utxos))


def test_psbt(test_obj: 'TestBitcoin'):
    btc_rpc = test_obj.conn.get_rpc()
    fee_addr = str(test_obj.addr_dic['fee'])
    fee_sk = test_obj.hdwallet.get_privkey(path=FEE_PATH).privkey
    main_addr = test_obj.addr_dic['main']
    utxos = get_utxo(btc_rpc, [str(fee_addr)])  # listunspent
    utxo_list = convert_bitcoin_utxos(test_obj, utxos)
    txouts = [
        PsbtAppendOutputData(
            100000000,
            address=test_obj.addr_dic['p2pkh'],
            descriptor=test_obj.desc_dic[str(test_obj.addr_dic['p2pkh'])]),
        PsbtAppendOutputData(
            100000000,
            address=str(test_obj.addr_dic['p2wpkh']),
            descriptor=test_obj.desc_dic[str(test_obj.addr_dic['p2wpkh'])]),
        PsbtAppendOutputData(
            100000000,
            address=str(test_obj.addr_dic['p2sh-p2wpkh']),
            descriptor=test_obj.desc_dic[str(
                test_obj.addr_dic['p2sh-p2wpkh'])],
        ),
    ]
    psbt = Psbt.create(tx_version=2, network=NETWORK)
    psbt.add(outputs=txouts)
    psbt.fund(
        utxo_list=utxo_list,
        reserved_address_descriptor=test_obj.desc_dic[str(fee_addr)],
        effective_fee_rate=2.0, long_term_fee_rate=2.0, knapsack_min_change=0)
    psbt.sign(fee_sk)
    # bitcoinrpc: finalize extract
    ret = btc_rpc.finalizepsbt(str(psbt), True)
    tx_hex = ret['hex'] if 'hex' in ret else ''
    if not ret.get('complete', True):
        raise AssertionError("finalizepsbt not complete.")
    print(Transaction.parse_to_json(tx_hex, network=NETWORK))
    txid = btc_rpc.sendrawtransaction(tx_hex)
    tx = Transaction(tx_hex)
    # generate block
    btc_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)
    utxos = get_utxo(btc_rpc, [str(main_addr)])
    print('UTXO: {}'.format(utxos))

    txid = tx.txid
    txin_list = []
    key_list = []
    for index, _ in enumerate(txouts):
        txout = tx.txout_list[index]
        addr = txout.get_address(network=NETWORK)
        desc = test_obj.desc_dic[str(addr)]
        txin_list.append(PsbtAppendInputData(
            outpoint=OutPoint(txid, index),
            utxo=txout, descriptor=str(desc),
            utxo_tx=tx_hex))
        path = str(test_obj.path_dic[str(addr)])
        key_list.append(test_obj.hdwallet.get_privkey(path=path).privkey)
    txouts2 = [
        TxOut(300000000, str(test_obj.addr_dic['main'])),
    ]
    tx2 = Transaction.create(2, 0, [], txouts2)
    psbt2 = Psbt.from_transaction(transaction=tx2, network=NETWORK)
    psbt2.set_output_bip32_key(0, pubkey=str(
        test_obj.desc_dic[str(txouts2[0].address)]))
    psbt2.add(inputs=txin_list)
    utxos = get_utxo(btc_rpc, [str(fee_addr)])  # listunspent
    utxo_list2 = convert_bitcoin_utxos(test_obj, utxos)
    psbt2.fund(
        utxo_list=utxo_list2,
        reserved_address_descriptor=test_obj.desc_dic[str(fee_addr)],
        effective_fee_rate=2.0, long_term_fee_rate=2.0, knapsack_min_change=0)
    psbt21 = Psbt(str(psbt2), network=NETWORK)
    psbt22 = Psbt(str(psbt2), network=NETWORK)
    psbt21.sign(fee_sk)
    for key in key_list:
        psbt22.sign(key)
    # psbt2_str = btc_rpc.combinepsbt([str(psbt21), str(psbt22)])
    # psbt2 = Psbt(psbt2_str, network=NETWORK)
    psbt2 = Psbt.combine_psbts([str(psbt21), psbt22])
    tx2 = psbt2.extract(True)
    print(Transaction.parse_to_json(str(tx2), network=NETWORK))
    txid = btc_rpc.sendrawtransaction(str(tx2))
    # generate block
    btc_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)
    utxos = get_utxo(btc_rpc, [str(main_addr)])
    print('UTXO: {}'.format(utxos))


def test_taproot_schnorr(test_obj: 'TestBitcoin'):
    btc_rpc = test_obj.conn.get_rpc()
    main_addr = test_obj.addr_dic['main']
    main_pk, _ = SchnorrPubkey.from_pubkey(str(main_addr.pubkey))
    tr_addr = AddressUtil.taproot(main_pk, network=NETWORK)
    main_path = str(test_obj.path_dic[str(main_addr)])
    main_sk = test_obj.hdwallet.get_privkey(path=main_path).privkey

    txouts = [
        TxOut(100000000, str(tr_addr)),
    ]
    tx = Transaction.create(2, 0, [], txouts)
    # fundrawtransaction
    fee_addr = str(test_obj.addr_dic['fee'])
    fee_desc = test_obj.desc_dic[fee_addr]
    fee_sk = test_obj.hdwallet.get_privkey(path=FEE_PATH).privkey
    utxos = get_utxo(btc_rpc, [fee_addr])
    utxo_list = convert_bitcoin_utxos(test_obj, utxos)
    tx.fund_raw_transaction([], utxo_list, fee_addr,
                            target_amount=0, effective_fee_rate=2.0,
                            knapsack_min_change=0)
    # add sign
    for txin in tx.txin_list:
        utxo = search_utxos(test_obj, utxo_list, txin.outpoint)
        tx.sign_with_privkey(txin.outpoint, fee_desc.data.hash_type, fee_sk,
                             amount=utxo.amount,
                             sighashtype=SigHashType.ALL)
    # broadcast
    print(Transaction.parse_to_json(str(tx), network=NETWORK))
    btc_rpc.sendrawtransaction(str(tx))
    # generate block
    btc_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)

    # create tx (output wpkh only, input tx1-3)
    txid = tx.txid
    txin_list = []
    txin_utxo_list = []
    txin_list.append(TxIn(txid=txid, vout=0))
    desc = f'raw({str(tr_addr.locking_script)})'
    txin_utxo_list.append(UtxoData(
        txid=txid, vout=0, amount=txouts[0].amount, descriptor=desc))
    txouts2 = [
        TxOut(100000000, str(test_obj.addr_dic['main'])),
    ]
    tx2 = Transaction.create(2, 0, txin_list, txouts2)
    main_addr = test_obj.addr_dic['main']
    utxos = get_utxo(btc_rpc, [fee_addr])
    utxo_list = convert_bitcoin_utxos(test_obj, utxos)
    tx2.fund_raw_transaction(txin_utxo_list, utxo_list, fee_addr,
                             target_amount=0, effective_fee_rate=20.0,
                             knapsack_min_change=1)
    # add sign
    join_utxo_list: List['UtxoData'] = []
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = txin_utxo_list
    for txin in tx2.txin_list:
        for utxo in utxo_list:
            if utxo.outpoint == txin.outpoint:
                join_utxo_list.append(utxo)
    for index, txin in enumerate(tx2.txin_list):
        utxo = search_utxos(test_obj, join_utxo_list, txin.outpoint)
        if index == 0:
            sk = main_sk
            hash_type = main_addr.hash_type
        else:
            path = str(test_obj.path_dic[str(utxo.descriptor.data.address)])
            sk = test_obj.hdwallet.get_privkey(path=path).privkey
            hash_type = utxo.descriptor.data.hash_type
        tx2.sign_with_privkey(txin.outpoint, hash_type,
                              sk, amount=utxo.amount,
                              sighashtype=SigHashType.ALL,
                              utxos=join_utxo_list)
    # broadcast
    print(Transaction.parse_to_json(str(tx2), network=NETWORK))
    btc_rpc.sendrawtransaction(str(tx2))
    # generate block
    btc_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)

    utxos = get_utxo(btc_rpc, [str(main_addr)])
    print('UTXO: {}'.format(utxos))


def test_taproot_tapscript(test_obj: 'TestBitcoin'):
    btc_rpc = test_obj.conn.get_rpc()
    main_addr = test_obj.addr_dic['main']
    main_pk, _ = SchnorrPubkey.from_pubkey(str(main_addr.pubkey))
    pkh_addr = test_obj.addr_dic['p2pkh']
    spk1, _ = SchnorrPubkey.from_pubkey(str(pkh_addr.pubkey))
    wpkh_addr = test_obj.addr_dic['p2wpkh']
    spk2, _ = SchnorrPubkey.from_pubkey(str(wpkh_addr.pubkey))
    main_path = str(test_obj.path_dic[str(main_addr)])
    main_sk = test_obj.hdwallet.get_privkey(path=main_path).privkey
    pkh_path = str(test_obj.path_dic[str(pkh_addr)])
    sk1 = test_obj.hdwallet.get_privkey(path=pkh_path).privkey
    # wpkh_path = str(test_obj.path_dic[str(wpkh_addr)])
    # sk2 = test_obj.hdwallet.get_privkey(path=wpkh_path).privkey

    script1 = Script.from_asm([str(spk1), 'OP_CHECKSIG'])
    script2 = Script.from_asm([str(spk2), 'OP_CHECKSIG'])
    op_true_script = Script('51')
    op_true_sub_tree1 = TaprootScriptTree(op_true_script)
    op_true_sub_tree1.add_branch(script1)

    script1_tree = TaprootScriptTree(script1)
    script1_tree.add_branches([op_true_script, script2])
    script1_tree.internal_pubkey = main_pk

    op_true_tree = TaprootScriptTree(op_true_script)
    op_true_tree.add_branches([script1, script2])
    op_true_tree.internal_pubkey = main_pk

    script2_tree = TaprootScriptTree(script2)
    script2_tree.add_branch(op_true_sub_tree1)
    script2_tree.internal_pubkey = main_pk

    tr_addr1 = AddressUtil.taproot(script1_tree, network=NETWORK)
    tr_addr2 = AddressUtil.taproot(op_true_tree, network=NETWORK)
    tr_addr3 = AddressUtil.taproot(script2_tree, network=NETWORK)

    txouts = [
        TxOut(100000, str(tr_addr1)),
        TxOut(150000, str(tr_addr2)),
        TxOut(200000, str(tr_addr3)),
    ]
    tx = Transaction.create(2, 0, [], txouts)
    # fundrawtransaction
    fee_addr = str(test_obj.addr_dic['fee'])
    fee_desc = test_obj.desc_dic[fee_addr]
    fee_sk = test_obj.hdwallet.get_privkey(path=FEE_PATH).privkey
    utxos = get_utxo(btc_rpc, [fee_addr])
    utxo_list = convert_bitcoin_utxos(test_obj, utxos)
    tx.fund_raw_transaction([], utxo_list, fee_addr,
                            target_amount=0, effective_fee_rate=2.0,
                            knapsack_min_change=0)
    # add sign
    for txin in tx.txin_list:
        utxo = search_utxos(test_obj, utxo_list, txin.outpoint)
        tx.sign_with_privkey(txin.outpoint, fee_desc.data.hash_type, fee_sk,
                             amount=utxo.amount,
                             sighashtype=SigHashType.ALL)
    # broadcast
    print(Transaction.parse_to_json(str(tx), network=NETWORK))
    btc_rpc.sendrawtransaction(str(tx))
    # generate block
    btc_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)

    txid = tx.txid
    utxo1 = UtxoData(txid=txid, vout=0, amount=txouts[0].amount,
                     descriptor=f'raw({str(tr_addr1.locking_script)})')
    utxo2 = UtxoData(txid=txid, vout=1, amount=txouts[1].amount,
                     descriptor=f'raw({str(tr_addr2.locking_script)})')
    utxo3 = UtxoData(txid=txid, vout=2, amount=txouts[2].amount,
                     descriptor=f'raw({str(tr_addr3.locking_script)})')

    # send tapscript script1
    txin_list = []
    txin_utxo_list = []
    txin_list.append(TxIn(txid=txid, vout=0))
    txin_utxo_list.append(utxo1)
    txouts2 = [
        TxOut(txouts[0].amount, str(test_obj.addr_dic['main'])),
    ]
    tx2 = Transaction.create(2, 0, txin_list, txouts2)
    main_addr = test_obj.addr_dic['main']
    utxos = get_utxo(btc_rpc, [fee_addr])
    utxo_list = convert_bitcoin_utxos(test_obj, utxos)
    tx2.fund_raw_transaction(txin_utxo_list, utxo_list, fee_addr,
                             target_amount=0, effective_fee_rate=2.0,
                             knapsack_min_change=0)
    # add sign
    join_utxo_list: List['UtxoData'] = []
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = txin_utxo_list
    for txin in tx2.txin_list:
        for utxo in utxo_list:
            if utxo.outpoint == txin.outpoint:
                join_utxo_list.append(utxo)
    for index, txin in enumerate(tx2.txin_list):
        utxo = search_utxos(test_obj, join_utxo_list, txin.outpoint)
        if index == 0:
            sk = sk1
            sighash = tx2.get_sighash(
                txin.outpoint, HashType.TAPROOT, redeem_script=script1,
                sighashtype=SigHashType.DEFAULT, utxos=join_utxo_list)
            sig = SchnorrUtil.sign(sighash, sk1)
            sign_param = SignParameter(sig, sighashtype=SigHashType.DEFAULT)
            _, _, _, control_block = script1_tree.get_taproot_data()
            tx2.add_tapscript_sign(txin.outpoint, [sign_param],
                                   script1, control_block)
        else:
            path = str(test_obj.path_dic[str(utxo.descriptor.data.address)])
            sk = test_obj.hdwallet.get_privkey(path=path).privkey
            hash_type = utxo.descriptor.data.hash_type
            tx2.sign_with_privkey(txin.outpoint, hash_type,
                                  sk, amount=utxo.amount,
                                  sighashtype=SigHashType.ALL,
                                  utxos=join_utxo_list)
    # broadcast
    print(Transaction.parse_to_json(str(tx2), network=NETWORK))
    btc_rpc.sendrawtransaction(str(tx2))
    # generate block
    btc_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)

    # send tapscript OP_TRUE
    txin_list = []
    txin_utxo_list = []
    txin_list.append(TxIn(txid=txid, vout=1))
    txin_utxo_list.append(utxo2)
    txouts2 = [
        TxOut(txouts[1].amount, str(test_obj.addr_dic['main'])),
    ]
    tx2 = Transaction.create(2, 0, txin_list, txouts2)
    main_addr = test_obj.addr_dic['main']
    utxos = get_utxo(btc_rpc, [fee_addr])
    utxo_list = convert_bitcoin_utxos(test_obj, utxos)
    tx2.fund_raw_transaction(txin_utxo_list, utxo_list, fee_addr,
                             target_amount=0, effective_fee_rate=2.0,
                             knapsack_min_change=0)
    # add sign
    join_utxo_list = []
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = txin_utxo_list
    for txin in tx2.txin_list:
        for utxo in utxo_list:
            if utxo.outpoint == txin.outpoint:
                join_utxo_list.append(utxo)
    for index, txin in enumerate(tx2.txin_list):
        utxo = search_utxos(test_obj, join_utxo_list, txin.outpoint)
        if index == 0:
            _, _, _, control_block = op_true_tree.get_taproot_data()
            tx2.add_tapscript_sign(txin.outpoint, [],
                                   op_true_script, control_block)
        else:
            path = str(test_obj.path_dic[str(utxo.descriptor.data.address)])
            sk = test_obj.hdwallet.get_privkey(path=path).privkey
            hash_type = utxo.descriptor.data.hash_type
            tx2.sign_with_privkey(txin.outpoint, hash_type,
                                  sk, amount=utxo.amount,
                                  sighashtype=SigHashType.ALL,
                                  utxos=join_utxo_list)
    # broadcast
    print(Transaction.parse_to_json(str(tx2), network=NETWORK))
    btc_rpc.sendrawtransaction(str(tx2))
    # generate block
    btc_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)

    # send tapscript internal_pubkey
    txin_list = []
    txin_utxo_list = []
    txin_list.append(TxIn(txid=txid, vout=2))
    txin_utxo_list.append(utxo3)
    txouts2 = [
        TxOut(txouts[2].amount, str(test_obj.addr_dic['main'])),
    ]
    tx2 = Transaction.create(2, 0, txin_list, txouts2)
    main_addr = test_obj.addr_dic['main']
    utxos = get_utxo(btc_rpc, [fee_addr])
    utxo_list = convert_bitcoin_utxos(test_obj, utxos)
    tx2.fund_raw_transaction(txin_utxo_list, utxo_list, fee_addr,
                             target_amount=0, effective_fee_rate=2.0,
                             knapsack_min_change=0)
    # add sign
    join_utxo_list = []
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = txin_utxo_list
    for txin in tx2.txin_list:
        for utxo in utxo_list:
            if utxo.outpoint == txin.outpoint:
                join_utxo_list.append(utxo)
    for index, txin in enumerate(tx2.txin_list):
        utxo = search_utxos(test_obj, join_utxo_list, txin.outpoint)
        if index == 0:
            sk = script2_tree.get_privkey(main_sk)
            hash_type = tr_addr3.hash_type
        else:
            path = str(test_obj.path_dic[str(utxo.descriptor.data.address)])
            sk = test_obj.hdwallet.get_privkey(path=path).privkey
            hash_type = utxo.descriptor.data.hash_type
        tx2.sign_with_privkey(txin.outpoint, hash_type,
                              sk, amount=utxo.amount,
                              sighashtype=SigHashType.ALL,
                              utxos=join_utxo_list)
    # broadcast
    print(Transaction.parse_to_json(str(tx2), network=NETWORK))
    btc_rpc.sendrawtransaction(str(tx2))
    # generate block
    btc_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)

    utxos = get_utxo(btc_rpc, [str(main_addr)])
    print('UTXO: {}'.format(utxos))


def test_taproot_single_key(test_obj: 'TestBitcoin'):
    btc_rpc = test_obj.conn.get_rpc()
    main_addr = test_obj.addr_dic['main']
    main_pk, _ = SchnorrPubkey.from_pubkey(str(main_addr.pubkey))
    pkh_addr = test_obj.addr_dic['p2pkh']
    spk1, _ = SchnorrPubkey.from_pubkey(str(pkh_addr.pubkey))
    wpkh_addr = test_obj.addr_dic['p2wpkh']
    spk2, _ = SchnorrPubkey.from_pubkey(str(wpkh_addr.pubkey))
    main_path = str(test_obj.path_dic[str(main_addr)])
    main_sk = test_obj.hdwallet.get_privkey(path=main_path).privkey
    pkh_path = str(test_obj.path_dic[str(pkh_addr)])
    sk1 = test_obj.hdwallet.get_privkey(path=pkh_path).privkey
    wpkh_path = str(test_obj.path_dic[str(wpkh_addr)])
    sk2 = test_obj.hdwallet.get_privkey(path=wpkh_path).privkey

    branch = TapBranch()
    tr_addr1 = AddressUtil.taproot(
        main_pk, script_tree=branch, network=NETWORK)
    tr_sk1 = branch.get_privkey(main_sk)
    tr_addr2 = AddressUtil.taproot(spk1, script_tree=branch, network=NETWORK)
    tr_sk2 = branch.get_privkey(sk1)
    tr_addr3 = AddressUtil.taproot(spk2, script_tree=branch, network=NETWORK)
    tr_sk3 = branch.get_privkey(sk2)

    txouts = [
        TxOut(100000, str(tr_addr1)),
        TxOut(150000, str(tr_addr2)),
        TxOut(200000, str(tr_addr3)),
    ]
    tx = Transaction.create(2, 0, [], txouts)
    # fundrawtransaction
    fee_addr = str(test_obj.addr_dic['fee'])
    fee_desc = test_obj.desc_dic[fee_addr]
    fee_sk = test_obj.hdwallet.get_privkey(path=FEE_PATH).privkey
    utxos = get_utxo(btc_rpc, [fee_addr])
    utxo_list = convert_bitcoin_utxos(test_obj, utxos)
    tx.fund_raw_transaction([], utxo_list, fee_addr,
                            target_amount=0, effective_fee_rate=2.0,
                            knapsack_min_change=0)
    # add sign
    for txin in tx.txin_list:
        utxo = search_utxos(test_obj, utxo_list, txin.outpoint)
        tx.sign_with_privkey(txin.outpoint, fee_desc.data.hash_type, fee_sk,
                             amount=utxo.amount,
                             sighashtype=SigHashType.ALL)
    # broadcast
    print(Transaction.parse_to_json(str(tx), network=NETWORK))
    btc_rpc.sendrawtransaction(str(tx))
    # generate block
    btc_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)

    txid = tx.txid
    utxo1 = UtxoData(txid=txid, vout=0, amount=txouts[0].amount,
                     descriptor=f'raw({str(tr_addr1.locking_script)})')
    utxo2 = UtxoData(txid=txid, vout=1, amount=txouts[1].amount,
                     descriptor=f'raw({str(tr_addr2.locking_script)})')
    utxo3 = UtxoData(txid=txid, vout=2, amount=txouts[2].amount,
                     descriptor=f'raw({str(tr_addr3.locking_script)})')

    # send taproot singleKey1
    txin_list = []
    txin_utxo_list = []
    txin_list.append(TxIn(txid=txid, vout=0))
    txin_utxo_list.append(utxo1)
    txouts2 = [
        TxOut(txouts[0].amount, str(test_obj.addr_dic['main'])),
    ]
    tx2 = Transaction.create(2, 0, txin_list, txouts2)
    main_addr = test_obj.addr_dic['main']
    utxos = get_utxo(btc_rpc, [fee_addr])
    utxo_list = convert_bitcoin_utxos(test_obj, utxos)
    tx2.fund_raw_transaction(txin_utxo_list, utxo_list, fee_addr,
                             target_amount=0, effective_fee_rate=2.0,
                             knapsack_min_change=0)
    # add sign
    join_utxo_list: List['UtxoData'] = []
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = txin_utxo_list
    for txin in tx2.txin_list:
        for utxo in utxo_list:
            if utxo.outpoint == txin.outpoint:
                join_utxo_list.append(utxo)
    for index, txin in enumerate(tx2.txin_list):
        utxo = search_utxos(test_obj, join_utxo_list, txin.outpoint)
        if index == 0:
            sighash = tx2.get_sighash(
                txin.outpoint, HashType.TAPROOT, pubkey=tr_addr1.pubkey,
                sighashtype=SigHashType.DEFAULT, utxos=join_utxo_list)
            sig = SchnorrUtil.sign(sighash, tr_sk1)
            sign_param = SignParameter(sig, sighashtype=SigHashType.DEFAULT)
            tx2.add_taproot_sign(txin.outpoint, sign_param)
        else:
            path = str(test_obj.path_dic[str(utxo.descriptor.data.address)])
            sk = test_obj.hdwallet.get_privkey(path=path).privkey
            hash_type = utxo.descriptor.data.hash_type
            tx2.sign_with_privkey(txin.outpoint, hash_type,
                                  sk, amount=utxo.amount,
                                  sighashtype=SigHashType.ALL,
                                  utxos=join_utxo_list)
    # broadcast
    print(Transaction.parse_to_json(str(tx2), network=NETWORK))
    btc_rpc.sendrawtransaction(str(tx2))
    # generate block
    btc_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)

    # send taproot singleKey2
    txin_list = []
    txin_utxo_list = []
    txin_list.append(TxIn(txid=txid, vout=1))
    txin_utxo_list.append(utxo2)
    txouts2 = [
        TxOut(txouts[1].amount, str(test_obj.addr_dic['main'])),
    ]
    tx2 = Transaction.create(2, 0, txin_list, txouts2)
    main_addr = test_obj.addr_dic['main']
    utxos = get_utxo(btc_rpc, [fee_addr])
    utxo_list = convert_bitcoin_utxos(test_obj, utxos)
    tx2.fund_raw_transaction(txin_utxo_list, utxo_list, fee_addr,
                             target_amount=0, effective_fee_rate=2.0,
                             knapsack_min_change=0)
    # add sign
    join_utxo_list = []
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = txin_utxo_list
    for txin in tx2.txin_list:
        for utxo in utxo_list:
            if utxo.outpoint == txin.outpoint:
                join_utxo_list.append(utxo)
    for index, txin in enumerate(tx2.txin_list):
        utxo = search_utxos(test_obj, join_utxo_list, txin.outpoint)
        if index == 0:
            sighash = tx2.get_sighash(
                txin.outpoint, HashType.TAPROOT, pubkey=tr_addr2.pubkey,
                sighashtype=SigHashType.DEFAULT, utxos=join_utxo_list)
            sig = SchnorrUtil.sign(sighash, tr_sk2)
            sign_param = SignParameter(sig, sighashtype=SigHashType.DEFAULT)
            tx2.add_taproot_sign(txin.outpoint, sign_param)
        else:
            path = str(test_obj.path_dic[str(utxo.descriptor.data.address)])
            sk = test_obj.hdwallet.get_privkey(path=path).privkey
            hash_type = utxo.descriptor.data.hash_type
            tx2.sign_with_privkey(txin.outpoint, hash_type,
                                  sk, amount=utxo.amount,
                                  sighashtype=SigHashType.ALL,
                                  utxos=join_utxo_list)
    # broadcast
    print(Transaction.parse_to_json(str(tx2), network=NETWORK))
    btc_rpc.sendrawtransaction(str(tx2))
    # generate block
    btc_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)

    # send taproot singleKey3
    txin_list = []
    txin_utxo_list = []
    txin_list.append(TxIn(txid=txid, vout=2))
    txin_utxo_list.append(utxo3)
    txouts2 = [
        TxOut(txouts[2].amount, str(test_obj.addr_dic['main'])),
    ]
    tx2 = Transaction.create(2, 0, txin_list, txouts2)
    main_addr = test_obj.addr_dic['main']
    utxos = get_utxo(btc_rpc, [fee_addr])
    utxo_list = convert_bitcoin_utxos(test_obj, utxos)
    tx2.fund_raw_transaction(txin_utxo_list, utxo_list, fee_addr,
                             target_amount=0, effective_fee_rate=2.0,
                             knapsack_min_change=0)
    # add sign
    join_utxo_list = []
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = txin_utxo_list
    for txin in tx2.txin_list:
        for utxo in utxo_list:
            if utxo.outpoint == txin.outpoint:
                join_utxo_list.append(utxo)
    for index, txin in enumerate(tx2.txin_list):
        utxo = search_utxos(test_obj, join_utxo_list, txin.outpoint)
        if index == 0:
            sighash = tx2.get_sighash(
                txin.outpoint, HashType.TAPROOT, pubkey=tr_addr3.pubkey,
                sighashtype=SigHashType.DEFAULT, utxos=join_utxo_list)
            sig = SchnorrUtil.sign(sighash, tr_sk3)
            sign_param = SignParameter(sig, sighashtype=SigHashType.DEFAULT)
            tx2.add_taproot_sign(txin.outpoint, sign_param)
        else:
            path = str(test_obj.path_dic[str(utxo.descriptor.data.address)])
            sk = test_obj.hdwallet.get_privkey(path=path).privkey
            hash_type = utxo.descriptor.data.hash_type
            tx2.sign_with_privkey(txin.outpoint, hash_type,
                                  sk, amount=utxo.amount,
                                  sighashtype=SigHashType.ALL,
                                  utxos=join_utxo_list)
    # broadcast
    print(Transaction.parse_to_json(str(tx2), network=NETWORK))
    btc_rpc.sendrawtransaction(str(tx2))
    # generate block
    btc_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)

    utxos = get_utxo(btc_rpc, [str(main_addr)])
    print('UTXO: {}'.format(utxos))


class TestBitcoin(unittest.TestCase):
    hdwallet: 'HDWallet'
    # addr_dic: dict[str, 'Address']
    # desc_dic: dict[str, 'Descriptor']
    # path_dic: dict[str, Union[str, List[str]]]
    conn: 'RpcWrapper'

    def setUp(self):
        logging.basicConfig()
        logging.getLogger("BitcoinRPC").setLevel(logging.DEBUG)

        self.path_dic = {}
        self.addr_dic = {}
        self.desc_dic = {}
        self.hdwallet = HDWallet.from_mnemonic(
            MNEMONIC, passphrase=PASSPHRASE, network=NETWORK)
        create_bitcoin_address(self)
        self.conn = RpcWrapper(
            port=18443, rpc_user='bitcoinrpc', rpc_password='password')

    def test_bitcoin(self):
        '''
        To execute sequentially, define only one test
        and call the test function in it.
        '''
        test_import_address(self)
        test_generate(self)
        test_bitcoin_pkh(self)
        test_bitcoin_multisig(self)
        test_psbt(self)
        test_taproot_schnorr(self)
        test_taproot_tapscript(self)
        test_taproot_single_key(self)


if __name__ == "__main__":
    unittest.main()
