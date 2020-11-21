import unittest
from helper import RpcWrapper, get_utxo
from cfd.address import AddressUtil
from cfd.key import SigHashType
from cfd.hdwallet import HDWallet
from cfd.script import HashType
from cfd.descriptor import parse_descriptor
from cfd.transaction import Transaction, TxIn, TxOut, UtxoData
from decimal import Decimal
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


def convert_bitcoin_utxos(test_obj, utxo_list):
    # {"txid": "f3c8453e1bda1366bc859532e27a829c8ce623b766ae699a0377b168993c44b5", "vout": 0, "address": "bcrt1qyq7xhec45m75m5nvhzuh47vsj3as7tqf8t8vkr", "label": "test_fee", "scriptPubKey": "0014203c6be715a6fd4dd26cb8b97af990947b0f2c09", "amount": 50.0, "confirmations": 101, "spendable": false, "solvable": false, "safe": true}  # noqa8
    utxos = []
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


def create_bitcoin_address(test_obj):
    # fee address
    pk = str(test_obj.hdwallet.get_pubkey(path=FEE_PATH).pubkey)
    addr = AddressUtil.p2wpkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = FEE_PATH
    test_obj.addr_dic['fee'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'wpkh({})'.format(str(pk)), network=NETWORK)
    print('set fee addr: ' + str(addr))

    # wpkh main address
    path = '{}/0/0'.format(ROOT_PATH)
    pk = str(test_obj.hdwallet.get_pubkey(path=path).pubkey)
    addr = AddressUtil.p2wpkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = path
    test_obj.addr_dic['main'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'wpkh({})'.format(str(pk)), network=NETWORK)
    print('set main addr: ' + str(addr))
    # pkh address
    path = '{}/0/1'.format(ROOT_PATH)
    pk = str(test_obj.hdwallet.get_pubkey(path=path).pubkey)
    addr = AddressUtil.p2pkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = path
    test_obj.addr_dic['p2pkh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'pkh({})'.format(str(pk)), network=NETWORK)
    print('set p2pkh addr: ' + str(addr))
    # wpkh address
    path = '{}/0/2'.format(ROOT_PATH)
    pk = str(test_obj.hdwallet.get_pubkey(path=path).pubkey)
    addr = AddressUtil.p2wpkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = path
    test_obj.addr_dic['p2wpkh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'wpkh({})'.format(str(pk)), network=NETWORK)
    print('set p2wpkh addr: ' + str(addr))
    # p2sh-p2wpkh address
    path = '{}/0/3'.format(ROOT_PATH)
    pk = str(test_obj.hdwallet.get_pubkey(path=path).pubkey)
    addr = AddressUtil.p2sh_p2wpkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = path
    test_obj.addr_dic['p2sh-p2wpkh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'sh(wpkh({}))'.format(str(pk)), network=NETWORK)
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


def test_import_address(test_obj):
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


def test_generate(test_obj):
    # generatetoaddress -> fee addresss
    print(test_obj.addr_dic)
    btc_rpc = test_obj.conn.get_rpc()
    addr = str(test_obj.addr_dic['fee'])
    btc_rpc.generatetoaddress(100, addr)
    btc_rpc.generatetoaddress(5, addr)
    time.sleep(2)
    resp = get_utxo(btc_rpc, [addr])
    print(resp)


def test_bitcoin_pkh(test_obj):
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
    join_utxo_list = []
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = utxo_list
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = txin_utxo_list
    for txin in tx2.txin_list:
        utxo = search_utxos(test_obj, join_utxo_list, txin.outpoint)
        path = test_obj.path_dic[str(utxo.descriptor.data.address)]
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


def test_bitcoin_multisig(test_obj):
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

    join_utxo_list = []
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = utxo_list
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = txin_utxo_list
    for index, txin in enumerate(tx2.txin_list):
        utxo = search_utxos(test_obj, join_utxo_list, txin.outpoint)
        if not utxo.descriptor.data.redeem_script:
            path = test_obj.path_dic[str(utxo.descriptor.data.address)]
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


class TestBitcoin(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
