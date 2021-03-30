import unittest
from helper import RpcWrapper, get_utxo
from cfd.address import AddressUtil
from cfd.key import SigHashType
from cfd.hdwallet import HDWallet
from cfd.script import HashType
from cfd.descriptor import parse_descriptor
from cfd.transaction import Transaction
from cfd.confidential_address import ConfidentialAddress
from cfd.confidential_transaction import ConfidentialTransaction,\
    ConfidentialTxIn, ConfidentialTxOut, ElementsUtxoData,\
    TargetAmountData
from decimal import Decimal
import logging
import time

MNEMONIC = [
    'clerk', 'zoo', 'mercy', 'board', 'grab', 'service', 'impact', 'tortoise',
    'step', 'crash', 'load', 'aerobic', 'suggest', 'rack', 'refuse', 'can',
    'solve', 'become', 'upset', 'jump', 'token', 'anchor', 'apart', 'dog']
PASSPHRASE = 'Unx3HmdQ'
NETWORK = 'elementsregtest'
MAINCHAIN_NETWORK = 'regtest'
ROOT_PATH = 'm/44h/0h/0h'
FEE_PATH = ROOT_PATH + '/1/0'
GEN_PATH = ROOT_PATH + '/1/1'
MULTISIG_CT_PATH_BASE = ROOT_PATH + '/0/100/'
BTC_AMOUNT = 100000000
BTC_AMOUNT_BIT = 8


def convert_elements_utxos(test_obj, utxo_list):
    # {'txid': 'b8e25f336229b447e02eb18cc3f1201979eaea7fd9299c167407c8b97454f849', 'vout': 0, 'address': 'ert1qyq7xhec45m75m5nvhzuh47vsj3as7tqflljjgr', 'label': 'test_fee', 'scriptPubKey': '0014203c6be715a6fd4dd26cb8b97af990947b0f2c09', 'amount': Decimal('248.99999710'), 'assetcommitment': '0a42101f526b26b4f74d26c5ce566d77d6159894a8b50214b82d2f838dd0a3a418', 'asset': '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225', 'amountcommitment': '0842192917a9b4adbd4e0d3ff7a71dc97004de57f94ef825b956e04531f6a87098', 'amountblinder': '2f79bce2b26efe065378cfb532907d77dfb426a90cf1181da597dc7ea05b303b', 'assetblinder': '0dfc94eb72987ee2781fa31b2881f132cce118b9005f3c1623224225b37c0eeb', 'confirmations': 111, 'spendable': False, 'solvable': False, 'safe': True}  # noqa8
    utxos = []
    for utxo in utxo_list:
        desc = test_obj.desc_dic[utxo['address']]
        value = Decimal(str(utxo['amount']))
        value = value * BTC_AMOUNT
        amount_commitment = utxo.get('amountcommitment', '')
        asset_blinder = utxo.get('assetblinder', '')
        amount_blinder = utxo.get('amountblinder', '')
        data = ElementsUtxoData(
            txid=utxo['txid'], vout=utxo['vout'],
            amount=int(value), descriptor=desc,
            value=amount_commitment,
            asset=test_obj.pegged_asset,
            asset_blinder=asset_blinder,
            amount_blinder=amount_blinder)
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
    path2 = FEE_PATH + '/0'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set fee ct_addr: ' + str(ct_addr))

    # gen address
    pk = str(test_obj.hdwallet.get_pubkey(path=GEN_PATH).pubkey)
    addr = AddressUtil.p2wpkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = FEE_PATH
    test_obj.addr_dic['gen'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'wpkh({})'.format(str(pk)), network=NETWORK)
    print('set gen addr: ' + str(addr))
    path2 = GEN_PATH + '/0'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set gen ct_addr: ' + str(ct_addr))

    # wpkh main address
    path = '{}/0/0'.format(ROOT_PATH)
    pk = str(test_obj.hdwallet.get_pubkey(path=path).pubkey)
    addr = AddressUtil.p2wpkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = path
    test_obj.addr_dic['main'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'wpkh({})'.format(str(pk)), network=NETWORK)
    print('set main addr: ' + str(addr))
    path2 = path + '/0'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set main ct_addr: ' + str(ct_addr))

    # pkh address
    path = '{}/0/1'.format(ROOT_PATH)
    pk = str(test_obj.hdwallet.get_pubkey(path=path).pubkey)
    addr = AddressUtil.p2pkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = path
    test_obj.addr_dic['p2pkh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'pkh({})'.format(str(pk)), network=NETWORK)
    print('set p2pkh addr: ' + str(addr))
    path2 = path + '/0'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set p2pkh ct_addr: ' + str(ct_addr))
    # wpkh address
    path = '{}/0/2'.format(ROOT_PATH)
    pk = str(test_obj.hdwallet.get_pubkey(path=path).pubkey)
    addr = AddressUtil.p2wpkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = path
    test_obj.addr_dic['p2wpkh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'wpkh({})'.format(str(pk)), network=NETWORK)
    print('set p2wpkh addr: ' + str(addr))
    path2 = path + '/0'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set p2wpkh ct_addr: ' + str(ct_addr))
    # p2sh-p2wpkh address
    path = '{}/0/3'.format(ROOT_PATH)
    pk = str(test_obj.hdwallet.get_pubkey(path=path).pubkey)
    addr = AddressUtil.p2sh_p2wpkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = path
    test_obj.addr_dic['p2sh-p2wpkh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'sh(wpkh({}))'.format(str(pk)), network=NETWORK)
    print('set p2sh-p2wpkh addr: ' + str(addr))
    path2 = path + '/0'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set p2sh-p2wpkh ct_addr: ' + str(ct_addr))

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
    path2 = MULTISIG_CT_PATH_BASE + '1'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set p2sh ct_addr: ' + str(ct_addr))
    addr = AddressUtil.multisig(
        req_num, pk_list, HashType.P2WSH, network=NETWORK)
    test_obj.path_dic[str(addr)] = path_list
    test_obj.addr_dic['p2wsh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'wsh({})'.format(desc_multi), network=NETWORK)
    print('set p2wsh addr: ' + str(addr))
    path2 = MULTISIG_CT_PATH_BASE + '2'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set p2wsh ct_addr: ' + str(ct_addr))
    addr = AddressUtil.multisig(
        req_num, pk_list, HashType.P2SH_P2WSH, network=NETWORK)
    test_obj.path_dic[str(addr)] = path_list
    test_obj.addr_dic['p2sh-p2wsh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'sh(wsh({}))'.format(desc_multi), network=NETWORK)
    print('set p2sh-p2wsh addr: ' + str(addr))
    path2 = MULTISIG_CT_PATH_BASE + '3'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set p2sh-p2wsh ct_addr: ' + str(ct_addr))

    # master blinding key
    path = '{}/0/1001'.format(ROOT_PATH)
    sk = str(test_obj.hdwallet.get_privkey(path=path).privkey)
    test_obj.master_blinding_key = sk
    print('set master blinding key: ' + sk)


def test_import_address(test_obj):
    btc_rpc = test_obj.btcConn.get_rpc()
    elm_rpc = test_obj.elmConn.get_rpc()

    # get btc address from bitcoin-cli (for fee)
    btc_addr = btc_rpc.getnewaddress('', 'bech32')
    test_obj.addr_dic['btc'] = btc_addr

    # fee address
    addr = str(test_obj.addr_dic['fee'])
    elm_rpc.importaddress(str(test_obj.ct_addr_dic[addr]), 'test_fee', False)
    elm_rpc.importblindingkey(
        str(test_obj.ct_addr_dic[addr]),
        str(test_obj.blind_key_dic[addr].hex))
    # pkh address
    addr = str(test_obj.addr_dic['main'])
    elm_rpc.importaddress(str(test_obj.ct_addr_dic[addr]), 'test_main', False)
    elm_rpc.importblindingkey(
        str(test_obj.ct_addr_dic[addr]),
        str(test_obj.blind_key_dic[addr].hex))
    addr = str(test_obj.addr_dic['p2pkh'])
    elm_rpc.importaddress(str(test_obj.ct_addr_dic[addr]), 'test_pkh', False)
    elm_rpc.importblindingkey(
        str(test_obj.ct_addr_dic[addr]),
        str(test_obj.blind_key_dic[addr].hex))
    addr = str(test_obj.addr_dic['p2wpkh'])
    elm_rpc.importaddress(str(test_obj.ct_addr_dic[addr]), 'test_wpkh', False)
    elm_rpc.importblindingkey(
        str(test_obj.ct_addr_dic[addr]),
        str(test_obj.blind_key_dic[addr].hex))
    addr = str(test_obj.addr_dic['p2sh-p2wpkh'])
    elm_rpc.importaddress(
        str(test_obj.ct_addr_dic[addr]), 'test_sh_wpkh', False)
    elm_rpc.importblindingkey(
        str(test_obj.ct_addr_dic[addr]),
        str(test_obj.blind_key_dic[addr].hex))
    # multisig_key
    addr = str(test_obj.addr_dic['p2sh'])
    elm_rpc.importaddress(str(test_obj.ct_addr_dic[addr]), 'test_sh', False)
    elm_rpc.importblindingkey(
        str(test_obj.ct_addr_dic[addr]),
        str(test_obj.blind_key_dic[addr].hex))
    addr = str(test_obj.addr_dic['p2wsh'])
    elm_rpc.importaddress(str(test_obj.ct_addr_dic[addr]), 'test_wsh', False)
    elm_rpc.importblindingkey(
        str(test_obj.ct_addr_dic[addr]),
        str(test_obj.blind_key_dic[addr].hex))
    addr = str(test_obj.addr_dic['p2sh-p2wsh'])
    elm_rpc.importaddress(
        str(test_obj.ct_addr_dic[addr]), 'test_sh_wsh', False)
    elm_rpc.importblindingkey(
        str(test_obj.ct_addr_dic[addr]),
        str(test_obj.blind_key_dic[addr].hex))


def get_elements_config(test_obj):
    elm_rpc = test_obj.elmConn.get_rpc()
    # mainchain
    test_obj.sidechaininfo = elm_rpc.getsidechaininfo()
    test_obj.pegged_asset = test_obj.sidechaininfo['pegged_asset']
    test_obj.fedpegscript = test_obj.sidechaininfo['fedpegscript']
    test_obj.parent_blockhash = test_obj.sidechaininfo['parent_blockhash']
    test_obj.pegin_confirmation_depth =\
        test_obj.sidechaininfo['pegin_confirmation_depth']


def update_pegin_tx(test_obj, pegin_tx, btc_tx, pegin_address):
    pegin_tx2 = pegin_tx
    btc_tx_obj = Transaction.from_hex(btc_tx)
    btc_txid = btc_tx_obj.txid
    btc_txout_index = btc_tx_obj.get_txout_index(address=pegin_address)
    btc_amount = btc_tx_obj.txout_list[btc_txout_index].amount
    btc_size = len(btc_tx) / 2

    # decode
    tx = ConfidentialTransaction.from_hex(pegin_tx)
    target_script_pubkey = ''
    target_amount = 0
    target_index = 0
    # fee_index = -1
    fee_amount = 0
    has_fee = len(tx.txout_list) == 2
    for index, txout in enumerate(tx.txout_list):
        if len(txout.locking_script.hex) > 0:
            target_script_pubkey = str(txout.locking_script)
            target_amount = txout.amount
            target_index = index
        else:
            fee_amount = txout.amount
            # fee_index = index
    # change script pubkey (string replace)
    target_script_pubkey = '16' + target_script_pubkey

    fee_addr = test_obj.addr_dic['fee']
    new_script_pubkey = '16' + str(fee_addr.locking_script)
    pegin_tx2 = pegin_tx.replace(target_script_pubkey, new_script_pubkey)
    tx = ConfidentialTransaction.from_hex(pegin_tx2)
    total_amount = target_amount + fee_amount
    utxo_amount = 0
    if has_fee:
        utxo_amount = total_amount - btc_amount

    # add txout
    tx.add_txout(amount=1,
                 address=test_obj.ct_addr_dic[str(test_obj.addr_dic['main'])],
                 asset=test_obj.pegged_asset)

    # calc fee
    pegin_utxo = ElementsUtxoData(
        txid=btc_txid, vout=btc_txout_index,
        amount=btc_amount,
        descriptor='wpkh({})'.format('02' * 33),  # dummy
        asset=test_obj.pegged_asset,
        is_pegin=True, pegin_btc_tx_size=int(btc_size),
        fedpeg_script=test_obj.fedpegscript)
    utxo_list = [pegin_utxo]
    if utxo_amount > 0:
        for txin in tx.txin_list:
            if txin.outpoint.txid != btc_txid:
                utxo = ElementsUtxoData(
                    outpoint=txin.outpoint, amount=utxo_amount,
                    descriptor='', asset=test_obj.pegged_asset)
                utxo_list.append(utxo)
                break
    calc_fee, _, _ = tx.estimate_fee(utxo_list, test_obj.pegged_asset)
    # update fee
    tx.update_txout_fee_amount(calc_fee)

    # change amount
    new_amount = total_amount - calc_fee - 1
    tx.update_txout_amount(target_index, new_amount)

    # blind
    fee_ct_addr = test_obj.ct_addr_dic[str(fee_addr)]
    tx.blind_txout(utxo_list,
                   confidential_address_list=[fee_ct_addr])
    return str(tx)


def test_generate_btc(test_obj):
    # generatetoaddress -> fee address
    print(test_obj.addr_dic)
    btc_rpc = test_obj.btcConn.get_rpc()

    addr = str(test_obj.addr_dic['btc'])
    btc_rpc.generatetoaddress(100, addr)
    btc_rpc.generatetoaddress(5, addr)
    time.sleep(2)
    resp = get_utxo(btc_rpc, [addr])
    print(resp)


def test_pegin(test_obj):
    btc_rpc = test_obj.btcConn.get_rpc()
    elm_rpc = test_obj.elmConn.get_rpc()

    # generate pegin address by RPC
    pegin_addr_info = elm_rpc.getpeginaddress()
    pegin_address = pegin_addr_info['mainchain_address']
    claim_script = pegin_addr_info['claim_script']

    for i in range(3):
        try:
            # send bitcoin
            utxos = get_utxo(btc_rpc, [])
            amount = 0
            for utxo in utxos:
                amount += utxo['amount']
            amount -= 1
            if amount > 100:
                amount = 100
            txid = btc_rpc.sendtoaddress(pegin_address, amount)

            # generate bitcoin 100 block
            addr = str(test_obj.addr_dic['btc'])
            btc_rpc.generatetoaddress(101, addr)

            # pegin transaction for fee address
            tx_data = btc_rpc.gettransaction(txid)['hex']
            txout_proof = btc_rpc.gettxoutproof([txid])
            pegin_tx = elm_rpc.createrawpegin(
                tx_data, txout_proof, claim_script)['hex']
            pegin_tx = update_pegin_tx(
                test_obj, pegin_tx, tx_data, pegin_address)
            pegin_tx = elm_rpc.signrawtransactionwithwallet(pegin_tx)['hex']
            # broadcast
            print(ConfidentialTransaction.parse_to_json(
                pegin_tx, network=NETWORK))
            txid = elm_rpc.sendrawtransaction(pegin_tx)
            test_obj.tx_dic[txid] = pegin_tx
            # generatetoaddress -> gen address
            addr = str(test_obj.addr_dic['gen'])
            elm_rpc.generatetoaddress(2, addr)
            time.sleep(2)
        except Exception as err:
            print('Exception({})'.format(i))
            raise err

    # generatetoaddress -> gen address
    addr = str(test_obj.addr_dic['gen'])
    elm_rpc.generatetoaddress(100, addr)
    elm_rpc.generatetoaddress(5, addr)
    time.sleep(2)
    fee_addr = test_obj.addr_dic['fee']
    utxos = get_utxo(elm_rpc, [str(fee_addr)])
    # utxos = get_utxo(elm_rpc, [])
    print('UTXO: {}'.format(utxos))


def test_elements_pkh(test_obj):
    # btc_rpc = test_obj.btcConn.get_rpc()
    elm_rpc = test_obj.elmConn.get_rpc()
    # create tx (output wpkh, p2sh-segwit, pkh)
    txouts = [
        ConfidentialTxOut(
            100000000,
            test_obj.ct_addr_dic[str(test_obj.addr_dic['p2pkh'])],
            asset=test_obj.pegged_asset),
        ConfidentialTxOut(
            100000000,
            test_obj.ct_addr_dic[str(test_obj.addr_dic['p2wpkh'])],
            asset=test_obj.pegged_asset),
        ConfidentialTxOut(
            100000000,
            test_obj.ct_addr_dic[str(test_obj.addr_dic['p2sh-p2wpkh'])],
            asset=test_obj.pegged_asset),
    ]
    tx = ConfidentialTransaction.create(2, 0, [], txouts)
    # fundrawtransaction
    fee_addr = str(test_obj.addr_dic['fee'])
    fee_desc = test_obj.desc_dic[fee_addr]
    fee_ct_addr = test_obj.ct_addr_dic[fee_addr]
    fee_sk = test_obj.hdwallet.get_privkey(path=FEE_PATH).privkey
    utxos = get_utxo(elm_rpc, [fee_addr])
    utxo_list = convert_elements_utxos(test_obj, utxos)
    target_list = [TargetAmountData(
        amount=1,
        asset=test_obj.pegged_asset,
        reserved_address=fee_ct_addr)]
    tx.fund_raw_transaction([], utxo_list,
                            target_list=target_list,
                            fee_asset=test_obj.pegged_asset,
                            effective_fee_rate=0.1,
                            knapsack_min_change=1)
    # blind
    blind_utxo_list = []
    for txin in tx.txin_list:
        blind_utxo_list.append(search_utxos(
            test_obj, utxo_list, txin.outpoint))
    tx.blind_txout(blind_utxo_list)
    # add sign
    for txin in tx.txin_list:
        utxo = search_utxos(test_obj, utxo_list, txin.outpoint)
        tx.sign_with_privkey(txin.outpoint, fee_desc.data.hash_type, fee_sk,
                             value=utxo.value,
                             sighashtype=SigHashType.ALL)
    # broadcast
    print(ConfidentialTransaction.parse_to_json(str(tx), network=NETWORK))
    txid = elm_rpc.sendrawtransaction(str(tx))
    test_obj.tx_dic[txid] = tx
    # generate block
    elm_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)

    # create tx (output wpkh only, input tx1-3)
    txid = tx.txid
    txin_list = []
    txin_utxo_list = []
    for index, txout in enumerate(tx.txout_list):
        if not txout.locking_script.hex:
            continue
        temp_addr = str(txout.get_address(network=NETWORK))
        if temp_addr == fee_addr:
            continue
        txin_list.append(ConfidentialTxIn(txid=txid, vout=index))
        if temp_addr not in test_obj.desc_dic:
            test_obj.assertTrue(False, 'addr not found. [{}]:[{}]'.format(
                index, temp_addr))
        desc = test_obj.desc_dic[temp_addr]
        blind_key = test_obj.blind_key_dic[temp_addr]
        unblind_data = tx.unblind_txout(index, blind_key)
        txin_utxo_list.append(ElementsUtxoData(
            txid=txid, vout=index,
            amount=unblind_data.value.amount,
            descriptor=desc,
            value=txout.value.hex,
            asset=test_obj.pegged_asset,
            asset_blinder=unblind_data.asset_blinder,
            amount_blinder=unblind_data.amount_blinder))
    txouts2 = [
        ConfidentialTxOut(
            300000000,
            test_obj.ct_addr_dic[str(test_obj.addr_dic['main'])],
            asset=test_obj.pegged_asset),
    ]
    tx2 = ConfidentialTransaction.create(2, 0, txin_list, txouts2)
    main_addr = test_obj.addr_dic['main']
    utxos = get_utxo(elm_rpc, [fee_addr])
    utxo_list = convert_elements_utxos(test_obj, utxos)
    target_list = [TargetAmountData(
        amount=0,
        asset=test_obj.pegged_asset,
        reserved_address=fee_ct_addr)]
    tx2.fund_raw_transaction(txin_utxo_list, utxo_list,
                             target_list=target_list,
                             fee_asset=test_obj.pegged_asset,
                             effective_fee_rate=0.1,
                             knapsack_min_change=1)
    # blind
    join_utxo_list = []
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = utxo_list
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = txin_utxo_list
    blind_utxo_list = []
    for txin in tx2.txin_list:
        blind_utxo_list.append(search_utxos(
            test_obj, join_utxo_list, txin.outpoint))
    tx2.blind_txout(blind_utxo_list)
    # add sign
    for txin in tx2.txin_list:
        utxo = search_utxos(test_obj, blind_utxo_list, txin.outpoint)
        path = test_obj.path_dic[str(utxo.descriptor.data.address)]
        sk = test_obj.hdwallet.get_privkey(path=path).privkey
        tx2.sign_with_privkey(txin.outpoint, utxo.descriptor.data.hash_type,
                              sk, value=utxo.value,
                              sighashtype=SigHashType.ALL)
    # broadcast
    print(ConfidentialTransaction.parse_to_json(str(tx2), network=NETWORK))
    txid = elm_rpc.sendrawtransaction(str(tx2))
    test_obj.tx_dic[txid] = tx2
    # generate block
    elm_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)
    utxos = get_utxo(elm_rpc, [str(main_addr)])
    print('UTXO: {}'.format(utxos))


def test_elements_multisig(test_obj):
    # btc_rpc = test_obj.btcConn.get_rpc()
    elm_rpc = test_obj.elmConn.get_rpc()
    # create tx (output multisig)
    txouts = [
        ConfidentialTxOut(
            100000000,
            test_obj.ct_addr_dic[str(test_obj.addr_dic['p2sh'])],
            asset=test_obj.pegged_asset),
        ConfidentialTxOut(
            100000000,
            test_obj.ct_addr_dic[str(test_obj.addr_dic['p2wsh'])],
            asset=test_obj.pegged_asset),
        ConfidentialTxOut(
            100000000,
            test_obj.ct_addr_dic[str(test_obj.addr_dic['p2sh-p2wsh'])],
            asset=test_obj.pegged_asset),
    ]
    tx = ConfidentialTransaction.create(2, 0, [], txouts)
    # fundrawtransaction
    fee_addr = str(test_obj.addr_dic['fee'])
    fee_desc = test_obj.desc_dic[fee_addr]
    fee_ct_addr = test_obj.ct_addr_dic[fee_addr]
    fee_sk = test_obj.hdwallet.get_privkey(path=FEE_PATH).privkey
    utxos = get_utxo(elm_rpc, [fee_addr])
    utxo_list = convert_elements_utxos(test_obj, utxos)
    target_list = [TargetAmountData(
        amount=1,
        asset=test_obj.pegged_asset,
        reserved_address=fee_ct_addr)]
    tx.fund_raw_transaction([], utxo_list,
                            fee_asset=test_obj.pegged_asset,
                            target_list=target_list,
                            effective_fee_rate=0.1,
                            knapsack_min_change=1)
    # blind
    blind_utxo_list = []
    for txin in tx.txin_list:
        blind_utxo_list.append(search_utxos(
            test_obj, utxo_list, txin.outpoint))
    tx.blind_txout(blind_utxo_list)
    # add sign
    for txin in tx.txin_list:
        utxo = search_utxos(test_obj, utxo_list, txin.outpoint)
        tx.sign_with_privkey(txin.outpoint, fee_desc.data.hash_type, fee_sk,
                             value=utxo.value,
                             sighashtype=SigHashType.ALL)
    # broadcast
    print(ConfidentialTransaction.parse_to_json(str(tx), network=NETWORK))
    elm_rpc.sendrawtransaction(str(tx))
    # generate block
    elm_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)

    # create tx (output wpkh only, input multisig tx1-3)
    txid = tx.txid
    txin_list = []
    txin_utxo_list = []
    for index, txout in enumerate(tx.txout_list):
        if not txout.locking_script.hex:
            continue
        temp_addr = str(txout.get_address(network=NETWORK))
        if temp_addr == fee_addr:
            continue
        txin_list.append(ConfidentialTxIn(txid=txid, vout=index))
        if temp_addr not in test_obj.desc_dic:
            test_obj.assertTrue(False, 'addr not found. [{}]:[{}]'.format(
                index, temp_addr))
        desc = test_obj.desc_dic[temp_addr]
        blind_key = test_obj.blind_key_dic[temp_addr]
        unblind_data = tx.unblind_txout(index, blind_key)
        txin_utxo_list.append(ElementsUtxoData(
            txid=txid, vout=index,
            amount=unblind_data.value.amount,
            descriptor=desc,
            value=txout.value.hex,
            asset=test_obj.pegged_asset,
            asset_blinder=unblind_data.asset_blinder,
            amount_blinder=unblind_data.amount_blinder))
    txouts2 = [
        ConfidentialTxOut(
            300000000,
            test_obj.ct_addr_dic[str(test_obj.addr_dic['main'])],
            asset=test_obj.pegged_asset),
    ]
    tx2 = ConfidentialTransaction.create(2, 0, txin_list, txouts2)
    main_addr = test_obj.addr_dic['main']
    utxos = get_utxo(elm_rpc, [fee_addr])
    utxo_list = convert_elements_utxos(test_obj, utxos)
    target_list = [TargetAmountData(
        amount=0,
        asset=test_obj.pegged_asset,
        reserved_address=fee_ct_addr)]
    tx2.fund_raw_transaction(txin_utxo_list, utxo_list,
                             fee_asset=test_obj.pegged_asset,
                             target_list=target_list,
                             effective_fee_rate=0.1,
                             knapsack_min_change=1)
    # blind
    join_utxo_list = []
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = utxo_list
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = txin_utxo_list
    blind_utxo_list = []
    for txin in tx2.txin_list:
        blind_utxo_list.append(search_utxos(
            test_obj, join_utxo_list, txin.outpoint))
    tx2.blind_txout(blind_utxo_list)

    def multisig_sign(tx_obj, utxo, path_list):
        sighash = tx_obj.get_sighash(
            outpoint=utxo.outpoint,
            hash_type=utxo.descriptor.data.hash_type,
            value=utxo.value,
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

    # add sign
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
                                  sk, value=utxo.value,
                                  sighashtype=SigHashType.ALL)
        else:
            path_list = test_obj.path_dic[str(utxo.descriptor.data.address)]
            multisig_sign(tx2, utxo, path_list)
    # broadcast
    print(ConfidentialTransaction.parse_to_json(str(tx2), network=NETWORK))
    elm_rpc.sendrawtransaction(str(tx2))
    # generate block
    elm_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)
    utxos = get_utxo(elm_rpc, [str(main_addr)])
    print('UTXO: {}'.format(utxos))


class TestElements(unittest.TestCase):
    def setUp(self):
        logging.basicConfig()
        logging.getLogger("BitcoinRPC").setLevel(logging.DEBUG)

        # FIXME get connection from config file.

        self.path_dic = {}
        self.addr_dic = {}
        self.desc_dic = {}
        self.master_blinding_key = ''
        self.ct_addr_dic = {}
        self.blind_key_dic = {}
        self.tx_dic = {}
        self.sidechaininfo = {}
        self.pegged_asset = ''
        self.fedpegscript = ''
        self.parent_blockhash = ''
        self.pegin_confirmation_depth = 0

        self.hdwallet = HDWallet.from_mnemonic(
            MNEMONIC, passphrase=PASSPHRASE, network=MAINCHAIN_NETWORK)
        create_bitcoin_address(self)
        self.btcConn = RpcWrapper(
            port=18443, rpc_user='bitcoinrpc', rpc_password='password')
        self.elmConn = RpcWrapper(
            port=18447, rpc_user='elementsrpc', rpc_password='password')
        # init command
        btc_rpc = self.btcConn.get_rpc()
        btc_rpc.settxfee(0.00001)

    def test_elements(self):
        '''
        To execute sequentially, define only one test
        and call the test function in it.
        '''
        get_elements_config(self)
        test_import_address(self)
        test_generate_btc(self)
        test_pegin(self)
        test_elements_pkh(self)
        test_elements_multisig(self)
        # issue on RPC
        # reissue
        # send multi asset
        # destroy amount


if __name__ == "__main__":
    unittest.main()
