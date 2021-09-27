from unittest import TestCase
from tests.util import load_json_file, exec_test, assert_message,\
    assert_equal, assert_error, assert_match, get_json_file
from cfd.util import CfdError
from cfd.hdwallet import ExtPrivkey
from cfd.address import AddressUtil
from cfd.descriptor import parse_descriptor
from cfd.script import HashType
from cfd.key import Network, SigHashType, SignParameter, SchnorrUtil
from cfd.transaction import OutPoint, TxIn, TxOut, Transaction, Txid, \
    UtxoData, CODE_SEPARATOR_POSITION_FINAL
import json


def load_utxo_list(request):
    result = []
    utxos = request.get('utxos', [])
    for utxo in utxos:
        desc = utxo.get('descriptor', '')
        if not desc:
            if 'address' in utxo:
                addr = utxo['address']
                desc = f'addr({addr})'
            if 'lockingScript' in utxo:
                script = utxo['lockingScript']
                desc = f'raw({script})'
        data = UtxoData(txid=utxo['txid'], vout=utxo['vout'],
                        amount=utxo['amount'], descriptor=desc)
        result.append(data)
    return result


def test_transaction_func1(obj, name, case, req, exp, error):
    try:
        resp = None
        if 'tx' in req:
            resp = Transaction.from_hex(req['tx'])
        txins, txouts = [], []
        for input in req.get('txins', []):
            txins.append(TxIn(txid=input['txid'], vout=input['vout'],
                              sequence=input.get('sequence',
                                                 TxIn.SEQUENCE_DISABLE)))
        for output in req.get('txouts', []):
            txouts.append(TxOut(
                output['amount'], address=output.get('address', ''),
                locking_script=output.get('directLockingScript', '')))

        if name == 'Transaction.Create':
            resp = Transaction.create(req['version'], req['locktime'],
                                      txins, txouts)
        elif name == 'Transaction.Add':
            if len(txins) + len(txouts) == 1:
                for input in req.get('txins', []):
                    resp.add_txin(txid=input['txid'], vout=input['vout'],
                                  sequence=input.get('sequence',
                                                     TxIn.SEQUENCE_DISABLE))
                for output in req.get('txouts', []):
                    resp.add_txout(
                        output['amount'], address=output.get('address', ''),
                        locking_script=output.get('directLockingScript', ''))
            else:
                resp.add(txins, txouts)
        elif name == 'Transaction.UpdateTxOutAmount':
            for output in req.get('txouts', []):
                index = resp.get_txout_index(
                    address=output.get('address', ''),
                    locking_script=output.get('directLockingScript', ''))
                resp.update_txout_amount(index, output['amount'])
        elif name == 'Transaction.SplitTxOut':
            txouts = []
            for output in req.get('txouts', []):
                txouts.append(TxOut(
                    amount=output['amount'], address=output.get('address', ''),
                    locking_script=output.get('directLockingScript', '')))
            resp.split_txout(req['index'], txouts)
        elif name == 'Transaction.UpdateWitnessStack':
            txin = req['txin']
            witness = txin['witnessStack']
            data = witness['hex']
            if witness.get('derEncode', False) and (
                    witness.get('type', '') == 'sign'):
                sign_param = SignParameter.encode_by_der(
                    data, sighashtype=witness.get('sighashType', 'all'))
                data = sign_param.hex
            resp.update_witness_stack(
                OutPoint(txin['txid'], txin['vout']),
                witness.get('index', 0), data)
        elif name == 'Transaction.UpdateTxInSequence':
            resp.update_sequence(
                OutPoint(req['txid'], req['vout']), req['sequence'])
        else:
            return False
        assert_error(obj, name, case, error)

        if exp['hex'] != str(resp):
            print('hex =', str(resp))
        assert_equal(obj, name, case, exp, str(resp), 'hex')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_transaction_func2(obj, name, case, req, exp, error):
    try:
        resp = None
        txin = {}
        if 'tx' in req:
            resp = Transaction.from_hex(req['tx'])
        if 'txin' in req:
            txin = req['txin']
        if name == 'Transaction.SignWithPrivkey':
            utxos = load_utxo_list(req)
            _sighashtype = SigHashType.get(
                txin.get('sighashType', 'all'),
                anyone_can_pay=txin.get('sighashAnyoneCanPay', False),
                is_rangeproof=txin.get('sighashRangeproof', False))
            resp.sign_with_privkey(
                OutPoint(txin['txid'], txin['vout']),
                txin['hashType'],
                txin['privkey'],
                amount=txin.get('amount', 0),
                sighashtype=_sighashtype,
                grind_r=txin.get('isGrindR', True),
                utxos=utxos,
                aux_rand=txin.get('auxRand', None),
                annex=txin.get('annex', None))
        elif name == 'Transaction.AddSign':
            hash_type = HashType.P2SH
            if txin.get('isWitness', True):
                hash_type = HashType.P2WSH
            for param in txin.get('signParams', []):
                _sighashtype = SigHashType.get(
                    param.get('sighashType', 'all'),
                    anyone_can_pay=param.get('sighashAnyoneCanPay', False),
                    is_rangeproof=param.get('sighashRangeproof', False))
                encode_der = False
                if param.get('type', '') == 'sign':
                    encode_der = True
                resp.add_sign(
                    OutPoint(txin['txid'], txin['vout']),
                    hash_type,
                    param['hex'],
                    clear_stack=txin.get('clearStack', False),
                    use_der_encode=param.get('derEncode', encode_der),
                    sighashtype=_sighashtype)

        elif name == 'Transaction.AddPubkeyHashSign':
            param = txin['signParam']
            _sighashtype = SigHashType.get(
                param.get('sighashType', 'all'),
                anyone_can_pay=param.get('sighashAnyoneCanPay', False),
                is_rangeproof=param.get('sighashRangeproof', False))
            resp.add_pubkey_hash_sign(
                OutPoint(txin['txid'], txin['vout']),
                txin['hashType'],
                pubkey=txin['pubkey'],
                signature=param['hex'],
                sighashtype=_sighashtype)

        elif name == 'Transaction.AddMultisigSign':
            signature_list = []
            script = txin.get('witnessScript', txin.get('redeemScript', ''))
            for param in txin.get('signParams', []):
                _sighashtype = SigHashType.get(
                    param.get('sighashType', 'all'),
                    anyone_can_pay=param.get('sighashAnyoneCanPay', False),
                    is_rangeproof=param.get('sighashRangeproof', False))
                sign = SignParameter(
                    param['hex'],
                    sighashtype=_sighashtype,
                    use_der_encode=param.get('derEncode', True),
                    related_pubkey=param.get('relatedPubkey', ''))
                signature_list.append(sign)

            resp.add_multisig_sign(
                OutPoint(txin['txid'], txin['vout']),
                txin['hashType'],
                redeem_script=script,
                signature_list=signature_list)

        elif name == 'Transaction.AddScriptHashSign':
            signature_list = []
            for param in txin.get('signParams', []):
                _sighashtype = SigHashType.get(
                    param.get('sighashType', 'all'),
                    anyone_can_pay=param.get('sighashAnyoneCanPay', False),
                    is_rangeproof=param.get('sighashRangeproof', False))
                try:
                    sign = SignParameter(
                        param['hex'],
                        sighashtype=_sighashtype,
                        use_der_encode=param.get('derEncode', True))
                    signature_list.append(sign)
                except CfdError:
                    signature_list.append(param['hex'])

            resp.add_script_hash_sign(
                OutPoint(txin['txid'], txin['vout']),
                txin['hashType'],
                redeem_script=txin['redeemScript'],
                signature_list=signature_list)
            if 'multisig p2wsh' == case:
                print(str(resp))

        elif name == 'Transaction.AddTaprootSchnorrSign':
            _sighashtype = SigHashType.get(
                txin.get('sighashType', 'default'),
                anyone_can_pay=txin.get('sighashAnyoneCanPay', False),
                is_rangeproof=txin.get('sighashRangeproof', False))
            resp.add_taproot_sign(
                OutPoint(txin['txid'], txin['vout']),
                signature=txin['signature'],
                sighashtype=_sighashtype,
                annex=txin.get('annex', None))

        elif name == 'Transaction.AddTapscriptSign':
            signature_list = []
            for param in txin.get('signParams', []):
                _sighashtype = SigHashType.get(
                    param.get('sighashType', 'default'),
                    anyone_can_pay=param.get('sighashAnyoneCanPay', False),
                    is_rangeproof=param.get('sighashRangeproof', False))
                try:
                    sign = SignParameter(
                        param['hex'],
                        sighashtype=_sighashtype, use_der_encode=False)
                    signature_list.append(sign)
                except CfdError:
                    signature_list.append(param['hex'])

            resp.add_tapscript_sign(
                OutPoint(txin['txid'], txin['vout']),
                signature_list=signature_list,
                tapscript=txin['tapscript'],
                control_block=txin['controlBlock'],
                annex=txin.get('annex', None))

        elif name == 'Transaction.VerifySign':
            err_list = []
            utxos = load_utxo_list(req)
            for txin in req.get('txins', []):
                hash_type = HashType.P2WPKH
                addr = txin.get('address', '')
                desc = txin.get('descriptor', '')
                if desc != '':
                    desc = parse_descriptor(desc)
                    addr = desc.data.address
                    hash_type = desc.data.hash_type
                elif addr != '':
                    addr = AddressUtil.parse(addr)
                    hash_type = addr.hash_type

                try:
                    resp.verify_sign(
                        OutPoint(txin['txid'], txin['vout']),
                        addr, hash_type, txin.get('amount', 0), utxos)
                except CfdError as err:
                    _dict = {'txid': txin['txid'], 'vout': txin['vout']}
                    _dict['reason'] = err.message
                    err_list.append(_dict)

            success = (len(err_list) == 0)
            resp = {'success': success, 'failTxins': err_list}

        elif name == 'Transaction.VerifySignature':
            if txin['hashType'] == 'taproot':
                utxos = load_utxo_list(req)
                txin = req['txin']
                script = txin.get('redeemScript', '')
                pubkey = txin['pubkey'] if not script else ''
                _sighashtype = SigHashType.get(
                    txin.get('sighashType', 'all'),
                    anyone_can_pay=txin.get('sighashAnyoneCanPay', False),
                    is_rangeproof=txin.get('sighashRangeproof', False))
                sighash = resp.get_sighash(
                    OutPoint(txin['txid'], txin['vout']),
                    txin['hashType'],
                    amount=txin.get('amount', 0),
                    pubkey=pubkey,
                    redeem_script=script,
                    sighashtype=_sighashtype,
                    utxos=utxos,
                    tapleaf_hash=txin.get('', ''),
                    annex=txin.get('annex', None),
                    codeseparator_pos=txin.get('codeSeparatorPosition',
                                               CODE_SEPARATOR_POSITION_FINAL))
                resp = SchnorrUtil.verify(txin.get('signature', ''), sighash,
                                          txin['pubkey'],
                                          is_message_hashed=True)
            else:
                resp = resp.verify_signature(
                    OutPoint(txin['txid'], txin['vout']),
                    signature=txin.get('signature', ''),
                    hash_type=txin['hashType'],
                    amount=txin.get('amount', 0),
                    pubkey=txin['pubkey'],
                    redeem_script=txin.get('redeemScript', ''),
                    sighashtype=txin.get('sighashType', 'all'))

        else:
            return False
        assert_error(obj, name, case, error)

        if name == 'Transaction.VerifySign':
            assert_equal(obj, name, case, exp, resp['success'], 'success')
            assert_match(obj, name, case, len(exp['failTxins']),
                         len(exp['failTxins']), 'failTxinsLen')
            for index, txin in enumerate(resp['failTxins']):
                assert_match(obj, name, case,
                             exp['failTxins'][index]['txid'],
                             txin['txid'], 'failTxins.txid')
                assert_match(obj, name, case,
                             exp['failTxins'][index]['vout'],
                             txin['vout'], 'failTxins.vout')
                assert_match(obj, name, case,
                             exp['failTxins'][index]['reason'],
                             txin['reason'], 'failTxins.reason')
        elif name == 'Transaction.VerifySignature':
            assert_equal(obj, name, case, exp, resp, 'success')
        else:
            assert_equal(obj, name, case, exp, str(resp), 'hex')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_transaction_func3(obj, name, case, req, exp, error):
    try:
        if name == 'Transaction.Decode':
            resp = Transaction.parse_to_json(
                req.get('hex', ''), req.get('network', 'mainnet'))
        elif name in ['Transaction.CreateSighash', 'Transaction.GetSighash']:
            resp = Transaction.from_hex(req['tx'])
            utxos = load_utxo_list(req)
            txin = req['txin']
            key_data = txin['keyData']
            pubkey = key_data['hex'] if key_data['type'] == 'pubkey' else ''
            script = key_data['hex'] if key_data['type'] != 'pubkey' else ''
            _sighashtype = SigHashType.get(
                txin.get('sighashType', 'all'),
                anyone_can_pay=txin.get('sighashAnyoneCanPay', False),
                is_rangeproof=txin.get('sighashRangeproof', False))
            resp = resp.get_sighash(
                OutPoint(txin['txid'], txin['vout']),
                txin['hashType'],
                amount=txin.get('amount', 0),
                pubkey=pubkey,
                redeem_script=script,
                sighashtype=_sighashtype,
                utxos=utxos,
                tapleaf_hash=txin.get('', ''),
                annex=txin.get('annex', None),
                codeseparator_pos=txin.get('codeSeparatorPosition',
                                           CODE_SEPARATOR_POSITION_FINAL))

        elif name == 'Transaction.GetWitnessStackNum':
            resp = Transaction.from_hex(req['tx'])
            txin = req['txin']
            index = resp.get_txin_index(txid=txin['txid'], vout=txin['vout'])
            resp = len(resp.txin_list[index].witness_stack)
        elif name == 'Transaction.GetTxInIndex':
            resp = Transaction.from_hex(req['tx'])
            resp = resp.get_txin_index(txid=req['txid'], vout=req['vout'])
        elif name == 'Transaction.GetTxOutIndex':
            resp = Transaction.from_hex(req['tx'])
            index = resp.get_txout_index(
                address=req.get('address', ''),
                locking_script=req.get('directLockingScript', ''))
            indexes = resp.get_txout_indexes(
                address=req.get('address', ''),
                locking_script=req.get('directLockingScript', ''))
            resp = {
                'index': index,
                'indexes': indexes,
            }
        else:
            return False
        assert_error(obj, name, case, error)

        if name == 'Transaction.Decode':
            exp_json = json.dumps(exp)
            exp_json = exp_json.replace(', ', ',')
            exp_json = exp_json.replace('} ', '}')
            exp_json = exp_json.replace('] ', ']')
            exp_json = exp_json.replace(': ', ':')

            assert_match(obj, name, case, exp_json, resp, 'json')
        elif name == 'Transaction.GetWitnessStackNum':
            assert_equal(obj, name, case, exp, resp, 'count')
        elif name == 'Transaction.GetTxInIndex':
            assert_equal(obj, name, case, exp, resp, 'index')
        elif name == 'Transaction.GetTxOutIndex':
            assert_equal(obj, name, case, exp, resp['index'], 'index')
            assert_match(obj, name, case, len(
                exp['indexes']), len(resp['indexes']), 'indexes')
            exp_list = exp['indexes']
            idx_list = resp['indexes']
            for i in range(len(exp_list)):
                assert_match(obj, name, case, exp_list[i],
                             idx_list[i], f'indexes.${i}')
        else:
            assert_equal(obj, name, case, exp, str(resp), 'sighash')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_transaction_func(obj, name, case, req, exp, error):
    if test_transaction_func1(obj, name, case, req, exp, error):
        pass
    elif test_transaction_func2(obj, name, case, req, exp, error):
        pass
    elif test_transaction_func3(obj, name, case, req, exp, error):
        pass
    else:
        raise Exception('unknown name: ' + name)


def test_bitcoin_tx_func(obj, name, case, req, exp, error):
    try:
        resp = ''
        if name == 'Bitcoin.CoinSelection':
            # selected_utxo_list, _utxo_fee, total_amount
            utxo_list = obj.utxos.get(req['utxoFile'], [])
            fee_info = req.get('feeInfo', {})
            resp = Transaction.select_coins(
                utxo_list,
                tx_fee_amount=fee_info.get('txFeeAmount', 0),
                target_amount=req.get('targetAmount', 0),
                effective_fee_rate=fee_info.get('feeRate', 20.0),
                long_term_fee_rate=fee_info.get('longTermFeeRate', 20.0),
                dust_fee_rate=fee_info.get('dustFeeRate', 3.0),
                knapsack_min_change=fee_info.get('knapsackMinChange', -1))
        elif name == 'Bitcoin.EstimateFee':
            utxo_list = convert_bitcoin_utxo(req['selectUtxos'])
            tx = Transaction.from_hex(req['tx'])
            resp = tx.estimate_fee(
                utxo_list, fee_rate=req.get('feeRate', 20.0))
        elif name == 'Bitcoin.FundTransaction':
            tx = Transaction.from_hex(req['tx'])
            txin_utxo_list = convert_bitcoin_utxo(req['selectUtxos'])
            utxo_list = obj.utxos.get(req['utxoFile'], [])
            fee_info = req.get('feeInfo', {})
            tx_fee, used_addr = tx.fund_raw_transaction(
                txin_utxo_list,
                utxo_list,
                reserved_address=req.get('reserveAddress', ''),
                target_amount=req.get('targetAmount', 0),
                effective_fee_rate=fee_info.get('feeRate', 20.0),
                long_term_fee_rate=fee_info.get('longTermFeeRate', 20.0),
                dust_fee_rate=fee_info.get('dustFeeRate', 3.0),
                knapsack_min_change=fee_info.get('knapsackMinChange', -1))
            resp = {'hex': str(tx), 'usedAddresses': [used_addr],
                    'feeAmount': tx_fee}
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        if name == 'Bitcoin.CoinSelection':
            selected_utxo_list, utxo_fee, total_amount = resp
            assert_equal(obj, name, case, exp, total_amount, 'selectedAmount')
            assert_equal(obj, name, case, exp, utxo_fee, 'utxoFeeAmount')
            exp_list = convert_bitcoin_utxo(exp['utxos'])
            for exp_utxo in exp_list:
                if exp_utxo not in selected_utxo_list:
                    assert_message(obj, name, case,
                                   '{} is not found.'.format(str(exp_utxo)))
        elif name == 'Bitcoin.EstimateFee':
            total_fee, txout_fee, utxo_fee = resp
            assert_equal(obj, name, case, exp, total_fee, 'feeAmount')
            assert_equal(obj, name, case, exp, txout_fee, 'txoutFeeAmount')
            assert_equal(obj, name, case, exp, utxo_fee, 'utxoFeeAmount')
        elif name == 'Bitcoin.FundTransaction':
            if resp['hex'] != exp['hex']:
                print(resp['hex'])
            assert_equal(obj, name, case, exp, resp['hex'], 'hex')
            assert_equal(obj, name, case, exp, resp['feeAmount'], 'feeAmount')
            exp_addr_list = exp['usedAddresses']
            assert_match(obj, name, case, len(exp_addr_list),
                         len(resp['usedAddresses']), 'usedAddressesLen')
            assert_match(obj, name, case, exp_addr_list[0],
                         resp['usedAddresses'][0], 'usedAddresses:0')

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


def convert_bitcoin_utxo(json_utxo_list):
    utxo_list = []
    for utxo in json_utxo_list:
        if utxo.get('base', False):
            continue
        desc = utxo.get('descriptor', '')
        # if not desc:
        #     desc = ''.format(utxo['redeemScript'])
        data = UtxoData(
            txid=utxo['txid'], vout=utxo['vout'],
            amount=utxo.get('amount', 0), descriptor=desc,
            scriptsig_template=utxo.get('scriptSigTemplate', ''))
        utxo_list.append(data)
    return utxo_list


class TestTxid(TestCase):
    def test_txid(self):
        txid = 'fe0000000000000000000000000000000000000000000000000000000000ff01'  # noqa: E501
        byte_data = b'\x01\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe'  # noqa: E501
        list_data = [1, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254]  # noqa: E501
        b_array = bytearray(list_data)
        _txid1 = Txid(txid)
        _txid2 = Txid(byte_data)
        _txid3 = Txid(list_data)
        _txid4 = Txid(b_array)
        self.assertEqual(txid, str(_txid1))
        self.assertEqual(txid, str(_txid2))
        self.assertEqual(txid, str(_txid3))
        self.assertEqual(txid, str(_txid4))
        self.assertEqual(byte_data, _txid1.as_bytes())
        self.assertEqual(list_data, _txid1.as_array())


class TestOutPoint(TestCase):
    def test_outpoint(self):
        txid = '0000000000000000000000000000000000000000000000000000000000000001'  # noqa: E501
        outpoint1 = OutPoint(txid, 2)
        outpoint2 = OutPoint(txid, 3)
        self.assertTrue(outpoint1 < outpoint2)
        self.assertTrue(outpoint1 <= outpoint2)
        self.assertFalse(outpoint1 > outpoint2)
        self.assertFalse(outpoint1 >= outpoint2)
        self.assertFalse(outpoint1 == outpoint2)
        self.assertFalse(outpoint1 != outpoint1)
        self.assertTrue(outpoint1 != outpoint2)


class TestUtxoData(TestCase):
    def test_utxo_data(self):
        txid = '0000000000000000000000000000000000000000000000000000000000000001'  # noqa: E501
        utxo1 = UtxoData(txid=txid, vout=2)
        utxo2 = UtxoData(txid=txid, vout=3)
        self.assertTrue(utxo1 < utxo2)
        self.assertTrue(utxo1 <= utxo2)
        self.assertFalse(utxo1 > utxo2)
        self.assertFalse(utxo1 >= utxo2)
        self.assertFalse(utxo1 == utxo2)
        self.assertFalse(utxo1 != utxo1)
        self.assertTrue(utxo1 != utxo2)
        self.assertEqual('{},{}'.format(txid, 2), str(utxo1))


class TestTransaction(TestCase):
    def setUp(self):
        self.test_list = load_json_file('transaction_test.json')
        self.test_list += load_json_file('bitcoin_coin_test.json')
        self.utxos = {}
        self.utxos['utxo_1'] = convert_bitcoin_utxo(
            get_json_file('utxo/utxo_1.json'))
        self.utxos['utxo_2'] = convert_bitcoin_utxo(
            get_json_file('utxo/utxo_2.json'))
        self.utxos['utxo_3'] = convert_bitcoin_utxo(
            get_json_file('utxo/utxo_3.json'))

    def test_transaction(self):
        exec_test(self, 'Transaction', test_transaction_func)

    def test_bitcoin_tx(self):
        exec_test(self, 'Bitcoin', test_bitcoin_tx_func)

    def test_create_raw_transaction(self):
        privkey = ExtPrivkey(
            'xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV')  # noqa: E501
        addr1 = AddressUtil.p2wpkh(
            privkey.derive_pubkey(number=1).pubkey, Network.REGTEST)
        addr2 = AddressUtil.p2wpkh(
            privkey.derive_pubkey(number=2).pubkey, Network.REGTEST)
        addr3 = AddressUtil.p2wpkh(
            privkey.derive_pubkey(number=3).pubkey, Network.REGTEST)

        outpoint1 = OutPoint(
            '0000000000000000000000000000000000000000000000000000000000000001',
            2)
        outpoint2 = OutPoint(
            '0000000000000000000000000000000000000000000000000000000000000001',
            3)
        txin1 = TxIn(outpoint=outpoint1)
        txout1 = TxOut(amount=10000, locking_script=addr1.locking_script)
        txout2 = TxOut(amount=10000, address=addr2)
        self.assertEqual(str(outpoint1), str(txin1))
        self.assertEqual(str(addr1.locking_script), str(txout1))
        self.assertEqual(str(addr2), str(txout2))
        self.assertEqual(str(addr1), str(txout1.get_address(Network.REGTEST)))

        tx = Transaction.create(
            version=2,
            locktime=0,
            txins=[
                txin1,
                TxIn(outpoint=outpoint2),
            ],
            txouts=[
                txout1,
                txout2,
            ])
        tx.add_txout(amount=50000, address=addr3)
        self.assertEqual(
            "020000000201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c00000000",  # noqa: E501
            tx.hex)

        privkey1 = privkey.derive(number=11).privkey
        pubkey1 = privkey1.pubkey
        sighash_type = SigHashType.ALL
        sighash = tx.get_sighash(
            outpoint=outpoint1,
            hash_type=HashType.P2WPKH,
            pubkey=pubkey1,
            amount=50000,
            sighashtype=sighash_type)
        signature = privkey1.calculate_ec_signature(sighash)
        tx.add_sign(
            outpoint=outpoint1,
            hash_type=HashType.P2WPKH,
            sign_data=signature,
            clear_stack=True,
            use_der_encode=True,
            sighashtype=sighash_type)
        tx.add_sign(
            outpoint=outpoint1,
            hash_type=HashType.P2WPKH,
            sign_data=pubkey1)
        self.assertEqual(
            "0200000000010201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c02473044022034db802aad655cd9be589075fc8ef325b6ffb8c24e5b27eb87bde8ad38f5fd7a0220364c916c8e8fc0adf714d7148cd1c6dc6f3e67d55471e57233b1870c65ec2727012103782f0ea892d7000e5f0f82b6ff283382a76500137a542bb0a616530094a8f54c0000000000",  # noqa: E501
            tx.hex)

    def test_empty_input(self):
        txout = TxOut(1000)
        self.assertEqual('', str(txout.locking_script))
