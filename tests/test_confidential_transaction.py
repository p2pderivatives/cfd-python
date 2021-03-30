import json
import typing
from typing import List
from unittest import TestCase
from tests.util import load_json_file, get_json_file, exec_test,\
    assert_equal, assert_error, assert_match, assert_message
from cfd.util import CfdError
from cfd.address import AddressUtil
from cfd.descriptor import parse_descriptor
from cfd.script import HashType
from cfd.key import SigHashType, SignParameter, Network
from cfd.transaction import OutPoint, TxIn
from cfd.confidential_transaction import BlindData, ConfidentialTxOut,\
    ConfidentialTransaction, ElementsUtxoData, IssuanceKeyPair,\
    TargetAmountData, Issuance, UnblindData,\
    IssuanceAssetBlindData, IssuanceTokenBlindData


def test_ct_transaction_func1(obj, name, case, req, exp, error):
    try:
        def get_tx():
            resp = ''
            if 'tx' in req:
                resp = ConfidentialTransaction.from_hex(req['tx'])
            txins, txouts = [], []
            for input in req.get('txins', []):
                txins.append(TxIn(txid=input['txid'], vout=input['vout'],
                                  sequence=input.get('sequence',
                                                     TxIn.SEQUENCE_DISABLE)))
            for output in req.get('txouts', []):
                txouts.append(ConfidentialTxOut(
                    output['amount'], address=output.get('address', ''),
                    locking_script=output.get('directLockingScript', ''),
                    asset=output.get('asset', ''),
                    nonce=output.get('directNonce', '')))
            for output in req.get('destroyAmountTxouts', []):
                txouts.append(ConfidentialTxOut.for_destroy_amount(
                    output['amount'], asset=output.get('asset', ''),
                    nonce=output.get('directNonce', '')))
            if 'fee' in req:
                output = req['fee']
                if 'amount' in output:
                    txouts.append(ConfidentialTxOut.for_fee(
                        output['amount'], asset=output.get('asset', '')))
            return resp, txins, txouts

        if name == 'ConfidentialTransaction.Create':
            resp, txins, txouts = get_tx()
            resp = ConfidentialTransaction.create(
                req['version'], req['locktime'], txins, txouts)
        elif name == 'ConfidentialTransaction.Add':
            resp, txins, txouts = get_tx()
            if len(txins) + len(txouts) == 1:
                for input in req.get('txins', []):
                    resp.add_txin(txid=input['txid'], vout=input['vout'],
                                  sequence=input.get('sequence',
                                                     TxIn.SEQUENCE_DISABLE))
                for output in req.get('txouts', []):
                    resp.add_txout(
                        output['amount'], address=output.get('address', ''),
                        locking_script=output.get('directLockingScript', ''),
                        asset=output.get('asset', ''),
                        nonce=output.get('directNonce', ''))
                for output in req.get('destroyAmountTxouts', []):
                    resp.add_destroy_amount_txout(
                        output['amount'], output.get('asset', ''),
                        nonce=output.get('directNonce', ''))
                if ('fee' in req) and ('amount' in req['fee']):
                    output = req['fee']
                    resp.add_fee_txout(
                        output['amount'], output.get('asset', ''))
            else:
                resp.add(txins, txouts)
        elif name == 'ConfidentialTransaction.UpdateTxOutAmount':
            resp, txins, txouts = get_tx()
            for output in req.get('txouts', []):
                if 'index' in output:
                    index = output['index']
                else:
                    index = resp.get_txout_index(
                        address=output.get('address', ''),
                        locking_script=output.get('directLockingScript', ''))
                resp.update_txout_amount(index, output['amount'])
        elif name == 'ConfidentialTransaction.UpdateWitnessStack':
            resp, txins, txouts = get_tx()
            # FIXME impl
            return True

        elif name == 'ConfidentialTransaction.UpdateTxOutFeeAmount':
            resp, _, _ = get_tx()
            resp.update_txout_fee_amount(req['feeAmount'])
        else:
            return False
        assert_error(obj, name, case, error)

        assert_equal(obj, name, case, exp, str(resp), 'hex')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_ct_transaction_func2(obj, name, case, req, exp, error):
    try:
        def get_tx():
            resp, txin = None, None
            if 'tx' in req:
                resp = ConfidentialTransaction.from_hex(req['tx'])
            if 'txin' in req:
                txin = req['txin']
            return resp, txin

        if name == 'ConfidentialTransaction.SignWithPrivkey':
            resp, txin = get_tx()
            _sighashtype = SigHashType.get(
                txin.get('sighashType', 'all'),
                txin.get('sighashAnyoneCanPay', False))
            resp.sign_with_privkey(
                OutPoint(txin['txid'], txin['vout']),
                txin['hashType'],
                txin['privkey'],
                value=txin.get('confidentialValueCommitment',
                               txin.get('amount', 0)),
                sighashtype=_sighashtype)
        elif name == 'ConfidentialTransaction.AddSign':
            resp, txin = get_tx()
            hash_type = HashType.P2SH
            if txin.get('isWitness', True):
                hash_type = HashType.P2WSH
            for param in txin.get('signParams', []):
                _sighashtype = SigHashType.get(
                    param.get('sighashType', 'all'),
                    param.get('sighashAnyoneCanPay', False))
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

        elif name == 'ConfidentialTransaction.AddPubkeyHashSign':
            resp, txin = get_tx()
            param = txin['signParam']
            _sighashtype = SigHashType.get(
                param.get('sighashType', 'all'),
                param.get('sighashAnyoneCanPay', False))
            resp.add_pubkey_hash_sign(
                OutPoint(txin['txid'], txin['vout']),
                txin['hashType'],
                pubkey=txin['pubkey'],
                signature=param['hex'],
                sighashtype=_sighashtype)

        elif name == 'ConfidentialTransaction.AddMultisigSign':
            resp, txin = get_tx()
            signature_list = []
            script = txin.get('witnessScript', txin.get('redeemScript', ''))
            for param in txin.get('signParams', []):
                _sighashtype = SigHashType.get(
                    param.get('sighashType', 'all'),
                    param.get('sighashAnyoneCanPay', False))
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

        elif name == 'ConfidentialTransaction.AddScriptHashSign':
            resp, txin = get_tx()
            signature_list = []
            for param in txin.get('signParams', []):
                _sighashtype = SigHashType.get(
                    param.get('sighashType', 'all'),
                    param.get('sighashAnyoneCanPay', False))
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

        elif name == 'ConfidentialTransaction.VerifySign':
            resp, txin = get_tx()
            err_list = []
            for txin in req.get('txins', []):
                hash_type = HashType.P2WPKH
                addr = txin.get('address', '')
                desc = txin.get('descriptor', '')
                if desc != '':
                    desc = parse_descriptor(desc, network=Network.LIQUID_V1)
                    addr = desc.data.address
                    hash_type = desc.data.hash_type
                elif addr != '':
                    addr = AddressUtil.parse(addr)
                    hash_type = addr.hash_type

                try:
                    resp.verify_sign(
                        OutPoint(txin['txid'], txin['vout']),
                        addr, hash_type,
                        txin.get('confidentialValueCommitment',
                                 txin.get('amount', 0)))
                except CfdError as err:
                    _dict = {'txid': txin['txid'], 'vout': txin['vout']}
                    _dict['reason'] = err.message
                    err_list.append(_dict)

            success = (len(err_list) == 0)
            resp = {'success': success, 'failTxins': err_list}

        elif name == 'ConfidentialTransaction.VerifySignature':
            resp, txin = get_tx()
            resp = resp.verify_signature(
                OutPoint(txin['txid'], txin['vout']),
                signature=txin.get('signature', ''),
                hash_type=txin['hashType'],
                pubkey=txin['pubkey'],
                value=txin.get('confidentialValueCommitment',
                               txin.get('amount', 0)),
                redeem_script=txin.get('redeemScript', ''),
                sighashtype=txin.get('sighashType', 'all'))

        else:
            return False
        assert_error(obj, name, case, error)

        if name == 'ConfidentialTransaction.VerifySign':
            assert_match(obj, name, case, len(exp['failTxins']),
                         len(resp['failTxins']), 'failTxinsLen')
            assert_equal(obj, name, case, exp, resp['success'], 'success')
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
        elif name == 'ConfidentialTransaction.VerifySignature':
            assert_equal(obj, name, case, exp, resp, 'success')
        else:
            if str(resp) != exp['hex']:
                print(str(resp))
            assert_equal(obj, name, case, exp, str(resp), 'hex')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_ct_transaction_func3(obj, name, case, req, exp, error):
    try:
        if name == 'ConfidentialTransaction.Decode':
            resp = ConfidentialTransaction.parse_to_json(
                req.get('hex', ''), req.get('network', 'mainnet'),
                req.get('fullDump', False))
        elif name == 'ConfidentialTransaction.CreateSighash':
            resp = ConfidentialTransaction.from_hex(req['tx'])
            txin = req['txin']
            key_data = txin['keyData']
            pubkey = key_data['hex'] if key_data['type'] == 'pubkey' else ''
            script = key_data['hex'] if key_data['type'] != 'pubkey' else ''
            _sighashtype = SigHashType.get(
                txin.get('sighashType', 'all'),
                txin.get('sighashAnyoneCanPay', False))
            resp = resp.get_sighash(
                OutPoint(txin['txid'], txin['vout']),
                txin['hashType'],
                value=txin.get('confidentialValueCommitment',
                               txin.get('amount', 0)),
                pubkey=pubkey,
                redeem_script=script,
                sighashtype=_sighashtype)
        elif name == 'ConfidentialTransaction.GetWitnessStackNum':
            resp = ConfidentialTransaction.from_hex(req['tx'])
            txin = req['txin']
            index = resp.get_txin_index(txid=txin['txid'], vout=txin['vout'])
            resp = len(resp.txin_list[index].witness_stack)
        else:
            return False
        assert_error(obj, name, case, error)

        if name == 'ConfidentialTransaction.Decode':
            exp_json = json.dumps(exp)
            exp_json = exp_json.replace(', ', ',')
            exp_json = exp_json.replace('} ', '}')
            exp_json = exp_json.replace('] ', ']')
            exp_json = exp_json.replace(': ', ':')

            assert_match(obj, name, case, exp_json, resp, 'json')
        elif name == 'ConfidentialTransaction.GetWitnessStackNum':
            assert_equal(obj, name, case, exp, resp, 'count')
        else:
            assert_equal(obj, name, case, exp, str(resp), 'sighash')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_ct_transaction_func4(obj, name, case, req, exp, error):
    try:
        resp = ''
        if name == 'ConfidentialTransaction.BlindingKey.Default':
            if 'lockingScript' in req:
                script = req['lockingScript']
            else:
                addr = AddressUtil.parse(req['address'])
                script = addr.locking_script
            resp = ConfidentialTransaction.get_default_blinding_key(
                req['masterBlindingKey'], script)
        elif name == 'ConfidentialTransaction.BlindingKey.Issuance':
            resp = ConfidentialTransaction.get_issuance_blinding_key(
                req['masterBlindingKey'], req['txid'], req['vout'])
        elif name == 'ConfidentialTransaction.CreateRawPegin':
            # FIXME: implement
            return True
        elif name == 'ConfidentialTransaction.CreateRawPegout':
            # FIXME: implement
            return True
        elif name == 'ConfidentialTransaction.CreateDestroyAmount':
            # FIXME: implement
            resp = ConfidentialTransaction.create(
                req['version'], req['locktime'])
            for input in req.get('txins', []):
                resp.add_txin(txid=input['txid'], vout=input['vout'],
                              sequence=input.get('sequence',
                                                 TxIn.SEQUENCE_DISABLE))
            for output in req.get('txouts', []):
                resp.add_txout(
                    output['amount'], address=output.get('address', ''),
                    locking_script=output.get('directLockingScript', ''),
                    asset=output.get('asset', ''),
                    nonce=output.get('directNonce', ''))
            destroy = req.get('destroy', {})
            resp.add_destroy_amount_txout(
                destroy['amount'], destroy.get('asset', ''),
                nonce=destroy.get('directNonce', ''))
            if ('fee' in req) and ('amount' in req['fee']):
                output = req['fee']
                resp.add_fee_txout(
                    output['amount'], output.get('asset', ''))
        elif name == 'ConfidentialTransaction.SetIssueAsset':
            # FIXME: implement
            return True
        elif name == 'ConfidentialTransaction.Unblind':
            outputs = []
            issuance_outputs = []
            resp = ConfidentialTransaction.from_hex(req['tx'])
            for output in req.get('txouts', []):
                txout = resp.unblind_txout(
                    output['index'], output['blindingKey'])
                outputs.append({
                    'index': output['index'],
                    'asset': str(txout.asset),
                    'blindFactor': str(txout.amount_blinder),
                    'assetBlindFactor': str(txout.asset_blinder),
                    'amount': txout.value.amount
                })
            for output in req.get('issuances', []):
                index = resp.get_txin_index(txid=output['txid'],
                                            vout=output['vout'])
                issuance = resp.unblind_issuance(
                    index, output['assetBlindingKey'],
                    output.get('tokenBlindingKey', output['assetBlindingKey']))
                issuance_outputs.append({
                    'txid': output['txid'],
                    'vout': output['vout'],
                    'asset': str(issuance[0].asset),
                    'assetamount': issuance[0].value.amount,
                    'token': str(issuance[1].asset),
                    'tokenamount': issuance[1].value.amount
                })
            resp = {'outputs': outputs, 'issuanceOutputs': issuance_outputs}
        elif name == 'ConfidentialTransaction.SetReissueAsset':
            resp = ConfidentialTransaction.from_hex(req['tx'])
            issuances = []
            for issuance in req.get('issuances', []):
                utxo = ElementsUtxoData(
                    txid=issuance['txid'], vout=issuance['vout'],
                    amount=issuance['amount'],
                    asset_blinder=issuance['assetBlindingNonce'])
                asset = resp.set_raw_reissue_asset(
                    utxo, issuance['amount'], issuance['address'],
                    issuance['assetEntropy'])
                issuances.append({
                    'txid': str(issuance['txid']),
                    'vout': issuance['vout'],
                    'asset': str(asset),
                    'entropy': str(issuance['assetEntropy'])
                })
            resp = {'hex': str(resp), 'issuances': issuances}
        elif name == 'ConfidentialTransaction.Blind':
            resp = ConfidentialTransaction.from_hex(req['tx'])
            utxo_list = []
            issuance_key_map = {}
            ct_addr_list = req.get('txoutConfidentialAddresses', [])
            txout_map = {}
            for txin in req.get('txins', []):
                utxo = ElementsUtxoData(
                    txid=txin['txid'], vout=txin['vout'],
                    amount=txin['amount'], asset=txin['asset'],
                    asset_blinder=txin['assetBlindFactor'],
                    amount_blinder=txin['blindFactor'])
                utxo_list.append(utxo)
            for issuance in req.get('issuances', []):
                outpoint = OutPoint(issuance['txid'], issuance['vout'])
                issuance_key_map[str(outpoint)] = IssuanceKeyPair(
                    issuance['assetBlindingKey'], issuance['tokenBlindingKey'])
            for output in req.get('txouts', []):
                txout_map[str(output['index'])] = output['confidentialKey']
            if issuance_key_map:
                blinder_list = resp.blind(
                    utxo_list,
                    issuance_key_map=issuance_key_map,
                    confidential_address_list=ct_addr_list,
                    direct_confidential_key_map=txout_map,
                    minimum_range_value=req.get('minimumRangeValue', 1),
                    exponent=req.get('exponent', 0),
                    minimum_bits=req.get('minimumBits', -1),
                    collect_blinder=True)
            else:
                blinder_list = resp.blind_txout(
                    utxo_list,
                    confidential_address_list=ct_addr_list,
                    direct_confidential_key_map=txout_map,
                    minimum_range_value=req.get(
                        'minimumRangeValue', 1),
                    exponent=req.get('exponent', 0),
                    minimum_bits=req.get('minimumBits', -1),
                    collect_blinder=True)

            resp = {'size': resp.size, 'vsize': resp.vsize,
                    'tx': resp, 'blinder_list': blinder_list,
                    'req_output': req.get('txouts', [])}
        else:
            return False
        assert_error(obj, name, case, error)

        if name == 'ConfidentialTransaction.Unblind':
            assert_match(obj, name, case, len(exp['outputs']),
                         len(resp['outputs']), 'outputsLen')
            exp_issuances = exp.get('issuanceOutputs', [])
            assert_match(obj, name, case, len(exp_issuances),
                         len(resp['issuanceOutputs']),
                         'issuanceOutputsLen')
            for index, output in enumerate(resp['outputs']):
                assert_match(obj, name, case,
                             exp['outputs'][index]['index'],
                             output['index'], 'outputs.index')
                assert_match(obj, name, case,
                             exp['outputs'][index]['asset'],
                             output['asset'], 'outputs.asset')
                assert_match(obj, name, case,
                             exp['outputs'][index]['blindFactor'],
                             output['blindFactor'], 'outputs.blindFactor')
                assert_match(obj, name, case,
                             exp['outputs'][index]['assetBlindFactor'],
                             output['assetBlindFactor'],
                             'outputs.assetBlindFactor')
                assert_match(obj, name, case,
                             exp['outputs'][index]['amount'],
                             output['amount'], 'outputs.amount')
            for index, output in enumerate(resp['issuanceOutputs']):
                assert_match(obj, name, case,
                             exp_issuances[index]['txid'],
                             output['txid'], 'issuanceOutputs.txid')
                assert_match(obj, name, case,
                             exp_issuances[index]['vout'],
                             output['vout'], 'issuanceOutputs.vout')
                assert_match(obj, name, case,
                             exp_issuances[index]['asset'],
                             output['asset'], 'issuanceOutputs.asset')
                assert_match(obj, name, case,
                             exp_issuances[index]['assetamount'],
                             output['assetamount'],
                             'issuanceOutputs.assetamount')
                assert_match(obj, name, case,
                             exp_issuances[index]['token'],
                             output['token'], 'issuanceOutputs.token')
                assert_match(obj, name, case,
                             exp_issuances[index]['tokenamount'],
                             output['tokenamount'],
                             'issuanceOutputs.tokenamount')
        elif name == 'ConfidentialTransaction.SetReissueAsset':
            assert_equal(obj, name, case, exp, str(resp['hex']), 'hex')
            assert_match(obj, name, case, len(exp['issuances']),
                         len(resp['issuances']), 'issuancesLen')
            for index, output in enumerate(resp['issuances']):
                assert_match(obj, name, case,
                             exp['issuances'][index]['txid'],
                             output['txid'], 'issuances.txid')
                assert_match(obj, name, case,
                             exp['issuances'][index]['vout'],
                             output['vout'], 'issuances.vout')
                assert_match(obj, name, case,
                             exp['issuances'][index]['asset'],
                             output['asset'], 'issuances.asset')
                assert_match(obj, name, case,
                             exp['issuances'][index]['entropy'],
                             output['entropy'], 'issuances.entropy')

        elif name == 'ConfidentialTransaction.Blind':
            if resp['size'] < exp['minSize']:
                obj.assertEqual(exp['minSize'], resp['size'],
                                'Fail: {}:{}:{}'.format(name, case, 'minSize'))
            elif exp['maxSize'] < resp['size']:
                obj.assertEqual(exp['maxSize'], resp['size'],
                                'Fail: {}:{}:{}'.format(name, case, 'maxSize'))
            if resp['vsize'] < exp['minVsize']:
                obj.assertEqual(exp['minVsize'], resp['vsize'],
                                'Fail: {}:{}:{}'.format(
                                    name, case, 'minVsize'))
            elif exp['maxVsize'] < resp['vsize']:
                obj.assertEqual(exp['maxVsize'], resp['vsize'],
                                'Fail: {}:{}:{}'.format(
                                    name, case, 'maxVsize'))
            txout_list = resp['req_output']
            tx = typing.cast('ConfidentialTransaction', resp['tx'])
            blinder_list = typing.cast(
                typing.List[typing.Union[
                    'BlindData', 'IssuanceAssetBlindData',
                    'IssuanceTokenBlindData']], resp['blinder_list'])
            blinding_keys = exp.get('blindingKeys', [])
            issuance_list = exp.get('issuanceList', [])
            txout_index_list = []
            for index, txout in enumerate(tx.txout_list):
                if txout.value.has_blind():
                    txout_index_list.append(index)
            for blind_index, blinder in enumerate(blinder_list):
                is_find = False
                data = {}
                has_asset = isinstance(blinder, IssuanceAssetBlindData)
                has_token = isinstance(blinder, IssuanceTokenBlindData)
                if has_asset or has_token:
                    for exp_issuance in issuance_list:
                        outpoint = OutPoint(
                            exp_issuance['txid'], exp_issuance['vout'])
                        if outpoint == blinder.outpoint:
                            data = tx.unblind_issuance(
                                blinder.vout,
                                exp_issuance['assetBlindingKey'],
                                exp_issuance.get('tokenBlindingKey', ''))
                            is_find = True
                            data = data[0] if has_asset else data[1]
                            break
                else:
                    for index, txout in enumerate(txout_list):
                        if txout['index'] == blinder.vout:
                            is_find = True
                            data = tx.unblind_txout(
                                blinder.vout, blinding_keys[index])
                            break
                    if not is_find:
                        for index, txout_index in enumerate(txout_index_list):
                            if txout_index == blinder.vout:
                                is_find = True
                                data = tx.unblind_txout(
                                    blinder.vout, blinding_keys[index])
                                break
                obj.assertEqual(
                    True, is_find,
                    f'Fail: {name}:{case}:blind_index:{blind_index}')
                if is_find:
                    obj.assertEqual(
                        str(data.asset), str(blinder.asset),
                        f'Fail: {name}:{case}:asset:{blind_index}')
                    obj.assertEqual(
                        data.value.amount, blinder.value.amount,
                        f'Fail: {name}:{case}:value:{blind_index}')
                    obj.assertEqual(
                        str(data.asset_blinder),
                        str(blinder.asset_blinder),
                        f'Fail: {name}:{case}:asset_blinder:' +
                        f'{blind_index}')
                    obj.assertEqual(
                        str(data.amount_blinder),
                        str(blinder.amount_blinder),
                        f'Fail: {name}:{case}:blinder:{blind_index}')
        else:
            assert_equal(obj, name, case, exp, str(resp), 'blindingKey')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_ct_transaction_func(obj, name, case, req, exp, error):
    if test_ct_transaction_func1(obj, name, case, req, exp, error):
        pass
    elif test_ct_transaction_func2(obj, name, case, req, exp, error):
        pass
    elif test_ct_transaction_func3(obj, name, case, req, exp, error):
        pass
    elif test_ct_transaction_func4(obj, name, case, req, exp, error):
        pass
    else:
        raise Exception('unknown name: ' + name)


def test_parse_tx_func(obj, name, case, req, exp, error):
    try:
        ignore_list = ['empty hex string', 'invalid hex string(3 chars)',
                       'invalid hex format', 'invalid elements network type']
        if case in ignore_list:
            return  # ignore testcase

        resp = ConfidentialTransaction.from_hex(req['hex'])
        assert_error(obj, name, case, error)

        exp_vin_list = exp.get('vin', [])
        exp_vout_list = exp.get('vout', [])
        assert_match(obj, name, case, len(exp_vin_list),
                     len(resp.txin_list), 'vin.len')
        assert_match(obj, name, case, len(exp_vout_list),
                     len(resp.txout_list), 'vout.len')
        empty_32byte = '00' * 32
        for index, txin in enumerate(resp.txin_list):
            exp_txin = exp_vin_list[index]
            if 'coinbase' in exp_txin:
                assert_match(obj, name, case, empty_32byte,
                             str(txin.outpoint.txid), 'txin.txid')
                assert_match(obj, name, case, 0xffffffff,
                             txin.outpoint.vout, 'txin.vout')
                assert_match(obj, name, case, exp_txin['coinbase'],
                             str(txin.script_sig), 'txin.coinbase')
            else:
                assert_match(obj, name, case, exp_txin['txid'],
                             str(txin.outpoint.txid), 'txin.txid')
                assert_match(obj, name, case, exp_txin['vout'],
                             txin.outpoint.vout, 'txin.vout')
                assert_match(obj, name, case, exp_txin['scriptSig']['hex'],
                             str(txin.script_sig), 'txin.scriptSig')

            assert_match(obj, name, case, exp_txin['sequence'],
                         txin.sequence, 'txin.sequence')
            assert_match(obj, name, case, len(exp_txin.get('txinwitness', [])),
                         len(txin.witness_stack), 'txin.witness_stack.length')
            for idx, stack in enumerate(txin.witness_stack):
                assert_match(obj, name, case, exp_txin['txinwitness'][idx],
                             str(stack), f'txin.witness_stack[{idx}]')
            is_pegin = True if len(txin.pegin_witness_stack) else False
            assert_match(obj, name, case, exp_txin.get('is_pegin', False),
                         is_pegin, 'is_pegin')
            if is_pegin:
                assert_match(obj, name, case, len(exp_txin['pegin_witness']),
                             len(txin.pegin_witness_stack),
                             'txin.pegin_witness_stack.length')
                for idx, stack in enumerate(txin.pegin_witness_stack):
                    assert_match(obj, name, case,
                                 exp_txin['pegin_witness'][idx],
                                 str(stack),
                                 f'txin.pegin_witness_stack[{idx}]')
            is_issuance = False
            if txin.issuance.asset_value.has_blind() or (
                    txin.issuance.asset_value.amount > 0):
                is_issuance = True
            exp_is_issuance = True if 'issuance' in exp_txin else False
            assert_match(obj, name, case, exp_is_issuance,
                         is_issuance, 'is_issuance')
            if is_issuance:
                exp_issuance = exp_txin['issuance']
                # assert_match(obj, name, case,
                #              exp_issuance['assetEntropy'],
                #              str(txin.issuance.entropy),
                #              'txin.issuance.assetEntropy')
                assert_match(obj, name, case,
                             exp_issuance['assetBlindingNonce'],
                             str(txin.issuance.nonce),
                             'txin.issuance.assetBlindingNonce')
                if 'assetamountcommitment' in exp_issuance:
                    assert_match(obj, name, case,
                                 exp_issuance['assetamountcommitment'],
                                 str(txin.issuance.asset_value.hex),
                                 'txin.issuance.assetamountcommitment')
                else:
                    assert_match(obj, name, case,
                                 exp_issuance['assetamount'],
                                 txin.issuance.asset_value.amount,
                                 'txin.issuance.assetamount')
                if 'tokenamountcommitment' in exp_issuance:
                    assert_match(obj, name, case,
                                 exp_issuance['tokenamountcommitment'],
                                 str(txin.issuance.token_value.hex),
                                 'txin.issuance.tokenamountcommitment')
                elif 'tokenamount' in exp_issuance:
                    assert_match(obj, name, case,
                                 exp_issuance['tokenamount'],
                                 txin.issuance.token_value.amount,
                                 'txin.issuance.tokenamount')

        for index, txout in enumerate(resp.txout_list):
            exp_txout = exp_vout_list[index]
            if 'valuecommitment' in exp_txout:
                assert_match(obj, name, case, exp_txout['valuecommitment'],
                             str(txout.value), 'txout.valuecommitment')
                assert_match(obj, name, case, exp_txout['assetcommitment'],
                             str(txout.asset), 'txout.assetcommitment')
                assert_match(obj, name, case, exp_txout['commitmentnonce'],
                             str(txout.nonce), 'txout.commitmentnonce')
            else:
                assert_match(obj, name, case, exp_txout['value'],
                             txout.value.amount, 'txout.value')
                assert_match(obj, name, case, exp_txout['asset'],
                             str(txout.asset), 'txout.asset')
                assert_match(obj, name, case, exp_txout['commitmentnonce'],
                             str(txout.nonce), 'txout.commitmentnonce')

            assert_match(obj, name, case,
                         exp_txout['scriptPubKey']['hex'],
                         str(txout.locking_script), 'txout.locking_script')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_elements_tx_func(obj, name, case, req, exp, error):
    try:
        coin_resp = ()
        resp = ()
        if name == 'Elements.CoinSelection':
            # selected_utxo_list, _utxo_fee, total_amount_map
            utxo_list = obj.utxos.get(req['utxoFile'], [])
            target_list = convert_target_amount(req['targets'])
            fee_info = req.get('feeInfo', {})
            fee_rate = fee_info.get('feeRate', 20.0)
            coin_resp = ConfidentialTransaction.select_coins(
                utxo_list,
                tx_fee_amount=fee_info.get('txFeeAmount', 0),
                target_list=target_list,
                fee_asset=fee_info.get('feeAsset', ''),
                effective_fee_rate=fee_rate,
                long_term_fee_rate=fee_info.get('longTermFeeRate', fee_rate),
                dust_fee_rate=fee_info.get('dustFeeRate', -1),
                knapsack_min_change=fee_info.get('knapsackMinChange', -1),
                exponent=fee_info.get('exponent', 0),
                minimum_bits=fee_info.get('minimumBits', 52))
        elif name == 'Elements.EstimateFee':
            utxo_list = convert_elements_utxo(req['selectUtxos'])
            tx = ConfidentialTransaction.from_hex(req['tx'])
            resp = tx.estimate_fee(
                utxo_list, fee_rate=req.get('feeRate', 0.15),
                fee_asset=req.get('feeAsset', ''),
                is_blind=req.get('isBlind', True),
                exponent=req.get('exponent', 0),
                minimum_bits=req.get('minimumBits', 52))
        elif name == 'Elements.FundTransaction':
            tx = ConfidentialTransaction.from_hex(req['tx'])
            txin_utxo_list = convert_elements_utxo(req['selectUtxos'])
            utxo_list = obj.utxos.get(req['utxoFile'], [])
            target_list = convert_target_amount(req['targets'])
            fee_info = req.get('feeInfo', {})
            tx_fee, used_addr_list = tx.fund_raw_transaction(
                txin_utxo_list,
                utxo_list,
                target_list,
                fee_asset=fee_info.get('feeAsset', -1),
                effective_fee_rate=fee_info.get('feeRate', 20.0),
                long_term_fee_rate=fee_info.get('longTermFeeRate', 20.0),
                dust_fee_rate=fee_info.get('dustFeeRate', 3.0),
                knapsack_min_change=fee_info.get('knapsackMinChange', -1),
                is_blind=req.get('isBlind', True),
                exponent=req.get('exponent', 0),
                minimum_bits=req.get('minimumBits', 52))
            resp = {'hex': str(tx), 'usedAddresses': used_addr_list,
                    'feeAmount': tx_fee}
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        if name == 'Elements.CoinSelection':
            # selected_utxo_list, _utxo_fee, total_amount_map
            selected_utxo_list, utxo_fee, total_amount_map = coin_resp
            assert_equal(obj, name, case, exp, utxo_fee, 'utxoFeeAmount')
            exp_list = convert_elements_utxo(exp['utxos'])
            for exp_utxo in exp_list:
                if exp_utxo not in selected_utxo_list:
                    assert_message(obj, name, case,
                                   '{} is not found.'.format(str(exp_utxo)))
            exp_amount_list = convert_target_amount(exp['selectedAmounts'])
            assert_match(obj, name, case, len(exp_amount_list),
                         len(total_amount_map), 'selectedAmountsLen')
            for exp_amount_data in exp_amount_list:
                if str(exp_amount_data.asset) not in total_amount_map:
                    print(f'{total_amount_map}')
                    assert_message(obj, name, case,
                                   'selectedAmounts:{}'.format(
                                       exp_amount_data.asset))
                assert_match(obj, name, case, exp_amount_data.amount,
                             total_amount_map[str(exp_amount_data.asset)],
                             'selectedAmounts:{}:amount'.format(
                                 exp_amount_data.asset))
        elif name == 'Elements.EstimateFee':
            total_fee, txout_fee, utxo_fee = resp
            assert_equal(obj, name, case, exp, total_fee, 'feeAmount')
            assert_equal(obj, name, case, exp, txout_fee, 'txoutFeeAmount')
            assert_equal(obj, name, case, exp, utxo_fee, 'utxoFeeAmount')
        elif name == 'Elements.FundTransaction':
            if resp['hex'] != exp['hex']:
                print(resp['hex'])
            assert_equal(obj, name, case, exp, resp['hex'], 'hex')
            assert_equal(obj, name, case, exp, resp['feeAmount'], 'feeAmount')
            exp_addr_list = exp['usedAddresses']
            assert_match(obj, name, case, len(exp_addr_list),
                         len(resp['usedAddresses']), 'usedAddressesLen')
            for exp_addr in exp_addr_list:
                if exp_addr not in resp['usedAddresses']:
                    assert_message(obj, name, case,
                                   'usedAddresses:{}'.format(exp_addr))

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


def convert_elements_utxo(json_utxo_list):
    utxo_list = []
    for utxo in json_utxo_list:
        if utxo.get('base', False):
            continue
        desc = utxo.get('descriptor', '')
        # if not desc:
        #     desc = ''.format(utxo['redeemScript'])
        data = ElementsUtxoData(
            txid=utxo['txid'], vout=utxo['vout'],
            amount=utxo.get('amount', 0), descriptor=desc,
            scriptsig_template=utxo.get('scriptSigTemplate', ''),
            value=utxo.get('valueCommitment', ''),
            asset=utxo.get('asset', utxo.get('assetCommitment', '')),
            is_issuance=utxo.get('isIssuance', False),
            is_blind_issuance=utxo.get('isBlindIssuance', True),
            is_pegin=utxo.get('isPegin', False),
            pegin_btc_tx_size=utxo.get('peginBtcTxSize', 0),
            fedpeg_script=utxo.get('fedpegScript', ''),
            asset_blinder=utxo.get('assetBlindFactor', ''),
            amount_blinder=utxo.get('blindFactor', ''))
        utxo_list.append(data)
    return utxo_list


def convert_target_amount(json_target_list) -> List['TargetAmountData']:
    target_list = []
    for target in json_target_list:
        data = TargetAmountData(
            amount=target['amount'],
            asset=target.get('asset', ''),
            reserved_address=target.get(
                'reservedAddress',
                target.get('reserveAddress', '')))
        target_list.append(data)
    return target_list


class TestElementsUtxoData(TestCase):
    def test_utxo_data(self):
        txid = '0000000000000000000000000000000000000000000000000000000000000001'  # noqa: E501
        utxo1 = ElementsUtxoData(txid=txid, vout=2)
        utxo2 = ElementsUtxoData(txid=txid, vout=3)
        self.assertTrue(utxo1 < utxo2)
        self.assertTrue(utxo1 <= utxo2)
        self.assertFalse(utxo1 > utxo2)
        self.assertFalse(utxo1 >= utxo2)
        self.assertFalse(utxo1 == utxo2)
        self.assertFalse(utxo1 != utxo1)
        self.assertTrue(utxo1 != utxo2)
        self.assertEqual('{},{}'.format(txid, 2), str(utxo1))


class TestConfidentialTransaction(TestCase):
    def setUp(self):
        self.test_list = load_json_file('elements_transaction_test.json')
        self.test_list += load_json_file('elements_coin_test.json')
        self.utxos = {}
        self.utxos['elements_utxo_1'] = convert_elements_utxo(
            get_json_file('utxo/elements_utxo_1.json'))
        self.utxos['elements_utxo_2'] = convert_elements_utxo(
            get_json_file('utxo/elements_utxo_2.json'))
        self.utxos['elements_utxo_3'] = convert_elements_utxo(
            get_json_file('utxo/elements_utxo_3.json'))

    def test_confidential_transaction(self):
        exec_test(self, 'ConfidentialTransaction', test_ct_transaction_func)

    def test_elements_tx(self):
        exec_test(self, 'Elements', test_elements_tx_func)

    def test_confidential_tx_parse(self):
        exec_test(self, 'ConfidentialTransaction.Decode', test_parse_tx_func)

    def test_string(self):
        asset = '0000000000000000000000000000000000000000000000000000000000000001'  # noqa: E501
        asset_blinder = '0000000000000000000000000000000000000000000000000000000000000002'  # noqa: E501
        amount_blinder = '0000000000000000000000000000000000000000000000000000000000000003'  # noqa: E501
        entropy = '0000000000000000000000000000000000000000000000000000000000000005'  # noqa: E501
        nonce = '0000000000000000000000000000000000000000000000000000000000000006'  # noqa: E501
        amount = 100000000
        token_amount = 100
        issuance = Issuance(entropy, nonce, amount, token_amount)
        self.assertEqual(
            '{},{},{}'.format(entropy, amount, token_amount), str(issuance))

        data = UnblindData(asset, amount, asset_blinder, amount_blinder)
        self.assertEqual('{},{}'.format(asset, amount), str(data))

        key_pair = IssuanceKeyPair()
        self.assertEqual('IssuanceKeyPair', str(key_pair))

    def test_parse_unblind_tx(self):
        tx_hex = '020000000001319bff5f4311e6255ecf4dd472650a6ef85fde7d11cd10d3e6ba5974174aeb560100000000ffffffff0201f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000bd2cc1584c002deb65cc52301e1622f482a2f588b9800d2b8386ffabf74d6b2d73d17503a2f921976a9146a98a3f2935718df72518c00768ec67c589e0b2888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000000004c4b40000000000000'  # noqa: E501
        tx = ConfidentialTransaction.from_hex(tx_hex)

        self.assertEqual(2, len(tx.txout_list))
        self.assertEqual(
            '6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3',
            str(tx.txout_list[0].asset))
        self.assertEqual(
            12999995000000,
            tx.txout_list[0].value.amount)
        self.assertEqual(
            '0100000bd2cc1584c0',
            tx.txout_list[0].value.hex)
        self.assertEqual(
            '02deb65cc52301e1622f482a2f588b9800d2b8386ffabf74d6b2d73d17503a2f92',  # noqa: E501
            str(tx.txout_list[0].nonce))
        self.assertEqual(
            '6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3',
            str(tx.txout_list[1].asset))
        self.assertEqual(
            5000000,
            tx.txout_list[1].value.amount)
        self.assertEqual(
            '0100000000004c4b40',
            tx.txout_list[1].value.hex)
        self.assertEqual(
            '',
            str(tx.txout_list[1].nonce))

        self.assertEqual(1, tx.get_txout_fee_index())
        self.assertEqual('Q6z1cAcrPxMCnsjAUjSgyT2DrSqRR6KZMr',
                         str(tx.txout_list[0].get_address()))
        self.assertEqual(
            'VTpz4UGuFrPeMdFvW6dzq1vH3ZumciG6jmGnCUidgqsY5RHRxbGfLjndgUjzECCzQnNwAGoP8ohYdHXv',  # noqa: E501
            str(tx.txout_list[0].get_confidential_address()))
        self.assertEqual(
            None,
            tx.txout_list[1].get_confidential_address())
