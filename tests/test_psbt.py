from unittest import TestCase
from tests.util import load_json_file,\
    exec_test, assert_equal, assert_error, assert_message, assert_match
from cfd.util import ByteData, CfdError
from cfd.address import AddressUtil
from cfd.hdwallet import KeyData, ExtPubkey
from cfd.key import Network, Pubkey, SigHashType
from cfd.psbt import Psbt
from cfd.script import Script
from cfd.transaction import Transaction, OutPoint, TxOut, UtxoData, TxIn


def test_decode_psbt_func(obj, name, case, req, exp, error):
    try:
        if name != 'Psbt.DecodePsbt':
            raise Exception('unknown name: ' + name)

        psbt = Psbt(req['psbt'], network=req.get(
            'network', Network.MAINNET))
        assert_error(obj, name, case, error)

        assert_equal(obj, name, case, exp, str(psbt.get_tx()), 'tx_hex')
        if 'version' in exp:
            _, ver, _, _ = psbt.get_global_data()
            assert_equal(obj, name, case, exp, ver, 'version')
        xpubkeys = psbt.get_global_xpub_list()
        if 'xpubs' in exp:
            assert_match(obj, name, case, len(exp['xpubs']), len(xpubkeys),
                         'global:xpubs:num')
            for xpub_index, xpub_data in enumerate(exp.get('xpubs', [])):
                assert_match(obj, name, case, xpub_data['xpub']['base58'], str(
                    xpubkeys[xpub_index].ext_pubkey),
                    f'global:xpubs{xpub_index}:xpub')
                assert_match(obj, name, case,
                             xpub_data['master_fingerprint'], str(
                                 xpubkeys[xpub_index].fingerprint),
                             f'global:xpubs{xpub_index}:master_fingerprint')
                assert_match(obj, name, case, xpub_data['path'], str(
                    xpubkeys[xpub_index].bip32_path),
                    f'global:xpubs{xpub_index}:path')
        if 'unknown' in exp:
            unknown_keys = psbt.get_global_unknown_keys()
            key_len = len(unknown_keys)
            if req.get('hasDetail', False):
                key_len = key_len - len(xpubkeys)
            assert_match(obj, name, case, len(exp['unknown']), key_len,
                         'global:unknown:num')
            for unknown_data in exp.get('unknown', []):
                key = unknown_data['key']
                value = psbt.get_global_record(key)
                assert_match(obj, name, case, unknown_data['value'], str(
                    value), f'global:unknown:{key}')

        in_num, out_num = psbt.get_tx_count()
        assert_match(obj, name, case, len(exp['inputs']), in_num, 'num:inputs')
        assert_match(obj, name, case, len(
            exp['outputs']), out_num, 'num:outputs')

        for index in range(in_num):
            exp_input = exp['inputs'][index]
            outpoint = psbt.get_input_outpoint(index)
            if ('witness_utxo' in exp_input) or (
                    'non_witness_utxo_hex' in exp_input):
                utxo, locking_script, _, full_tx = psbt.get_input_utxo_data(
                    outpoint)
                if 'witness_utxo' in exp_input:
                    assert_match(
                        obj,
                        name,
                        case,
                        exp_input['witness_utxo']['amount'],
                        utxo.amount,
                        f'input{index}:witness_utxo:amount')
                    assert_match(
                        obj,
                        name,
                        case,
                        exp_input['witness_utxo']['scriptPubKey']['hex'],
                        str(locking_script),
                        f'input{index}:witness_utxo:scriptPubKey:hex')
                if 'non_witness_utxo_hex' in exp_input:
                    assert_match(
                        obj, name, case, exp_input['non_witness_utxo_hex'],
                        str(full_tx), f'input{index}:non_witness_utxo_hex')
            if 'sighash' in exp_input:
                sighash = psbt.get_input_sighash_type(outpoint)
                assert_match(
                    obj, name, case, exp_input['sighash'].lower(), str(
                        sighash), f'input{index}:sighash')
            if 'final_scriptsig' in exp_input:
                final_scriptsig = psbt.get_input_final_scriptsig(outpoint)
                assert_match(
                    obj,
                    name,
                    case,
                    exp_input['final_scriptsig']['hex'],
                    str(final_scriptsig),
                    f'input{index}:final_scriptsig:hex')
            if 'final_scriptsig' in exp_input:
                final_scriptsig = psbt.get_input_final_scriptsig(outpoint)
                assert_match(
                    obj,
                    name,
                    case,
                    exp_input['final_scriptsig']['hex'],
                    str(final_scriptsig),
                    f'input{index}:final_scriptsig:hex')
            if 'final_scriptwitness' in exp_input:
                witness = psbt.get_input_final_witness(outpoint)
                assert_match(obj, name, case, len(
                    exp_input['final_scriptwitness']), len(witness),
                    f'input{index}:final_scriptwitness:num')
                for wit_index, stack in enumerate(
                        exp_input.get('final_scriptwitness', [])):
                    assert_match(
                        obj, name, case, stack, str(witness[wit_index]),
                        f'input{index}:final_scriptwitness{wit_index}')
            if 'redeem_script' in exp_input:
                redeem_script = psbt.get_input_redeem_script(outpoint)
                assert_match(
                    obj,
                    name,
                    case,
                    exp_input['redeem_script']['hex'],
                    str(redeem_script),
                    f'input{index}:redeem_script:hex')
            if 'witness_script' in exp_input:
                witness_script = psbt.get_input_witness_script(outpoint)
                assert_match(
                    obj,
                    name,
                    case,
                    exp_input['witness_script']['hex'],
                    str(witness_script),
                    f'input{index}:witness_script:hex')
            if 'partial_signatures' in exp_input:
                sigs = psbt.get_input_signature_list(outpoint)
                assert_match(obj, name, case, len(
                    exp_input['partial_signatures']), len(sigs),
                    f'input{index}:partial_signatures:num')
                for sig_index, sig_data in enumerate(
                        exp_input.get('partial_signatures', [])):
                    assert_match(
                        obj, name, case, sig_data['pubkey'], str(
                            sigs[sig_index].related_pubkey),
                        f'input{index}:partial_signatures{sig_index}:pubkey')
                    assert_match(obj, name, case, sig_data['signature'], str(
                        sigs[sig_index].hex),
                        f'input{index}:partial_signatures{sig_index}:sig')
            if 'bip32_derivs' in exp_input:
                pubkeys = psbt.get_input_bip32_list(outpoint)
                assert_match(obj, name, case, len(
                    exp_input['bip32_derivs']), len(pubkeys),
                    f'input{index}:bip32_derivs:num')
                for key_index, key_data in enumerate(
                        exp_input.get('bip32_derivs', [])):
                    assert_match(obj, name, case, key_data['pubkey'], str(
                        pubkeys[key_index].pubkey),
                        f'input{index}:bip32_derivs{key_index}:pubkey')
                    assert_match(
                        obj, name, case,
                        key_data['master_fingerprint'], str(
                            pubkeys[key_index].fingerprint),
                        f'input{index}:bip32_derivs{key_index}:fingerprint')
                    assert_match(obj, name, case, key_data['path'],
                                 pubkeys[key_index].bip32_path,
                                 f'input{index}:bip32_derivs{key_index}:path')
            if 'unknown' in exp_input:
                unknown_keys = psbt.get_input_unknown_keys(outpoint)
                assert_match(obj, name, case, len(exp_input['unknown']), len(
                    unknown_keys), f'input{index}:unknown:num')
                for unknown_data in exp_input.get('unknown', []):
                    key = unknown_data['key']
                    value = psbt.get_input_record(outpoint, key)
                    assert_match(obj, name, case, unknown_data['value'], str(
                        value), f'input{index}:unknown:{key}')

        for index in range(out_num):
            exp_output = exp['outputs'][index]
            if 'redeem_script' in exp_output:
                redeem_script = psbt.get_output_redeem_script(index)
                assert_match(
                    obj,
                    name,
                    case,
                    exp_output['redeem_script']['hex'],
                    str(redeem_script),
                    f'output{index}:redeem_script:hex')
            if 'witness_script' in exp_output:
                witness_script = psbt.get_output_witness_script(index)
                assert_match(
                    obj,
                    name,
                    case,
                    exp_output['witness_script']['hex'],
                    str(witness_script),
                    f'output{index}:witness_script:hex')
            if 'bip32_derivs' in exp_output:
                pubkeys = psbt.get_output_bip32_list(index)
                assert_match(obj, name, case, len(
                    exp_output['bip32_derivs']), len(pubkeys),
                    f'output{index}:bip32_derivs:num')
                for key_index, key_data in enumerate(
                        exp_output.get('bip32_derivs', [])):
                    assert_match(obj, name, case, key_data['pubkey'], str(
                        pubkeys[key_index].pubkey),
                        f'output{index}:bip32_derivs{key_index}:pubkey')
                    assert_match(
                        obj, name, case,
                        key_data['master_fingerprint'], str(
                            pubkeys[key_index].fingerprint),
                        f'output{index}:bip32_derivs{key_index}:fingerprint')
                    assert_match(obj, name, case, key_data['path'],
                                 pubkeys[key_index].bip32_path,
                                 f'output{index}:bip32_derivs{key_index}:path')
            if 'unknown' in exp_output:
                unknown_keys = psbt.get_output_unknown_keys(index)
                assert_match(obj, name, case, len(exp_output['unknown']), len(
                    unknown_keys), f'output{index}:unknown:num')
                for unknown_data in exp_output.get('unknown', []):
                    key = unknown_data['key']
                    value = psbt.get_output_record(index, key)
                    assert_match(obj, name, case, unknown_data['value'], str(
                        value), f'output{index}:unknown:{key}')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_verify_psbt_func(obj, name, case, req, exp, error):
    try:
        error = False if exp.get('success', True) else True
        if name == 'Psbt.VerifyPsbtSign':
            psbt = Psbt(req['psbt'], network=req.get(
                'network', Network.MAINNET))
            outpoints = req.get('outPointList', [])
            if outpoints:
                for txin in outpoints:
                    psbt.verify(OutPoint(txin['txid'], txin['vout']))
            else:
                psbt.verify()
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        for fail_data in exp.get('failTxins', []):
            if fail_data['reason'] in err.message:
                return True
        assert_message(obj, name, case, err.message)
    return True


def test_check_finalized_psbt_func(obj, name, case, req, exp, error):
    try:
        resp = {}
        if name == 'Psbt.IsFinalizedPsbt':
            psbt = Psbt(req['psbt'], network=req.get(
                'network', Network.MAINNET))
            success = True
            fail_inputs = []
            outpoints = req.get('outPointList', psbt.get_tx().txin_list)
            for txin in outpoints:
                if isinstance(txin, TxIn):
                    outpoint = txin.outpoint
                else:
                    outpoint = OutPoint(txin['txid'], txin['vout'])
                if not psbt.is_finalized_input(outpoint):
                    success = False
                    fail_inputs.append(outpoint)
            finalized_all = psbt.is_finalized()
            resp = {
                'success': success,
                'finalizedAll': finalized_all,
                'failInputs': fail_inputs,
            }
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        assert_equal(obj, name, case, exp, resp['success'], 'success')
        assert_equal(obj, name, case, exp,
                     resp['finalizedAll'], 'finalizedAll')
        exp_fail_inputs = exp.get('failInputs', [])
        assert_match(obj, name, case, len(exp_fail_inputs),
                     len(resp['failInputs']), 'failInputs')
        if len(exp_fail_inputs) == len(resp['failInputs']):
            for txin in exp_fail_inputs:
                outpoint = OutPoint(txin['txid'], txin['vout'])
                if outpoint not in resp['failInputs']:
                    assert_message(obj, name, case,
                                   f'not found in failInputs: {str(outpoint)}')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_get_utxos_psbt_func(obj, name, case, req, exp, error):
    try:
        resp = {}
        if name == 'Psbt.GetPsbtUtxos':
            psbt = Psbt(req['psbt'], network=req.get(
                'network', Network.MAINNET))
            resp = []
            in_count, _ = psbt.get_tx_count()
            for index in range(in_count):
                outpoint, amount, _, _, desc, _ = psbt.get_input_data_by_index(
                    index)
                resp.append(UtxoData(outpoint, amount=amount, descriptor=desc))
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        exp_utxos = exp.get('utxos', [])
        assert_match(obj, name, case, len(exp_utxos), len(resp), 'utxos')
        if len(exp_utxos) == len(resp):
            for index, exp_utxo in enumerate(exp_utxos):
                utxo: 'UtxoData' = resp[index]
                assert_equal(obj, name, case, exp_utxo,
                             str(utxo.outpoint.txid), 'txid')
                assert_equal(obj, name, case, exp_utxo,
                             utxo.outpoint.vout, 'vout')
                assert_equal(obj, name, case, exp_utxo, utxo.amount, 'amount')
                assert_equal(obj, name, case, exp_utxo,
                             str(utxo.descriptor), 'descriptor')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_psbt_func(obj, name, case, req, exp, error):
    try:
        fee_amount = None
        if name == 'Psbt.CreatePsbt':
            resp = Psbt.create(
                req['version'],
                req['locktime'],
                network=req.get(
                    'network',
                    Network.MAINNET))
            for txin in req.get('txins', []):
                sequence = txin.get('sequence', TxIn.SEQUENCE_DISABLE)
                if (sequence == TxIn.SEQUENCE_DISABLE) and (
                        req['locktime'] != 0):
                    sequence = TxIn.SEQUENCE_FINAL
                resp.add_input(OutPoint(txin['txid'], txin['vout']),
                               sequence=sequence)
            for txout in req.get('txouts', []):
                resp.add_output(txout['amount'], address=txout['address'])
        elif name == 'Psbt.ConvertToPsbt':
            tx = Transaction(req['tx'])
            resp = Psbt.from_transaction(
                tx,
                permit_sig_data=req.get('permitSigData', False),
                network=req.get('network', Network.MAINNET))
        elif name == 'Psbt.JoinPsbts':
            resp = Psbt.join_psbts(req['psbts'], network=req.get(
                'network', Network.MAINNET))
        elif name == 'Psbt.CombinePsbt':
            resp = Psbt.combine_psbts(req['psbts'], network=req.get(
                'network', Network.MAINNET))
        elif name == 'Psbt.FinalizePsbtInput':
            psbt = Psbt(req['psbt'], network=req.get(
                'network', Network.MAINNET))
            for input in req.get('inputs', []):
                scripts = []
                outpoint = OutPoint(input['txid'], input['vout'])
                if 'final_scriptwitness' in input:
                    for stack in input['final_scriptwitness']:
                        try:
                            scripts.append(Script(stack))
                        except BaseException:
                            scripts.append(Script.from_asm([stack]))
                    psbt.set_input_finalize(outpoint, scripts)
                if 'finalScriptsig' in input:
                    if 'final_scriptwitness' in input:
                        psbt.set_input_final_scriptsig(
                            outpoint, input['finalScriptsig'])
                    else:
                        psbt.set_input_finalize(
                            outpoint, Script(input['finalScriptsig']))
                psbt.clear_input_sign_data(outpoint)
            resp = psbt
        elif name == 'Psbt.FinalizePsbt':
            psbt = Psbt(req['psbt'], network=req.get(
                'network', Network.MAINNET))
            psbt.finalize()
            resp = psbt
        elif name == 'Psbt.SignPsbt':
            psbt = Psbt(req['psbt'], network=req.get(
                'network', Network.MAINNET))
            psbt.sign(privkey=req['privkey'],
                      has_grind_r=req.get('hasGrindR', True))
            resp = psbt
        elif name == 'Psbt.AddPsbtData':
            net_type = Network.get(req.get('network', Network.MAINNET))
            psbt = Psbt(req['psbt'], network=net_type)
            for input_data in req.get('inputs', []):
                txin = input_data['txin']
                input = input_data['input']
                utxo = TxOut(0)
                if 'witnessUtxo' in input:
                    addr = ''
                    if 'address' in input['witnessUtxo']:
                        addr = AddressUtil.parse(
                            input['witnessUtxo']['address'])
                    utxo = TxOut(
                        input['witnessUtxo']['amount'],
                        address=addr,
                        locking_script=input['witnessUtxo'].get(
                            'directLockingScript',
                            ''))
                script = '' if 'redeemScript' not in input else Script(
                    input['redeemScript'])
                tx = '' if 'utxoFullTx' not in input else Transaction(
                    input['utxoFullTx'])
                outpoint = OutPoint(txin['txid'], txin['vout'])
                psbt.add_input(
                    outpoint,
                    utxo=utxo,
                    redeem_script=script,
                    utxo_tx=tx,
                    sequence=txin.get(
                        'sequence',
                        4294967295))
                for bip32_data in input.get('bip32Derives', []):
                    if 'descriptor' in bip32_data:
                        psbt.set_input_bip32_key(
                            outpoint, pubkey=bip32_data['descriptor'])
                    else:
                        psbt.set_input_bip32_key(
                            outpoint,
                            key_data=KeyData(Pubkey(bip32_data['pubkey']),
                                             fingerprint=ByteData(
                                bip32_data['master_fingerprint']),
                                bip32_path=bip32_data['path']))
            _, index = psbt.get_tx_count()
            for output_data in req.get('outputs', []):
                txout = output_data['txout']
                output = output_data['output']
                addr = ''
                if 'address' in txout:
                    addr = AddressUtil.parse(
                        txout['address'])
                script = '' if 'redeemScript' not in output else Script(
                    output['redeemScript'])
                psbt.add_output(
                    txout['amount'],
                    address=addr,
                    locking_script=txout.get(
                        'directLockingScript',
                        ''),
                    redeem_script=script)
                for bip32_data in output.get('bip32Derives', []):
                    if 'descriptor' in bip32_data:
                        psbt.set_output_bip32_key(
                            index, pubkey=bip32_data['descriptor'])
                    else:
                        psbt.set_output_bip32_key(
                            index, key_data=KeyData(
                                Pubkey(
                                    bip32_data['pubkey']),
                                fingerprint=ByteData(
                                    bip32_data['master_fingerprint']),
                                bip32_path=bip32_data['path']))
                index += 1
            resp = psbt
        elif name == 'Psbt.SetPsbtData':
            net_type = Network.get(req.get('network', Network.MAINNET))
            psbt = Psbt(req['psbt'], network=net_type)
            for input_data in req.get('inputs', []):
                input = input_data['input']
                outpoint = psbt.get_input_outpoint(input_data.get('index', 0))
                full_tx = input.get('utxoFullTx', '')
                utxo = None
                if 'witnessUtxo' in input:
                    addr = ''
                    if 'address' in input['witnessUtxo']:
                        addr = AddressUtil.parse(
                            input['witnessUtxo']['address'])
                    utxo = TxOut(
                        input['witnessUtxo']['amount'],
                        addr,
                        input['witnessUtxo'].get(
                            'directLockingScript',
                            ''))
                if 'redeemScript' in input:
                    psbt.set_input_script(outpoint, input['redeemScript'])
                if full_tx or (utxo is not None):
                    utxo = TxOut(0) if utxo is None else utxo
                    psbt.set_input_utxo(outpoint, utxo, full_tx)
                for bip32_data in input.get('bip32Derives', []):
                    if 'descriptor' in bip32_data:
                        psbt.set_input_bip32_key(
                            outpoint, pubkey=bip32_data['descriptor'])
                    else:
                        psbt.set_input_bip32_key(
                            outpoint,
                            key_data=KeyData(Pubkey(bip32_data['pubkey']),
                                             fingerprint=ByteData(
                                bip32_data['master_fingerprint']),
                                bip32_path=bip32_data['path']))
                if 'sighash' in input:
                    psbt.set_input_sighash_type(
                        outpoint, SigHashType.get(input['sighash']))
                for sig_data in input.get('partialSignature', []):
                    psbt.set_input_signature(
                        outpoint, sig_data['pubkey'], sig_data['signature'])
                for record in input.get('unknown', []):
                    psbt.set_input_record(
                        outpoint, record['key'], record['value'])
            for output_data in req.get('outputs', []):
                output = output_data['output']
                index = output_data.get('index', 0)
                if 'redeemScript' in output:
                    psbt.set_output_script(index, output['redeemScript'])
                for bip32_data in output.get('bip32Derives', []):
                    if 'descriptor' in bip32_data:
                        psbt.set_output_bip32_key(
                            index, pubkey=bip32_data['descriptor'])
                    else:
                        psbt.set_output_bip32_key(
                            index, key_data=KeyData(
                                Pubkey(
                                    bip32_data['pubkey']),
                                fingerprint=ByteData(
                                    bip32_data['master_fingerprint']),
                                bip32_path=bip32_data['path']))
                for record in output.get('unknown', []):
                    psbt.set_output_record(
                        index, record['key'], record['value'])
            if 'global' in req:
                global_data = req['global']
                for xpub_data in global_data.get('xpubs', []):
                    if 'descriptorXpub' in xpub_data:
                        psbt.set_global_xpub(
                            ext_pubkey=xpub_data['descriptorXpub'])
                    else:
                        psbt.set_global_xpub(
                            key_data=KeyData(
                                ExtPubkey(
                                    xpub_data['xpub']),
                                fingerprint=ByteData(
                                    xpub_data['master_fingerprint']),
                                bip32_path=xpub_data['path']))
                for record in global_data.get('unknown', []):
                    psbt.set_global_record(record['key'], record['value'])
            resp = psbt
        elif name == 'Psbt.SetPsbtRecord':
            psbt = Psbt(req['psbt'], network=req.get(
                'network', Network.MAINNET))
            for record in req['records']:
                if record['type'] == 'input':
                    psbt.set_input_record(None, record['key'], record['value'],
                                          record.get('index', 0))
                elif record['type'] == 'output':
                    psbt.set_output_record(record.get(
                        'index', 0), record['key'], record['value'])
                elif record['type'] == 'global':
                    psbt.set_global_record(record['key'], record['value'])
            resp = psbt
        elif name == 'Psbt.FundPsbt':
            psbt = Psbt(req['psbt'], network=req.get(
                'network', Network.MAINNET))
            utxos = []
            desc = req['reservedDescriptor']
            fee_rate = req['feeInfo']['feeRate']
            long_term_fee_rate = req['feeInfo']['longTermFeeRate']
            knapsack_min_change = req['feeInfo']['knapsackMinChange']
            dust_fee_rate = req['feeInfo']['dustFeeRate']
            for utxo in req.get('utxos', []):
                utxos.append(
                    UtxoData(
                        OutPoint(
                            utxo['txid'],
                            utxo['vout']),
                        amount=utxo['amount'],
                        descriptor=utxo['descriptor']))
            fee_amount = psbt.fund(utxos, desc, fee_rate, long_term_fee_rate,
                                   dust_fee_rate, knapsack_min_change)
            resp = psbt
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        assert_equal(obj, name, case, exp, str(resp), 'psbt')
        if isinstance(resp, Psbt) and ('hex' in exp):
            assert_equal(obj, name, case, exp, str(resp.get_bytes()), 'hex')
        if fee_amount:
            assert_equal(obj, name, case, exp, fee_amount, 'feeAmount')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


class TestPsbt(TestCase):
    def setUp(self):
        self.test_list = load_json_file('psbt_test.json')

    def test_psbt_decode(self):
        exec_test(self, 'Psbt.DecodePsbt', test_decode_psbt_func)

    def test_psbt_create(self):
        exec_test(self, 'Psbt.CreatePsbt', test_psbt_func)

    def test_psbt_convert(self):
        exec_test(self, 'Psbt.ConvertToPsbt', test_psbt_func)

    def test_psbt_join(self):
        exec_test(self, 'Psbt.JoinPsbts', test_psbt_func)

    def test_psbt_combine(self):
        exec_test(self, 'Psbt.CombinePsbt', test_psbt_func)

    def test_psbt_finalize_input(self):
        exec_test(self, 'Psbt.FinalizePsbtInput', test_psbt_func)

    def test_psbt_finalize(self):
        exec_test(self, 'Psbt.FinalizePsbt', test_psbt_func)

    def test_psbt_sign(self):
        exec_test(self, 'Psbt.SignPsbt', test_psbt_func)

    def test_psbt_verify(self):
        exec_test(self, 'Psbt.VerifyPsbtSign', test_verify_psbt_func)

    def test_psbt_add(self):
        exec_test(self, 'Psbt.AddPsbtData', test_psbt_func)

    def test_psbt_set_data(self):
        exec_test(self, 'Psbt.SetPsbtData', test_psbt_func)

    def test_psbt_set_record(self):
        exec_test(self, 'Psbt.SetPsbtRecord', test_psbt_func)

    def test_psbt_is_finalized(self):
        exec_test(self, 'Psbt.IsFinalizedPsbt', test_check_finalized_psbt_func)

    def test_psbt_get_utxos(self):
        exec_test(self, 'Psbt.GetPsbtUtxos', test_get_utxos_psbt_func)

    def test_psbt_fund(self):
        exec_test(self, 'Psbt.FundPsbt', test_psbt_func)

    def test_decodepsbt(self):
        psbt_str = 'cHNidP8BAJoCAAAAAiZ//Xbq5rbBP/uGzquqJNQkhVICM8LDgF4K12RwlXjAAQAAAAD/////fSVGKkL/LLG6VAHliTJZ2zykvPXParlxXTUWPTHJ7MAAAAAAAP////8CAOH1BQAAAAAWABSzIr3c5jO4UaxzcKtFTws2egZU5QDh9QUAAAAAFgAUyrjFOm6PwCltHNORWjB9UcSRpVUAAAAAAAEA9gIAAAAAAQHxmT/o5xiVQu5FBiWOFwIBviknA80nWssJ7OFmcv2EiwAAAAAXFgAUrJ74CyevHJ2VwdtddhMZMivEL8X/////AggEECQBAAAAFgAUCd4qBDHLs0RPwiytnZoP0JY5chAA4fUFAAAAABepFFCfWYX06QoU+5Djkxb9tPOsl1MHhwJHMEQCIB4H33IcMyJBno820H7q5HlZdboNnRljDKPNPcDUlnFyAiAVQo574GtlZ1AVOQUL15GjgPALvdvFCX6pe6e+QBcRSgEhAkrvQ7HVrHulAUmY1jzqxYOVnR/cZuommc2E7q+CooMGAAAAAAEBIADh9QUAAAAAF6kUUJ9ZhfTpChT7kOOTFv2086yXUweHIgICVlJIRgs8GG3s8T2wbwck/VC0fMPkicMAdsg2PVA4zv5HMEQCICmYYqZ6m0VNbNpf7jSlLZCJv6AkRE2IAxw0qY4pi9vKAiBLR/z1B7gJVBCOA3VnP9vdCExfu5lPbJUXIPLrL2u4ZgEBAwQBAAAAAQQWABSWLE4I8zbTr7w0FcnTWa4QQEcFICIGAlZSSEYLPBht7PE9sG8HJP1QtHzD5InDAHbINj1QOM7+GCpwR2AsAACAAAAAgAAAAIABAAAAAQAAAAABAL8CAAAAAcbS6jbi6AK1LdrGZdrL7S+DG1JjRZ4cpzT1yUXXUV5AAAAAAGpHMEQCIBG5bH0tDS6NyzcTjhisxGB1KWWt2cuHh99cNJ3w4q5mAiAuk68xtk9RZuVgWBlVXavsV755QwD62zcFLzHd3qmQXAEhA+PSRKOWfguHdl/ahsX/OIhfdJk5U7lYQ4iu8wsmr2rs/////wF4Uc0dAAAAABl2qRSNIEQ6kZaeO8oOJAzQ/+TcmMY94oisAAAAACICAtn2iI8oWhWmoYgKIgLCsjCkLXfPYtpqSKykGYJizaPHRzBEAiBm7JVulng81hIsnAdzKjrpkxtpq9r/HzYsKO1fqWco0wIgahbUrkb+1I09BJJzdhO9m1H+PiRTtERuRHxlvyyWfhABIgYC2faIjyhaFaahiAoiAsKyMKQtd89i2mpIrKQZgmLNo8cYnWtthiwAAIAAAACAAAAAgAAAAAABAAAAACICA0c7/Ix3DBsiCi56rkut9sDX6vKQKNWynTQ4ASuyie+BGCpwR2AsAACAAAAAgAAAAIAAAAAAAgAAAAAiAgNkdK/yYzw1GGVTn7UrYrnW+55OI1dmKOHwoKeZNFjgbBida22GLAAAgAAAAIAAAACAAAAAAAIAAAAA'  # noqa: E501
        json_str = Psbt.parse_to_json(psbt_str, has_detail=True)
        exp_str = """\
{"tx":{"txid":"f2bd9cccedc37e91a8b10e8034eefc49b901afa6220833097a31ed91772d81a5","hash":"f2bd9cccedc37e91a8b10e8034eefc49b901afa6220833097a31ed91772d81a5","version":2,"size":154,"vsize":154,"weight":616,"locktime":0,"vin":[{"txid":"c078957064d70a5e80c3c23302528524d424aaabce86fb3fc1b6e6ea76fd7f26","vout":1,"scriptSig":{"asm":"","hex":""},"sequence":4294967295},{"txid":"c0ecc9313d16355d71b96acff5bca43cdb593289e50154bab12cff422a46257d","vout":0,"scriptSig":{"asm":"","hex":""},"sequence":4294967295}],"vout":[{"value":100000000,"n":0,"scriptPubKey":{"asm":"0 b322bddce633b851ac7370ab454f0b367a0654e5","hex":"0014b322bddce633b851ac7370ab454f0b367a0654e5","reqSigs":1,"type":"witness_v0_keyhash","addresses":["bc1qkv3tmh8xxwu9rtrnwz452nctxeaqv489dcscvw"]}},{"value":100000000,"n":1,"scriptPubKey":{"asm":"0 cab8c53a6e8fc0296d1cd3915a307d51c491a555","hex":"0014cab8c53a6e8fc0296d1cd3915a307d51c491a555","reqSigs":1,"type":"witness_v0_keyhash","addresses":["bc1qe2uv2wnw3lqzjmgu6wg45vra28zfrf24f5qa8p"]}}]},"tx_hex":"0200000002267ffd76eae6b6c13ffb86ceabaa24d42485520233c2c3805e0ad764709578c00100000000ffffffff7d25462a42ff2cb1ba5401e5893259db3ca4bcf5cf6ab9715d35163d31c9ecc00000000000ffffffff0200e1f50500000000160014b322bddce633b851ac7370ab454f0b367a0654e500e1f50500000000160014cab8c53a6e8fc0296d1cd3915a307d51c491a55500000000","version":0,"unknown":[],"inputs":[{"non_witness_utxo_hex":"02000000000101f1993fe8e7189542ee4506258e170201be292703cd275acb09ece16672fd848b0000000017160014ac9ef80b27af1c9d95c1db5d761319322bc42fc5ffffffff02080410240100000016001409de2a0431cbb3444fc22cad9d9a0fd09639721000e1f5050000000017a914509f5985f4e90a14fb90e39316fdb4f3ac975307870247304402201e07df721c3322419e8f36d07eeae4795975ba0d9d19630ca3cd3dc0d4967172022015428e7be06b6567501539050bd791a380f00bbddbc5097ea97ba7be4017114a0121024aef43b1d5ac7ba5014998d63ceac583959d1fdc66ea2699cd84eeaf82a2830600000000","non_witness_utxo":{"txid":"c078957064d70a5e80c3c23302528524d424aaabce86fb3fc1b6e6ea76fd7f26","hash":"9cb67d0ba945c8da2342429e19b12e11852e3a032144ca908996ff46f05dd906","version":2,"size":246,"vsize":165,"weight":657,"locktime":0,"vin":[{"txid":"c078957064d70a5e80c3c23302528524d424aaabce86fb3fc1b6e6ea76fd7f26","vout":1,"scriptSig":{"asm":"","hex":""},"sequence":4294967295},{"txid":"c0ecc9313d16355d71b96acff5bca43cdb593289e50154bab12cff422a46257d","vout":0,"scriptSig":{"asm":"","hex":""},"sequence":4294967295},{"txid":"8b84fd7266e1ec09cb5a27cd032729be0102178e250645ee429518e7e83f99f1","vout":0,"scriptSig":{"asm":"0014ac9ef80b27af1c9d95c1db5d761319322bc42fc5","hex":"160014ac9ef80b27af1c9d95c1db5d761319322bc42fc5"},"txinwitness":["304402201e07df721c3322419e8f36d07eeae4795975ba0d9d19630ca3cd3dc0d4967172022015428e7be06b6567501539050bd791a380f00bbddbc5097ea97ba7be4017114a01","024aef43b1d5ac7ba5014998d63ceac583959d1fdc66ea2699cd84eeaf82a28306"],"sequence":4294967295}],"vout":[{"value":100000000,"n":0,"scriptPubKey":{"asm":"0 b322bddce633b851ac7370ab454f0b367a0654e5","hex":"0014b322bddce633b851ac7370ab454f0b367a0654e5","reqSigs":1,"type":"witness_v0_keyhash","addresses":["bc1qkv3tmh8xxwu9rtrnwz452nctxeaqv489dcscvw"]}},{"value":100000000,"n":1,"scriptPubKey":{"asm":"0 cab8c53a6e8fc0296d1cd3915a307d51c491a555","hex":"0014cab8c53a6e8fc0296d1cd3915a307d51c491a555","reqSigs":1,"type":"witness_v0_keyhash","addresses":["bc1qe2uv2wnw3lqzjmgu6wg45vra28zfrf24f5qa8p"]}},{"value":4899996680,"n":0,"scriptPubKey":{"asm":"0 09de2a0431cbb3444fc22cad9d9a0fd096397210","hex":"001409de2a0431cbb3444fc22cad9d9a0fd096397210","reqSigs":1,"type":"witness_v0_keyhash","addresses":["bc1qp80z5pp3ewe5gn7z9jkemxs06ztrjusscl4mx0"]}},{"value":100000000,"n":1,"scriptPubKey":{"asm":"OP_HASH160 509f5985f4e90a14fb90e39316fdb4f3ac975307 OP_EQUAL","hex":"a914509f5985f4e90a14fb90e39316fdb4f3ac97530787","reqSigs":1,"type":"scripthash","addresses":["393JshdyfRGe4Z4zvjvYYFPSUbrFvJy5tm"]}}]},"witness_utxo":{"amount":100000000,"scriptPubKey":{"asm":"OP_HASH160 509f5985f4e90a14fb90e39316fdb4f3ac975307 OP_EQUAL","hex":"a914509f5985f4e90a14fb90e39316fdb4f3ac97530787","type":"scripthash","address":"393JshdyfRGe4Z4zvjvYYFPSUbrFvJy5tm"}},"partial_signatures":[{"pubkey":"02565248460b3c186decf13db06f0724fd50b47cc3e489c30076c8363d5038cefe","signature":"30440220299862a67a9b454d6cda5fee34a52d9089bfa024444d88031c34a98e298bdbca02204b47fcf507b80954108e0375673fdbdd084c5fbb994f6c951720f2eb2f6bb86601"}],"sighash":"ALL","redeem_script":{"asm":"0 962c4e08f336d3afbc3415c9d359ae1040470520","hex":"0014962c4e08f336d3afbc3415c9d359ae1040470520","type":"witness_v0_keyhash"},"bip32_derivs":[{"pubkey":"02565248460b3c186decf13db06f0724fd50b47cc3e489c30076c8363d5038cefe","master_fingerprint":"2a704760","path":"44'/0'/0'/1/1","descriptor":"[2a704760/44'/0'/0'/1/1]02565248460b3c186decf13db06f0724fd50b47cc3e489c30076c8363d5038cefe"}]},{"non_witness_utxo_hex":"0200000001c6d2ea36e2e802b52ddac665dacbed2f831b5263459e1ca734f5c945d7515e40000000006a473044022011b96c7d2d0d2e8dcb37138e18acc460752965add9cb8787df5c349df0e2ae6602202e93af31b64f5166e5605819555dabec57be794300fadb37052f31dddea9905c012103e3d244a3967e0b87765fda86c5ff38885f74993953b9584388aef30b26af6aecffffffff017851cd1d000000001976a9148d20443a91969e3bca0e240cd0ffe4dc98c63de288ac00000000","non_witness_utxo":{"txid":"c0ecc9313d16355d71b96acff5bca43cdb593289e50154bab12cff422a46257d","hash":"c0ecc9313d16355d71b96acff5bca43cdb593289e50154bab12cff422a46257d","version":2,"size":191,"vsize":191,"weight":764,"locktime":0,"vin":[{"txid":"c078957064d70a5e80c3c23302528524d424aaabce86fb3fc1b6e6ea76fd7f26","vout":1,"scriptSig":{"asm":"","hex":""},"sequence":4294967295},{"txid":"c0ecc9313d16355d71b96acff5bca43cdb593289e50154bab12cff422a46257d","vout":0,"scriptSig":{"asm":"","hex":""},"sequence":4294967295},{"txid":"8b84fd7266e1ec09cb5a27cd032729be0102178e250645ee429518e7e83f99f1","vout":0,"scriptSig":{"asm":"0014ac9ef80b27af1c9d95c1db5d761319322bc42fc5","hex":"160014ac9ef80b27af1c9d95c1db5d761319322bc42fc5"},"txinwitness":["304402201e07df721c3322419e8f36d07eeae4795975ba0d9d19630ca3cd3dc0d4967172022015428e7be06b6567501539050bd791a380f00bbddbc5097ea97ba7be4017114a01","024aef43b1d5ac7ba5014998d63ceac583959d1fdc66ea2699cd84eeaf82a28306"],"sequence":4294967295},{"txid":"405e51d745c9f534a71c9e4563521b832fedcbda65c6da2db502e8e236ead2c6","vout":0,"scriptSig":{"asm":"3044022011b96c7d2d0d2e8dcb37138e18acc460752965add9cb8787df5c349df0e2ae6602202e93af31b64f5166e5605819555dabec57be794300fadb37052f31dddea9905c01 03e3d244a3967e0b87765fda86c5ff38885f74993953b9584388aef30b26af6aec","hex":"473044022011b96c7d2d0d2e8dcb37138e18acc460752965add9cb8787df5c349df0e2ae6602202e93af31b64f5166e5605819555dabec57be794300fadb37052f31dddea9905c012103e3d244a3967e0b87765fda86c5ff38885f74993953b9584388aef30b26af6aec"},"sequence":4294967295}],"vout":[{"value":100000000,"n":0,"scriptPubKey":{"asm":"0 b322bddce633b851ac7370ab454f0b367a0654e5","hex":"0014b322bddce633b851ac7370ab454f0b367a0654e5","reqSigs":1,"type":"witness_v0_keyhash","addresses":["bc1qkv3tmh8xxwu9rtrnwz452nctxeaqv489dcscvw"]}},{"value":100000000,"n":1,"scriptPubKey":{"asm":"0 cab8c53a6e8fc0296d1cd3915a307d51c491a555","hex":"0014cab8c53a6e8fc0296d1cd3915a307d51c491a555","reqSigs":1,"type":"witness_v0_keyhash","addresses":["bc1qe2uv2wnw3lqzjmgu6wg45vra28zfrf24f5qa8p"]}},{"value":4899996680,"n":0,"scriptPubKey":{"asm":"0 09de2a0431cbb3444fc22cad9d9a0fd096397210","hex":"001409de2a0431cbb3444fc22cad9d9a0fd096397210","reqSigs":1,"type":"witness_v0_keyhash","addresses":["bc1qp80z5pp3ewe5gn7z9jkemxs06ztrjusscl4mx0"]}},{"value":100000000,"n":1,"scriptPubKey":{"asm":"OP_HASH160 509f5985f4e90a14fb90e39316fdb4f3ac975307 OP_EQUAL","hex":"a914509f5985f4e90a14fb90e39316fdb4f3ac97530787","reqSigs":1,"type":"scripthash","addresses":["393JshdyfRGe4Z4zvjvYYFPSUbrFvJy5tm"]}},{"value":499995000,"n":0,"scriptPubKey":{"asm":"OP_DUP OP_HASH160 8d20443a91969e3bca0e240cd0ffe4dc98c63de2 OP_EQUALVERIFY OP_CHECKSIG","hex":"76a9148d20443a91969e3bca0e240cd0ffe4dc98c63de288ac","reqSigs":1,"type":"pubkeyhash","addresses":["1DsCvxydk2JqbEj1EqL6mXcEvStsKQvKbx"]}}]},"partial_signatures":[{"pubkey":"02d9f6888f285a15a6a1880a2202c2b230a42d77cf62da6a48aca4198262cda3c7","signature":"3044022066ec956e96783cd6122c9c07732a3ae9931b69abdaff1f362c28ed5fa96728d302206a16d4ae46fed48d3d0492737613bd9b51fe3e2453b4446e447c65bf2c967e1001"}],"bip32_derivs":[{"pubkey":"02d9f6888f285a15a6a1880a2202c2b230a42d77cf62da6a48aca4198262cda3c7","master_fingerprint":"9d6b6d86","path":"44'/0'/0'/0/1","descriptor":"[9d6b6d86/44'/0'/0'/0/1]02d9f6888f285a15a6a1880a2202c2b230a42d77cf62da6a48aca4198262cda3c7"}]}],"outputs":[{"bip32_derivs":[{"pubkey":"03473bfc8c770c1b220a2e7aae4badf6c0d7eaf29028d5b29d3438012bb289ef81","master_fingerprint":"2a704760","path":"44'/0'/0'/0/2","descriptor":"[2a704760/44'/0'/0'/0/2]03473bfc8c770c1b220a2e7aae4badf6c0d7eaf29028d5b29d3438012bb289ef81"}]},{"bip32_derivs":[{"pubkey":"036474aff2633c351865539fb52b62b9d6fb9e4e23576628e1f0a0a7993458e06c","master_fingerprint":"9d6b6d86","path":"44'/0'/0'/0/2","descriptor":"[9d6b6d86/44'/0'/0'/0/2]036474aff2633c351865539fb52b62b9d6fb9e4e23576628e1f0a0a7993458e06c"}]}],"fee":399995000}\
"""  # noqa: E501
        self.assertEqual(exp_str, json_str, 'Fail: decodepsbt')
