from unittest import TestCase
from tests.util import load_json_file, exec_test,\
    assert_equal, assert_error, assert_match
from cfd.util import CfdError, to_hex_string
from cfd.key import Privkey, Pubkey, SchnorrPubkey,\
    SchnorrUtil, SignParameter, SigHashType, EcdsaAdaptor


def test_privkey_func(obj, name, case, req, exp, error):
    try:
        if name == 'Privkey.GenerateKeyPair':
            resp = Privkey.generate(network=req['network'],
                                    is_compressed=req['isCompressed'])
        elif name == 'Privkey.FromHex':
            resp = Privkey.from_hex(req['hex'],
                                    network=req['network'],
                                    is_compressed=req['isCompressed'])
        elif name == 'Privkey.FromWif':
            resp = Privkey.from_wif(req['wif'])
        elif name == 'Privkey.AddTweak':
            key = Privkey(hex=req['hex'])
            resp = key.add_tweak(req['tweak'])
        elif name == 'Privkey.MulTweak':
            key = Privkey(hex=req['hex'])
            resp = key.mul_tweak(req['tweak'])
        elif name == 'Privkey.Negate':
            key = Privkey(hex=req['hex'])
            resp = key.negate()
        elif name == 'Privkey.CalculateEcSignature':
            priv_data = req['privkeyData']
            if priv_data['wif']:
                key = Privkey(wif=priv_data['privkey'])
            else:
                key = Privkey(hex=priv_data['privkey'],
                              network=priv_data['network'],
                              is_compressed=priv_data['isCompressed'])
            resp = key.calculate_ec_signature(
                req['sighash'], req.get('isGrindR', True))
        elif name == 'Privkey.GetPubkey':
            _use_wif = req.get('wif', True)
            _wif = req['privkey'] if _use_wif else ''
            _hex = req['privkey'] if not _use_wif else ''
            resp = Privkey(wif=_wif, hex=_hex,
                           is_compressed=req['isCompressed'])
            resp = resp.pubkey
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        if name == 'Privkey.GenerateKeyPair':
            assert_equal(obj, name, case, exp, resp.wif_first, 'wif')
            assert_equal(obj, name, case, exp,
                         resp.network.as_str(), 'network')
            assert_equal(obj, name, case, exp,
                         resp.is_compressed, 'is_compressed')
        elif isinstance(resp, Privkey):
            assert_equal(obj, name, case, exp, str(resp), 'privkey')
            assert_equal(obj, name, case, exp, resp.wif, 'wif')
            assert_equal(obj, name, case, exp, resp.hex, 'hex')
            assert_equal(obj, name, case, exp,
                         resp.network.as_str(), 'network')
            assert_equal(obj, name, case, exp,
                         resp.is_compressed, 'is_compressed')
            assert_equal(obj, name, case, exp,
                         str(resp.pubkey), 'pubkey')
        else:
            assert_equal(obj, name, case, exp, resp, 'signature')
            assert_equal(obj, name, case, exp, resp, 'hex')

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


def test_pubkey_func(obj, name, case, req, exp, error):
    try:
        if name == 'Pubkey':
            resp = Pubkey(req['hex'])
        elif name == 'Pubkey.AddTweak':
            key = Pubkey(req['hex'])
            resp = key.add_tweak(req['tweak'])
        elif name == 'Pubkey.MulTweak':
            key = Pubkey(req['hex'])
            resp = key.mul_tweak(req['tweak'])
        elif name == 'Pubkey.Negate':
            key = Pubkey(req['hex'])
            resp = key.negate()
        elif name == 'Pubkey.Compress':
            key = Pubkey(req['hex'])
            resp = key.compress()
        elif name == 'Pubkey.Uncompress':
            key = Pubkey(req['hex'])
            resp = key.uncompress()
        elif name == 'Pubkey.VerifyEcSignature':
            key = Pubkey(req['hex'])
            resp = key.verify_ec_signature(
                req['sighash'], req['signature'])
        elif name == 'Pubkey.Combine':
            resp = Pubkey.combine(req['keyList'])
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        if isinstance(resp, Pubkey):
            assert_equal(obj, name, case, exp, str(resp), 'hex')
        elif isinstance(resp, bool):
            assert_equal(obj, name, case, exp, resp, 'bool')
        else:
            assert_equal(obj, name, case, exp, resp, 'hex')

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


def test_signature_func(obj, name, case, req, exp, error):
    try:
        if name == 'Signature.EncodeByDer':
            sighash_type = SigHashType.get(
                req['sighashType'], req.get('sighashAnyoneCanPay', False))
            resp = SignParameter.encode_by_der(
                req['signature'], sighash_type)
        elif name == 'Signature.DecodeDerToRaw':
            resp = SignParameter.decode_from_der(
                req['signature'])
        elif name == 'Signature.Normalize':
            resp = SignParameter.normalize(req['signature'])
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        assert_equal(obj, name, case, exp, str(resp), 'signature')
        if isinstance(resp, SignParameter):
            assert_equal(obj, name, case, exp,
                         resp.sighashtype.get_type_object().as_str(),
                         'sighashType')
            assert_equal(obj, name, case, exp,
                         resp.sighashtype.anyone_can_pay(),
                         'sighashAnyoneCanPay')

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


def test_ecdsa_adaptor_func(obj, name, case, req, exp, error):
    try:
        _proof = ''
        if name == 'EcdsaAdaptor.Adapt':
            resp = EcdsaAdaptor.adapt(req['signature'], req['secret'])

        elif name == 'EcdsaAdaptor.ExtractSecret':
            resp = EcdsaAdaptor.extract_secret(
                req['adaptorSignature'], req['signature'], req['adaptor'])

        elif name == 'EcdsaAdaptor.Sign':
            resp, _proof = EcdsaAdaptor.sign(req['message'], req['privkey'],
                                             req['adaptor'],
                                             is_message_hashed=req['isHashed'])

        elif name == 'EcdsaAdaptor.Verify':
            resp = EcdsaAdaptor.verify(req['signature'], req['proof'],
                                       req['adaptor'], req['message'],
                                       req['pubkey'],
                                       is_message_hashed=req['isHashed'])
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        assert_equal(obj, name, case, exp, str(resp), 'signature')
        assert_equal(obj, name, case, exp, str(resp), 'secret')
        assert_equal(obj, name, case, exp, resp, 'valid')
        assert_equal(obj, name, case, exp, _proof, 'proof')

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


def test_schnorr_func(obj, name, case, req, exp, error):
    try:
        parity = False
        privkey = ''
        if name == 'Schnorr.GetSchnorrPubkeyFromPrivkey':
            resp, parity = SchnorrPubkey.from_privkey(
                Privkey.from_hex(req['privkey']))
        elif name == 'Schnorr.GetSchnorrPubkeyFromPubkey':
            resp, parity = SchnorrPubkey.from_pubkey(req['pubkey'])
        elif name == 'Schnorr.TweakAddSchnorrPubkeyFromPrivkey':
            resp, parity, privkey =\
                SchnorrPubkey.add_tweak_from_privkey(
                    req['privkey'], req['tweak'])
        elif name == 'Schnorr.TweakAddSchnorrPubkey':
            resp = SchnorrPubkey(req['pubkey'])
            resp, parity = resp.add_tweak(req['tweak'])
        elif name == 'Schnorr.CheckTweakAddSchnorrPubkey':
            resp = SchnorrPubkey(req['pubkey'])
            resp = resp.is_tweaked(
                req['parity'], req['basePubkey'], req['tweak'])
        elif name == 'Schnorr.Sign':
            aux_rand, nonce = req['nonceOrAux'], ''
            if req.get('isNonce', False):
                nonce, aux_rand = req['nonceOrAux'], ''
            resp = SchnorrUtil.sign(req['message'], req['privkey'],
                                    aux_rand=aux_rand, nonce=nonce,
                                    is_message_hashed=req['isHashed'])

        elif name == 'Schnorr.Verify':
            resp = SchnorrUtil.verify(req['signature'], req['message'],
                                      req['pubkey'],
                                      is_message_hashed=req['isHashed'])

        elif name == 'Schnorr.ComputeSigPoint':
            resp = SchnorrUtil.compute_sig_point(
                req['message'], req['nonce'], req['pubkey'],
                is_message_hashed=req['isHashed'])

        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        assert_equal(obj, name, case, exp, str(resp), 'pubkey')
        assert_equal(obj, name, case, exp, str(resp), 'hex')
        assert_equal(obj, name, case, exp, resp, 'valid')
        assert_equal(obj, name, case, exp, privkey, 'privkey')
        if 'parity' in exp:
            assert_match(obj, name, case, exp['parity'], parity, 'parity')

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


class TestKey(TestCase):
    def setUp(self):
        self.test_list = load_json_file('key_test.json')

    def test_privkey(self):
        exec_test(self, 'Privkey', test_privkey_func)
        # to_hex_string on Privkey test
        _key = Privkey.from_wif(
            '92nXugKVPD1wCiuy6Ain4BnjxSJainfDHmF4V8rwxmSpZiXrb5E')
        _hex = to_hex_string(_key)
        self.assertEqual(
            '9e1285166b42230e448ae63f72d4135d42300e0462c3b7018a5d041a43bed7a0',
            _hex, 'Privkey to hex test')

    def test_pubkey(self):
        exec_test(self, 'Pubkey', test_pubkey_func)

    def test_schnorr(self):
        exec_test(self, 'Schnorr', test_schnorr_func)

    def test_signature(self):
        exec_test(self, 'Signature', test_signature_func)

    def test_ecdsa_adaptor(self):
        exec_test(self, 'EcdsaAdaptor', test_ecdsa_adaptor_func)
