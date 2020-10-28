from unittest import TestCase
from tests.util import load_json_file, exec_test,\
    assert_equal, assert_error, assert_match
from cfd.address import AddressUtil
from cfd.key import Network
from cfd.script import HashType
from cfd.util import CfdError


def test_address_func(obj, name, case, req, exp, error):
    try:
        _network = req.get('network', 'mainnet')
        if req.get('isElements', False) and (
                _network.lower() == Network.REGTEST.as_str()):
            _network = Network.ELEMENTS_REGTEST

        if name == 'Address.Create':
            _hash_type = HashType.get(req['hashType'])
            if _hash_type == HashType.P2PKH:
                resp = AddressUtil.p2pkh(
                    req['keyData']['hex'], network=_network)
            elif _hash_type == HashType.P2WPKH:
                resp = AddressUtil.p2wpkh(
                    req['keyData']['hex'], network=_network)
            elif _hash_type == HashType.P2SH_P2WPKH:
                resp = AddressUtil.p2sh_p2wpkh(
                    req['keyData']['hex'], network=_network)
            elif _hash_type == HashType.P2SH:
                resp = AddressUtil.p2sh(
                    req['keyData']['hex'], network=_network)
            elif _hash_type == HashType.P2WSH:
                resp = AddressUtil.p2wsh(
                    req['keyData']['hex'], network=_network)
            elif _hash_type == HashType.P2SH_P2WSH:
                resp = AddressUtil.p2sh_p2wsh(
                    req['keyData']['hex'], network=_network)
        elif name == 'Address.GetInfo':
            resp = AddressUtil.parse(req['address'])
        elif name == 'Address.MultisigAddresses':
            resp = AddressUtil.get_multisig_address_list(
                req['redeemScript'], req['hashType'], network=_network)
        elif name == 'Address.CreateMultisig':
            resp = AddressUtil.multisig(
                req['nrequired'],
                req['keys'], req['hashType'], network=_network)

        elif name == 'Address.FromLockingScript':
            resp = AddressUtil.from_locking_script(
                req['lockingScript'], network=_network)

        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        if isinstance(resp, list):
            assert_match(obj, name, case, len(exp['addresses']),
                         len(resp), 'addressLen')
            if 'pubkeys' in exp:
                assert_match(obj, name, case, len(exp['pubkeys']),
                             len(resp), 'pubkeyLen')
            for index, addr in enumerate(resp):
                assert_match(obj, name, case, exp['addresses'][index],
                             str(addr), 'address')
                assert_match(obj, name, case, exp['pubkeys'][index],
                             str(addr.pubkey), 'pubkey')
        else:
            assert_equal(obj, name, case, exp, str(resp), 'address')
            if name == 'Address.CreateMultisig':
                if ('redeemScript' in exp) and ('witnessScript' in exp):
                    assert_equal(obj, name, case, exp,
                                 resp.redeem_script, 'witnessScript')
                    assert_equal(obj, name, case, exp,
                                 resp.p2sh_wrapped_script, 'redeemScript')
                elif 'witnessScript' in exp:
                    assert_equal(obj, name, case, exp,
                                 resp.redeem_script, 'witnessScript')
                else:
                    assert_equal(obj, name, case, exp,
                                 resp.redeem_script, 'redeemScript')

            elif name == 'Address.Create':
                assert_equal(obj, name, case, exp,
                             resp.p2sh_wrapped_script, 'redeemScript')

            if resp.network == Network.ELEMENTS_REGTEST:
                assert_match(obj, name, case,
                             Network.ELEMENTS_REGTEST.as_str(),
                             resp.network.as_str(), 'network')
            else:
                assert_equal(obj, name, case, exp,
                             resp.network.as_str(), 'network')

            assert_equal(obj, name, case, exp,
                         resp.locking_script, 'lockingScript')
            assert_equal(obj, name, case, exp,
                         resp.hash_type.as_str(), 'hashType')
            assert_equal(obj, name, case, exp,
                         resp.witness_version, 'witnessVersion')

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


class TestAddress(TestCase):
    def setUp(self):
        self.test_list = load_json_file('address_test.json')

    def test_address(self):
        exec_test(self, 'Address', test_address_func)
