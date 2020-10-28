from unittest import TestCase
from tests.util import load_json_file, exec_test,\
    assert_equal, assert_error, assert_match
from cfd.key import Network
from cfd.descriptor import parse_descriptor, Descriptor, DescriptorScriptType
from cfd.util import CfdError


def test_descriptor_func(obj, name, case, req, exp, error):
    try:
        _network = req.get('network', 'mainnet')
        if req.get('isElements', False) and (
                _network.lower() == Network.REGTEST.as_str()):
            _network = Network.ELEMENTS_REGTEST

        if name == 'Descriptor.Parse':
            resp = parse_descriptor(req['descriptor'], _network,
                                    path=req.get('bip32DerivationPath', ''))
        elif name == 'Descriptor.Checksum':
            resp = parse_descriptor(req['descriptor'], _network,
                                    path=req.get('bip32DerivationPath', '0'))
        elif name == 'Descriptor.Create':
            return  # not implement

        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        assert_equal(obj, name, case, exp, str(resp), 'descriptor')
        if isinstance(resp, Descriptor):
            if resp.network == Network.ELEMENTS_REGTEST:
                assert_match(obj, name, case,
                             Network.ELEMENTS_REGTEST.as_str(),
                             resp.network.as_str(), 'network')
            else:
                assert_equal(obj, name, case, exp,
                             resp.network.as_str(), 'network')

            def check_keys(target, exp, depth, index=-1):
                assert_equal(obj, name, case, exp,
                             target.key_type.as_str(),
                             'keyType:{}:{}'.format(depth, index))
                assert_equal(obj, name, case, exp,
                             str(target),
                             'key:{}:{}'.format(depth, index))

            def check_descriptor_item(data, exp, depth=-1):
                assert_equal(obj, name, case, exp,
                             data.script_type.as_str(),
                             'type:{}'.format(depth))
                assert_equal(obj, name, case, exp,
                             data.address, 'address:{}'.format(depth))
                assert_equal(obj, name, case, exp,
                             data.depth, 'depth:{}'.format(depth))
                assert_equal(obj, name, case, exp,
                             data.hash_type, 'hashType:{}'.format(depth))
                assert_equal(obj, name, case, exp,
                             data.redeem_script,
                             'lockingScript:{}'.format(depth))
                assert_equal(obj, name, case, exp,
                             data.multisig_require_num,
                             'reqNum:{}'.format(depth))
                if data.key_data is not None:
                    check_keys(data.key_data, exp, depth)

                if depth != -1:
                    keys = exp.get('keys', [])
                    assert_match(obj, name, case, len(keys),
                                 len(data.key_list), 'keyListNum')
                    for index, data in enumerate(data.key_list):
                        check_keys(data, keys[index], depth, index)

            check_descriptor_item(resp.data, exp)
            if name == 'Descriptor.Checksum':
                pass
            elif resp.data.script_type == DescriptorScriptType.COMBO:
                scripts = exp.get('scripts', [])
                assert_match(obj, name, case, 1,
                             len(resp.script_list), 'scriptListNum')
                check_descriptor_item(resp.script_list[0], scripts[0], 0)
            elif resp.data.script_type in [DescriptorScriptType.ADDR,
                                           DescriptorScriptType.RAW]:
                pass
            else:
                scripts = exp.get('scripts', [])
                assert_match(obj, name, case, len(scripts),
                             len(resp.script_list), 'scriptListNum')
                for index, data in enumerate(resp.script_list):
                    check_descriptor_item(data, scripts[index], index)

            if exp.get('includeMultisig', False):
                pass

    except CfdError as err:
        if not error:
            print('{}:{}'.format(name, case))
            raise err
        assert_equal(obj, name, case, exp, err.message)


class TestDescriptor(TestCase):
    def setUp(self):
        self.test_list = load_json_file('descriptor_test.json')

    def test_descriptor(self):
        exec_test(self, 'Descriptor', test_descriptor_func)
