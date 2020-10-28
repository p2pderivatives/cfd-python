from unittest import TestCase
from tests.util import load_json_file, exec_test,\
    assert_equal, assert_error, assert_match
from cfd.util import CfdError
from cfd.script import Script
from cfd.key import SignParameter, SigHashType


def test_script_func(obj, name, case, req, exp, error):
    try:
        if name == 'Script.Parse':
            resp = Script(req['script'])

        elif name == 'Script.Create':
            resp = Script.from_asm(req['items'])

        elif name == 'Script.CreateMultisigScriptSig':
            _sign_list = []
            for data in req.get('signParams', []):
                sighash_type = SigHashType.get(
                    data.get('sighashType', 'all'),
                    data.get('sighashAnyoneCanPay', False))
                _sign = SignParameter(
                    data['hex'], data.get('relatedPubkey', ''),
                    sighash_type)
                if data.get('derEncode', False):
                    _sign.set_der_encode()
                _sign_list.append(_sign)
            resp = Script.create_multisig_scriptsig(
                req['redeemScript'], _sign_list)

        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        assert_equal(obj, name, case, exp, str(resp), 'hex')
        if 'scriptItems' in exp:
            _items = exp['scriptItems']
            _asm = '' if len(_items) == 0 else ' '.join(exp['scriptItems'])
            assert_match(obj, name, case, _asm, resp.asm, 'scriptItems')

    except CfdError as err:
        if not error:
            print('test case: {}:{}'.format(name, case))
            raise err
        assert_equal(obj, name, case, exp, err.message)

    except ValueError as err:
        print(err)
        print(req)
        raise err


class TestScript(TestCase):
    def setUp(self):
        self.test_list = load_json_file('script_test.json')

    def test_script(self):
        exec_test(self, 'Script', test_script_func)
