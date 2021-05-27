from unittest import TestCase
from tests.util import load_json_file,\
    exec_test, assert_equal, assert_error
from cfd.util import CfdError
from cfd.confidential_address import ConfidentialAddress


def test_ct_address_func(obj, name, case, req, exp, error):
    try:
        if name == 'ConfidentialAddress.Create':
            resp = ConfidentialAddress(
                req['unblindedAddress'], req['key'])
        elif name == 'ConfidentialAddress.Parse':
            resp = ConfidentialAddress.parse(req['confidentialAddress'])
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        assert_equal(obj, name, case, exp, str(resp), 'confidentialAddress')
        if 'unblindedAddress' in exp:
            assert_equal(obj, name, case, exp, resp.address,
                         'unblindedAddress')
            assert_equal(obj, name, case, exp, resp.confidential_key,
                         'confidentialKey')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


class TestConfidentialAddress(TestCase):
    def setUp(self):
        self.test_list = load_json_file('elements_address_test.json')

    def test_confidential_address(self):
        exec_test(self, 'ConfidentialAddress', test_ct_address_func)
