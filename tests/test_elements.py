from unittest import TestCase
from tests.util import load_json_file,\
    exec_test, assert_equal, assert_error
from cfd.util import CfdError
from cfd.confidential_transaction import ConfidentialAsset, ConfidentialValue


def test_elements_func(obj, name, case, req, exp, error):
    try:
        if name == 'Elements.GetCommitment':
            asset = ConfidentialAsset(req['asset'])
            asset_commitment = asset.get_commitment(
                req['assetBlindFactor'])
            value = ConfidentialValue(req['amount'])
            amount_commitment = value.get_commitment(
                asset_commitment, req['blindFactor'])
            resp = {'assetCommitment': str(asset_commitment),
                    'amountCommitment': str(amount_commitment)}
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        if 'assetCommitment' in exp:
            assert_equal(obj, name, case, exp, resp['assetCommitment'],
                         'assetCommitment')
            assert_equal(obj, name, case, exp, resp['amountCommitment'],
                         'amountCommitment')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


class TestElementsCommon(TestCase):
    def setUp(self):
        self.test_list = load_json_file('elements_test.json')

    def test_elements(self):
        exec_test(self, 'Elements', test_elements_func)
