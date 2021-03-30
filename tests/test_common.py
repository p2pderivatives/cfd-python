from unittest import TestCase
from tests.util import load_json_file,\
    exec_test, assert_equal, assert_error
from cfd.util import ByteData, CfdError
from cfd.crypto import CryptoUtil, HashUtil


def test_crypto_func(obj, name, case, req, exp, error):
    try:
        if name == 'Base58.Encode':
            resp = CryptoUtil.encode_base58(req['hex'], req['hasChecksum'])
        elif name == 'Base58.Decode':
            resp = CryptoUtil.decode_base58(req['data'], req['hasChecksum'])
        elif name == 'Base64.Encode':
            resp = CryptoUtil.encode_base64(req['hex'])
        elif name == 'Base64.Decode':
            resp = CryptoUtil.decode_base64(req['base64'])
        elif name == 'AES.Encode':
            resp = CryptoUtil.encrypto_aes(
                req['key'], req['data'], req.get('iv', None))
        elif name == 'AES.Decode':
            resp = CryptoUtil.decrypto_aes(
                req['key'], req['data'], req.get('iv', None))
        elif name == 'Hash.Hash256':
            resp = HashUtil.hash256(req['message'], req['hasText'])
        elif name == 'Hash.Hash160':
            resp = HashUtil.hash160(req['message'], req['hasText'])
        elif name == 'Hash.Sha256':
            resp = HashUtil.sha256(req['message'], req['hasText'])
        elif name == 'Hash.Ripemd160':
            resp = HashUtil.ripemd160(req['message'], req['hasText'])
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        assert_equal(obj, name, case, exp, str(resp), 'hex')
        assert_equal(obj, name, case, exp, str(resp), 'base64')
        assert_equal(obj, name, case, exp, str(resp), 'data')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


class TestCrypto(TestCase):
    def setUp(self):
        self.test_list = load_json_file('common_test.json')

    def test_base58(self):
        exec_test(self, 'Base58', test_crypto_func)

    def test_base64(self):
        exec_test(self, 'Base64', test_crypto_func)

    def test_hash(self):
        exec_test(self, 'Hash', test_crypto_func)

    def test_aes(self):
        exec_test(self, 'AES', test_crypto_func)


class TestByteData(TestCase):
    def test_byte_data(self):
        data = '01ff0000000000000000000000000000000000000000000000000000000000fe'  # noqa: E501
        byte_data = b'\x01\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe'  # noqa: E501
        list_data = [1, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254]  # noqa: E501
        b_array = bytearray(list_data)
        _data1 = ByteData(data)
        _data2 = ByteData(byte_data)
        _data3 = ByteData(list_data)
        _data4 = ByteData(b_array)
        self.assertEqual(data, str(_data1))
        self.assertEqual(data, str(_data2))
        self.assertEqual(data, str(_data3))
        self.assertEqual(data, str(_data4))
        self.assertEqual(byte_data, _data1.as_bytes())
        self.assertEqual(list_data, _data1.as_array())

    def test_serialize(self):
        data_hex = '00112233'
        serialized_hex = '0400112233'
        data1 = ByteData(data_hex)
        serialized = data1.serialize()
        self.assertEqual(serialized_hex, str(serialized))


class TestCfdError(TestCase):
    def test_error_string(self):
        code = 1
        message = 'ErrorTest'
        try:
            raise CfdError(code, message)
            self.assertFalse(True, 'Invalid route')
        except CfdError as e:
            self.assertEqual('code={}, msg={}'.format(code, message), str(e))
