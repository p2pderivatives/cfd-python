from unittest import TestCase
from cfd.util import ByteData, CfdError


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
