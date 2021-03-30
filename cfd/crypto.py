# -*- coding: utf-8 -*-
##
# @file crypto.py
# @brief crypto (encrypto, hash, etc.) function implements file.
# @note Copyright 2021 CryptoGarage
from .util import get_util, to_hex_string, CfdError, ByteData


##
# @class CryptoUtil
# @brief crypto utility class.
class CryptoUtil:
    ##
    # @brief encrypto AES.
    # @param[in] key    encrypto key data
    # @param[in] data   encrypto target data
    # @param[in] iv     initial vector. (for CBC mode)
    # @return aes data.
    @classmethod
    def encrypto_aes(cls, key, data, iv=None) -> 'ByteData':
        util = get_util()
        with util.create_handle() as handle:
            cbc_iv = '' if iv is None else to_hex_string(iv)
            encoded_data = util.call_func(
                'CfdEncryptAES', handle.get_handle(),
                to_hex_string(key), cbc_iv, to_hex_string(data))
            return ByteData(encoded_data)

    ##
    # @brief encrypto AES.
    # @param[in] key    encrypto key data
    # @param[in] data   encrypted data
    # @param[in] iv     initial vector. (for CBC mode)
    # @return aes data.
    @classmethod
    def decrypto_aes(cls, key, data, iv=None) -> 'ByteData':
        util = get_util()
        with util.create_handle() as handle:
            cbc_iv = '' if iv is None else to_hex_string(iv)
            decoded_data = util.call_func(
                'CfdDecryptAES', handle.get_handle(),
                to_hex_string(key), cbc_iv, to_hex_string(data))
            return ByteData(decoded_data)

    ##
    # @brief Encode base64.
    # @param[in] data   encode target data
    # @return base64 encoded data
    @classmethod
    def encode_base64(cls, data) -> str:
        util = get_util()
        with util.create_handle() as handle:
            encoded_data = util.call_func(
                'CfdEncodeBase64', handle.get_handle(), to_hex_string(data))
            return encoded_data

    ##
    # @brief Decode base64.
    # @param[in] data   base64 encoded data
    # @return data
    @classmethod
    def decode_base64(cls, data: str) -> 'ByteData':
        util = get_util()
        with util.create_handle() as handle:
            decoded_data = util.call_func(
                'CfdDecodeBase64', handle.get_handle(), data)
            if (len(decoded_data) == 0) and (len(data) != 0):
                raise CfdError(error_code=1, message='Decode base64 error.')
            return ByteData(decoded_data)

    ##
    # @brief Encode base58.
    # @param[in] data           encode target data
    # @param[in] use_checksum   use base58 checksum
    # @return base58 encoded data
    @classmethod
    def encode_base58(cls, data, use_checksum: bool = True) -> str:
        util = get_util()
        with util.create_handle() as handle:
            encoded_data = util.call_func(
                'CfdEncodeBase58',
                handle.get_handle(),
                to_hex_string(data),
                use_checksum)
            return encoded_data

    ##
    # @brief Decode base58.
    # @param[in] data           base58 encoded data
    # @param[in] use_checksum   use base58 checksum
    # @return data
    @classmethod
    def decode_base58(cls, data: str, use_checksum: bool = True) -> 'ByteData':
        util = get_util()
        with util.create_handle() as handle:
            decoded_data = util.call_func(
                'CfdDecodeBase58', handle.get_handle(), data, use_checksum)
            return ByteData(decoded_data)


##
# @class HashUtil
# @brief hash utility class.
class HashUtil:
    ##
    # @brief hash function.
    # @param[in] func_name  function name
    # @param[in] message    message string. (text or binary data)
    # @param[in] has_text   message has text.
    # @return hashed data.
    @classmethod
    def _hash_function(
            cls,
            func_name,
            message,
            has_text: bool = False) -> 'ByteData':
        if (has_text is True) and (isinstance(message, str) is False):
            raise CfdError(
                error_code=1,
                message='Error: Text mode requires a string message.')
        util = get_util()
        with util.create_handle() as handle:
            data = message if has_text is True else to_hex_string(message)
            hashed_data = util.call_func(
                func_name, handle.get_handle(), data, bool(has_text))
            return ByteData(hashed_data)

    ##
    # @brief hash ripemd160.
    # @param[in] message    message string. (text or binary data)
    # @param[in] has_text   message has text.
    # @return hashed data.
    @classmethod
    def ripemd160(cls, message, has_text: bool = False) -> 'ByteData':
        return cls._hash_function('CfdRipemd160', message, has_text)

    ##
    # @brief hash sha256.
    # @param[in] message    message string. (text or binary data)
    # @param[in] has_text   message has text.
    # @return hashed data.
    @classmethod
    def sha256(cls, message, has_text: bool = False) -> 'ByteData':
        return cls._hash_function('CfdSha256', message, has_text)

    ##
    # @brief hash hash160.
    # @param[in] message    message string. (text or binary data)
    # @param[in] has_text   message has text.
    # @return hashed data.
    @classmethod
    def hash160(cls, message, has_text: bool = False) -> 'ByteData':
        return cls._hash_function('CfdHash160', message, has_text)

    ##
    # @brief hash hash256.
    # @param[in] message    message string. (text or binary data)
    # @param[in] has_text   message has text.
    # @return hashed data.
    @classmethod
    def hash256(cls, message, has_text: bool = False) -> 'ByteData':
        return cls._hash_function('CfdHash256', message, has_text)


##
# All import target.
__all__ = [
    'CryptoUtil',
    'HashUtil',
]
