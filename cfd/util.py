# -*- coding: utf-8 -*-
##
# @file util.py
# @brief cfd utility file.
# @note Copyright 2020 CryptoGarage
from ctypes import c_int, c_void_p, c_char_p, c_int32, c_int64,\
    c_uint32, c_uint64, c_uint8, c_bool, c_double, c_ubyte, \
    CDLL, byref, POINTER, ArgumentError
from os.path import isfile, abspath
from enum import Enum
import platform
import os
import re
from typing import List, Union

################
# Public class #
################


##
# @class CfdErrorCode
# @brief Cfd error code.
class CfdErrorCode(Enum):
    ##
    # CfdErrorCode: success
    SUCCESS = 0
    ##
    # CfdErrorCode: unknown error.
    UNKNOWN = -1
    ##
    # CfdErrorCode: internal error.
    INTERNAL = -2
    ##
    # CfdErrorCode: memory full error.
    MEMORY_FULL = -3
    ##
    # CfdErrorCode: illegal argument error.
    ILLEGAL_ARGUMENT = 1
    ##
    # CfdErrorCode: illegal state error.
    ILLEGAL_STATE = 2
    ##
    # CfdErrorCode: out of range error.
    OUT_OF_RANGE = 3
    ##
    # CfdErrorCode: invalid setting.
    INVALID_SETTING = 4
    ##
    # CfdErrorCode: connection error.
    CONNECTION_ERROR = 5
    ##
    # CfdErrorCode: disk access error.
    DISK_ACCESS_ERROR = 6
    ##
    # CfdErrorCode: sign verification.
    SIGN_VERIFICATION = 7
    ##
    # CfdErrorCode: not found.
    NOT_FOUND = 8


##
# @class CfdError
# @brief cfd custom error class.
class CfdError(Exception):
    ##
    # @var error_code
    # error code
    error_code: int
    ##
    # @var message
    # error message
    message: str

    ##
    # @brief constructor.
    # @param[in] error_code     error code
    # @param[in] message        error message
    def __init__(
        self,
        error_code: Union[int, 'CfdErrorCode'] = CfdErrorCode.UNKNOWN,
        message: str = '',
    ) -> None:
        if isinstance(error_code, CfdErrorCode):
            self.error_code = error_code.value
        else:
            self.error_code = int(error_code)
        self.message = message

    ##
    # @brief get error information.
    # @return error information.
    def __str__(self) -> str:
        return f'code={self.error_code}, msg={self.message}'


##
# @class ByteData
# @brief cfd byte data class.
class ByteData:
    ##
    # @var hex
    # hex string
    hex: str

    ##
    # @brief constructor.
    # @param[in] data     byte data
    def __init__(self, data) -> None:
        if isinstance(data, bytes) or isinstance(data, bytearray):
            self.hex = data.hex()
        elif isinstance(data, list):
            self.hex = ''.join("%02x" % b for b in data)
        elif data is None:
            self.hex = ''
        else:
            self.hex = str(data).lower()
            bytes.fromhex(self.hex)  # check hex

    ##
    # @brief get string.
    # @return hex.
    def __str__(self) -> str:
        return self.hex

    ##
    # @brief get bytes data.
    # @return bytes data.
    def as_bytes(self) -> bytes:
        return bytes.fromhex(self.hex)

    ##
    # @brief get array data.
    # @return array data.
    def as_array(self) -> List[int]:
        _hex_list = re.split('(..)', self.hex)[1:: 2]
        return [int('0x' + s, 16) for s in _hex_list]

    ##
    # @brief get serialized data.
    # @return serialize hex.
    def serialize(self) -> 'ByteData':
        util = get_util()
        with util.create_handle() as handle:
            _serialized = util.call_func(
                'CfdSerializeByteData', handle.get_handle(), self.hex)
            return ByteData(_serialized)


##
# @class ReverseByteData
# @brief reversible byte data class.
class ReverseByteData:
    ##
    # @var hex
    # hex string
    hex: str

    ##
    # @brief constructor.
    # @param[in] data     byte data
    def __init__(self, data) -> None:
        if isinstance(data, bytes) or isinstance(data, bytearray):
            _data = data.hex()
            _list = re.split('(..)', _data)[1::2]
            new_list = _list[::-1]
            self.hex = ''.join(new_list)
        elif isinstance(data, list):
            new_list = data[::-1]
            self.hex = ''.join("%02x" % int(b) for b in new_list)
        else:
            self.hex = str(data).lower()
            if self.hex != '':
                try:
                    bytes.fromhex(self.hex)
                except ValueError:
                    raise CfdError(
                        error_code=1,
                        message='Error: Invalid hex value.')

    ##
    # @brief get string.
    # @return hex.
    def __str__(self) -> str:
        return self.hex

    ##
    # @brief get bytes data.
    # @return bytes data.
    def as_bytes(self) -> bytes:
        _hex_list = re.split('(..)', self.hex)[1::2]
        _hex_list = _hex_list[::-1]
        return bytes.fromhex(''.join(_hex_list))

    ##
    # @brief get array data.
    # @return array data.
    def as_array(self) -> List[int]:
        _hex_list = re.split('(..)', self.hex)[1::2]
        _hex_list = _hex_list[::-1]
        return [int('0x' + s, 16) for s in _hex_list]


##
# @brief get hex string.
# @param[in] value      data
# @return hex string.
def to_hex_string(value) -> str:
    if value is None:
        return ''
    elif isinstance(value, bytes):
        return value.hex()
    elif isinstance(value, bytearray):
        return value.hex()
    elif isinstance(value, list):
        return "".join("%02x" % int(b) for b in value)
    elif str(type(value)) == "<class 'cfd.key.Privkey'>":
        return str(value.hex)
    else:
        _hex = str(value)
        if _hex != '':
            try:
                bytes.fromhex(_hex)
            except ValueError:
                raise CfdError(
                    error_code=1,
                    message='Error: Invalid hex value.')
        return _hex


##################
# Internal class #
##################


##
# @class CVoidPP
# @brief void double pointer class.
class CVoidPP(object):
    pass


##
# @class CCharPP
# @brief char double pointer class.
class CCharPP(object):
    pass


##
# @class CBoolP
# @brief bool pointer class.
class CBoolP(object):
    pass


##
# @class CIntP
# @brief int pointer class.
class CIntP(object):
    pass


##
# @class CUint8P
# @brief uint8 pointer class.
class CUint8P(object):
    pass


##
# @class CUint32P
# @brief uint32 pointer class.
class CUint32P(object):
    pass


##
# @class CInt32P
# @brief int32 pointer class.
class CInt32P(object):
    pass


##
# @class CUint64P
# @brief uint64 pointer class.
class CUint64P(object):
    pass


##
# @class CInt64P
# @brief int64 pointer class.
class CInt64P(object):
    pass


##
# @brief void double pointer.
c_void_p_p = CVoidPP()
##
# @brief char double pointer.
c_char_p_p = CCharPP()
##
# @brief bool pointer.
c_bool_p = CBoolP()
##
# @brief int pointer.
c_int_p = CIntP()
##
# @brief uint8 pointer.
c_uint8_p = CUint8P()
##
# @brief uint32 pointer.
c_uint32_p = CUint32P()
##
# @brief int32 pointer.
c_int32_p = CInt32P()
##
# @brief uint64 pointer.
c_uint64_p = CUint64P()
##
# @brief int64 pointer.
c_int64_p = CInt64P()


##
# @class CfdHandle
# @brief cfd handle class.
class CfdHandle:
    ##
    # @var _handle
    # handle pointer

    ##
    # @brief constructor.
    # @param[in] handle     handle
    def __init__(self, handle):
        self._handle = handle

    ##
    # @brief get handle.
    # @retval _handle  handle.
    def get_handle(self):
        return self._handle

    ##
    # @brief enter method.
    # @retval self  object.
    def __enter__(self):
        return self

    ##
    # @brief exit method.
    # @param[in] type       type
    # @param[in] value      value
    # @param[in] traceback  traceback
    # @return void
    def __exit__(self, type, value, traceback):
        get_util().free_handle(self._handle)


##
# @class JobHandle
# @brief cfd job handle class.
class JobHandle:
    ##
    # @var _handle
    # cfd handle.
    ##
    # @var _job_handle
    # job handle.
    ##
    # @var _close_func
    # close function name.

    ##
    # @brief constructor.
    # @param[in] handle         handle
    # @param[in] job_handle     job handle
    # @param[in] close_function_name    close func name.
    def __init__(self, handle: 'CfdHandle',
                 job_handle, close_function_name):
        self._handle = handle
        self._job_handle = job_handle
        self._close_func = close_function_name

    ##
    # @brief get job handle.
    # @retval _job_handle  handle.
    def get_handle(self):
        return self._job_handle

    ##
    # @brief enter method.
    # @retval self  object.
    def __enter__(self):
        return self

    ##
    # @brief exit method.
    # @param[in] type       type
    # @param[in] value      value
    # @param[in] traceback  traceback
    # @return void
    def __exit__(self, type, value, traceback):
        get_util().call_func(
            self._close_func,
            self._handle.get_handle(),
            self._job_handle)


##
# @class CfdUtil
# @brief cfd utility class.
class CfdUtil:
    ##
    # @var _instance
    # singleton instance.

    ##
    # function map list
    _FUNC_LIST = [
        ("CfdCreateAddress", c_int, [c_void_p, c_int, c_char_p, c_char_p, c_int, c_char_p_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdInitializeMultisigScript", c_int, [c_void_p, c_int, c_int, c_void_p_p]),  # noqa: E501
        ("CfdAddMultisigScriptData", c_int, [c_void_p, c_void_p, c_char_p]),  # noqa: E501
        ("CfdFinalizeMultisigScript", c_int, [c_void_p, c_void_p, c_uint32, c_char_p_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdFreeMultisigScriptHandle", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdParseDescriptor", c_int, [c_void_p, c_char_p, c_int, c_char_p, c_void_p_p, c_uint32_p]),  # noqa: E501
        ("CfdGetDescriptorRootData", c_int, [c_void_p, c_void_p, c_int_p, c_char_p_p, c_char_p_p, c_int_p, c_char_p_p, c_int_p, c_char_p_p, c_char_p_p, c_char_p_p, c_char_p_p, c_char_p_p, c_bool_p, c_uint32_p, c_uint32_p]),  # noqa: E501
        ("CfdGetDescriptorData", c_int, [c_void_p, c_void_p, c_uint32, c_uint32_p, c_uint32_p, c_int_p, c_char_p_p, c_char_p_p, c_int_p, c_char_p_p, c_int_p, c_char_p_p, c_char_p_p, c_char_p_p, c_bool_p, c_uint32_p, c_uint32_p]),  # noqa: E501
        ("CfdGetDescriptorMultisigKey", c_int, [c_void_p, c_void_p, c_uint32, c_int_p, c_char_p_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdFreeDescriptorHandle", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdGetDescriptorChecksum", c_int, [c_void_p, c_int, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdGetAddressesFromMultisig", c_int, [c_void_p, c_char_p, c_int, c_int, c_void_p_p, c_uint32_p]),  # noqa: E501
        ("CfdGetAddressFromMultisigKey", c_int, [c_void_p, c_void_p, c_uint32, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdFreeAddressesMultisigHandle", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdGetAddressFromLockingScript", c_int, [c_void_p, c_char_p, c_int, c_char_p_p]),  # noqa: E501
        ("CfdGetAddressInfo", c_int, [c_void_p, c_char_p, c_int_p, c_int_p, c_int_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdInitializeBlockHandle", c_int, [c_void_p, c_int, c_char_p, c_void_p_p]),  # noqa: E501
        ("CfdFreeBlockHandle", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdGetBlockHash", c_int, [c_void_p, c_void_p, c_char_p_p]),  # noqa: E501
        ("CfdGetBlockHeaderData", c_int, [c_void_p, c_void_p, c_uint32_p, c_char_p_p, c_char_p_p, c_uint32_p, c_uint32_p, c_uint32_p]),  # noqa: E501
        ("CfdGetTransactionFromBlock", c_int, [c_void_p, c_void_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdGetTxOutProof", c_int, [c_void_p, c_void_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdExistTxidInBlock", c_int, [c_void_p, c_void_p, c_char_p]),  # noqa: E501
        ("CfdGetTxCountInBlock", c_int, [c_void_p, c_void_p, c_uint32_p]),  # noqa: E501
        ("CfdGetTxidFromBlock", c_int, [c_void_p, c_void_p, c_uint32, c_char_p_p]),  # noqa: E501
        ("CfdInitializeCoinSelection", c_int, [c_void_p, c_uint32, c_uint32, c_char_p, c_int64, c_double, c_double, c_double, c_int64, c_void_p_p]),  # noqa: E501
        ("CfdAddCoinSelectionUtxo", c_int, [c_void_p, c_void_p, c_int32, c_char_p, c_uint32, c_int64, c_char_p, c_char_p]),  # noqa: E501
        ("CfdAddCoinSelectionUtxoTemplate", c_int, [c_void_p, c_void_p, c_int32, c_char_p, c_uint32, c_int64, c_char_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdAddCoinSelectionAmount", c_int, [c_void_p, c_void_p, c_uint32, c_int64, c_char_p]),  # noqa: E501
        ("CfdSetOptionCoinSelection", c_int, [c_void_p, c_void_p, c_int, c_int64, c_double, c_bool]),  # noqa: E501
        ("CfdFinalizeCoinSelection", c_int, [c_void_p, c_void_p, c_int64_p]),  # noqa: E501
        ("CfdGetSelectedCoinIndex", c_int, [c_void_p, c_void_p, c_uint32, c_int32_p]),  # noqa: E501
        ("CfdGetSelectedCoinAssetAmount", c_int, [c_void_p, c_void_p, c_uint32, c_int64_p]),  # noqa: E501
        ("CfdFreeCoinSelectionHandle", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdInitializeEstimateFee", c_int, [c_void_p, c_void_p_p, c_bool]),  # noqa: E501
        ("CfdAddTxInForEstimateFee", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_char_p, c_char_p, c_bool, c_bool, c_bool, c_uint32, c_char_p]),  # noqa: E501
        ("CfdAddTxInTemplateForEstimateFee", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_char_p, c_char_p, c_bool, c_bool, c_bool, c_uint32, c_char_p, c_char_p]),  # noqa: E501
        ("CfdAddTxInputForEstimateFee", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_char_p, c_char_p, c_bool, c_bool, c_bool, c_char_p, c_uint32, c_uint32, c_char_p]),  # noqa: E501
        ("CfdSetOptionEstimateFee", c_int, [c_void_p, c_void_p, c_int, c_int64, c_double, c_bool]),  # noqa: E501
        ("CfdFinalizeEstimateFee", c_int, [c_void_p, c_void_p, c_char_p, c_char_p, c_int64_p, c_int64_p, c_bool, c_double]),  # noqa: E501
        ("CfdFreeEstimateFeeHandle", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdGetSupportedFunction", c_int, [c_uint64_p]),  # noqa: E501
        ("CfdInitialize", c_int, []),  # noqa: E501
        ("CfdFinalize", c_int, [c_bool]),  # noqa: E501
        ("CfdCreateHandle", c_int, [c_void_p_p]),  # noqa: E501
        ("CfdCreateSimpleHandle", c_int, [c_void_p_p]),  # noqa: E501
        ("CfdCloneHandle", c_int, [c_void_p, c_void_p_p]),  # noqa: E501
        ("CfdCopyErrorState", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdFreeHandle", c_int, [c_void_p]),  # noqa: E501
        ("CfdFreeBuffer", c_int, [c_void_p]),  # noqa: E501
        ("CfdFreeStringBuffer", c_int, [c_char_p]),  # noqa: E501
        ("CfdGetLastErrorCode", c_int, [c_void_p]),  # noqa: E501
        ("CfdGetLastErrorMessage", c_int, [c_void_p, c_char_p_p]),  # noqa: E501
        ("CfdRequestExecuteJson", c_int, [c_void_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdSerializeByteData", c_int, [c_void_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdEncryptAES", c_int, [c_void_p, c_char_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdDecryptAES", c_int, [c_void_p, c_char_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdEncodeBase64", c_int, [c_void_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdDecodeBase64", c_int, [c_void_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdEncodeBase58", c_int, [c_void_p, c_char_p, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdDecodeBase58", c_int, [c_void_p, c_char_p, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdRipemd160", c_int, [c_void_p, c_char_p, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdSha256", c_int, [c_void_p, c_char_p, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdHash160", c_int, [c_void_p, c_char_p, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdHash256", c_int, [c_void_p, c_char_p, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdCreateConfidentialAddress", c_int, [c_void_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdParseConfidentialAddress", c_int, [c_void_p, c_char_p, c_char_p_p, c_char_p_p, c_int_p]),  # noqa: E501
        ("CfdGetPeginAddress", c_int, [c_void_p, c_int, c_char_p, c_int, c_char_p, c_char_p, c_char_p_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdGetPegoutAddress", c_int, [c_void_p, c_int, c_int, c_char_p, c_uint32, c_int, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdInitializeConfidentialTx", c_int, [c_void_p, c_uint32, c_uint32, c_char_p_p]),  # noqa: E501
        ("CfdAddConfidentialTxIn", c_int, [c_void_p, c_char_p, c_char_p, c_uint32, c_uint32, c_char_p_p]),  # noqa: E501
        ("CfdAddConfidentialTxOut", c_int, [c_void_p, c_char_p, c_char_p, c_int64, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdUpdateConfidentialTxOut", c_int, [c_void_p, c_char_p, c_uint32, c_char_p, c_int64, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdGetConfidentialTxInfo", c_int, [c_void_p, c_char_p, c_char_p_p, c_char_p_p, c_char_p_p, c_uint32_p, c_uint32_p, c_uint32_p, c_uint32_p, c_uint32_p]),  # noqa: E501
        ("CfdGetConfidentialTxIn", c_int, [c_void_p, c_char_p, c_uint32, c_char_p_p, c_uint32_p, c_uint32_p, c_char_p_p]),  # noqa: E501
        ("CfdGetConfidentialTxInWitness", c_int, [c_void_p, c_char_p, c_uint32, c_uint32, c_char_p_p]),  # noqa: E501
        ("CfdGetConfidentialTxInPeginWitness", c_int, [c_void_p, c_char_p, c_uint32, c_uint32, c_char_p_p]),  # noqa: E501
        ("CfdGetTxInIssuanceInfo", c_int, [c_void_p, c_char_p, c_uint32, c_char_p_p, c_char_p_p, c_int64_p, c_char_p_p, c_int64_p, c_char_p_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdGetConfidentialTxOut", c_int, [c_void_p, c_char_p, c_uint32, c_char_p_p, c_int64_p, c_char_p_p, c_char_p_p, c_char_p_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdGetConfidentialTxInCount", c_int, [c_void_p, c_char_p, c_uint32_p]),  # noqa: E501
        ("CfdGetConfidentialTxInWitnessCount", c_int, [c_void_p, c_char_p, c_uint32, c_uint32_p]),  # noqa: E501
        ("CfdGetConfidentialTxInPeginWitnessCount", c_int, [c_void_p, c_char_p, c_uint32, c_uint32_p]),  # noqa: E501
        ("CfdGetConfidentialTxOutCount", c_int, [c_void_p, c_char_p, c_uint32_p]),  # noqa: E501
        ("CfdGetConfidentialTxInIndex", c_int, [c_void_p, c_char_p, c_char_p, c_uint32, c_uint32_p]),  # noqa: E501
        ("CfdGetConfidentialTxOutIndex", c_int, [c_void_p, c_char_p, c_char_p, c_char_p, c_uint32_p]),  # noqa: E501
        ("CfdGetConfidentialTxInfoByHandle", c_int, [c_void_p, c_void_p, c_char_p_p, c_char_p_p, c_char_p_p, c_uint32_p, c_uint32_p, c_uint32_p, c_uint32_p, c_uint32_p]),  # noqa: E501
        ("CfdHasPegoutConfidentialTxOut", c_int, [c_void_p, c_void_p, c_uint32]),  # noqa: E501
        ("CfdGetPegoutMainchainAddress", c_int, [c_void_p, c_void_p, c_uint32, c_int, c_char_p_p]),  # noqa: E501
        ("CfdGetTxInIssuanceInfoByHandle", c_int, [c_void_p, c_void_p, c_uint32, c_char_p_p, c_char_p_p, c_int64_p, c_char_p_p, c_int64_p, c_char_p_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdGetConfidentialTxOutSimpleByHandle", c_int, [c_void_p, c_void_p, c_uint32, c_char_p_p, c_int64_p, c_char_p_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdGetConfidentialTxOutByHandle", c_int, [c_void_p, c_void_p, c_uint32, c_char_p_p, c_int64_p, c_char_p_p, c_char_p_p, c_char_p_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdSetRawReissueAsset", c_int, [c_void_p, c_char_p, c_char_p, c_uint32, c_int64, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdGetIssuanceBlindingKey", c_int, [c_void_p, c_char_p, c_char_p, c_uint32, c_char_p_p]),  # noqa: E501
        ("CfdGetDefaultBlindingKey", c_int, [c_void_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdInitializeBlindTx", c_int, [c_void_p, c_void_p_p]),  # noqa: E501
        ("CfdSetBlindTxOption", c_int, [c_void_p, c_void_p, c_int, c_int64]),  # noqa: E501
        ("CfdAddBlindTxInData", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_char_p, c_char_p, c_char_p, c_int64, c_char_p, c_char_p]),  # noqa: E501
        ("CfdAddBlindTxOutData", c_int, [c_void_p, c_void_p, c_uint32, c_char_p]),  # noqa: E501
        ("CfdAddBlindTxOutByAddress", c_int, [c_void_p, c_void_p, c_char_p]),  # noqa: E501
        ("CfdFinalizeBlindTx", c_int, [c_void_p, c_void_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdGetBlindTxBlindData", c_int, [c_void_p, c_void_p, c_uint32, c_uint32_p, c_char_p_p, c_int64_p, c_char_p_p, c_char_p_p, c_char_p_p, c_uint32_p, c_bool_p, c_bool_p]),  # noqa: E501
        ("CfdFreeBlindHandle", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdAddConfidentialTxSign", c_int, [c_void_p, c_char_p, c_char_p, c_uint32, c_bool, c_char_p, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdAddConfidentialTxDerSign", c_int, [c_void_p, c_char_p, c_char_p, c_uint32, c_bool, c_char_p, c_int, c_bool, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdFinalizeElementsMultisigSign", c_int, [c_void_p, c_void_p, c_char_p, c_char_p, c_uint32, c_int, c_char_p, c_char_p, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdAddConfidentialTxSignWithPrivkeySimple", c_int, [c_void_p, c_char_p, c_char_p, c_uint32, c_int, c_char_p, c_char_p, c_int64, c_char_p, c_int, c_bool, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdCreateConfidentialSighash", c_int, [c_void_p, c_char_p, c_char_p, c_uint32, c_int, c_char_p, c_char_p, c_int64, c_char_p, c_int, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdUnblindTxOut", c_int, [c_void_p, c_char_p, c_uint32, c_char_p, c_char_p_p, c_int64_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdUnblindIssuance", c_int, [c_void_p, c_char_p, c_uint32, c_char_p, c_char_p, c_char_p_p, c_int64_p, c_char_p_p, c_char_p_p, c_char_p_p, c_int64_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdVerifyConfidentialTxSignature", c_int, [c_void_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_uint32, c_int, c_bool, c_int64, c_char_p, c_int]),  # noqa: E501
        ("CfdVerifyConfidentialTxSign", c_int, [c_void_p, c_char_p, c_char_p, c_uint32, c_char_p, c_int, c_char_p, c_int64, c_char_p]),  # noqa: E501
        ("CfdGetConfidentialValueHex", c_int, [c_void_p, c_int64, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdGetAssetCommitment", c_int, [c_void_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdGetValueCommitment", c_int, [c_void_p, c_int64, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdAddConfidentialTxOutput", c_int, [c_void_p, c_void_p, c_int64, c_char_p, c_char_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdSetIssueAsset", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_char_p, c_int64, c_char_p, c_char_p, c_int64, c_char_p, c_char_p, c_bool, c_char_p_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdSetReissueAsset", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_int64, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdAddTxPeginInput", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_int64, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdAddTxPegoutOutput", c_int, [c_void_p, c_void_p, c_char_p, c_int64, c_int, c_int, c_char_p, c_char_p, c_char_p, c_char_p, c_uint32, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdUnblindTxOutData", c_int, [c_void_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p_p, c_int64_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdCalculateEcSignature", c_int, [c_void_p, c_char_p, c_char_p, c_char_p, c_int, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdVerifyEcSignature", c_int, [c_void_p, c_char_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdSignEcdsaAdaptor", c_int, [c_void_p, c_char_p, c_char_p, c_char_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdAdaptEcdsaAdaptor", c_int, [c_void_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdExtractEcdsaAdaptorSecret", c_int, [c_void_p, c_char_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdVerifyEcdsaAdaptor", c_int, [c_void_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdGetSchnorrPubkeyFromPrivkey", c_int, [c_void_p, c_char_p, c_char_p_p, c_bool_p]),  # noqa: E501
        ("CfdGetSchnorrPubkeyFromPubkey", c_int, [c_void_p, c_char_p, c_char_p_p, c_bool_p]),  # noqa: E501
        ("CfdSchnorrPubkeyTweakAdd", c_int, [c_void_p, c_char_p, c_char_p, c_char_p_p, c_bool_p]),  # noqa: E501
        ("CfdSchnorrKeyPairTweakAdd", c_int, [c_void_p, c_char_p, c_char_p, c_char_p_p, c_bool_p, c_char_p_p]),  # noqa: E501
        ("CfdCheckTweakAddFromSchnorrPubkey", c_int, [c_void_p, c_char_p, c_bool, c_char_p, c_char_p]),  # noqa: E501
        ("CfdSignSchnorr", c_int, [c_void_p, c_char_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdSignSchnorrWithNonce", c_int, [c_void_p, c_char_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdAddSighashTypeInSchnorrSignature", c_int, [c_void_p, c_char_p, c_int, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdGetSighashTypeFromSchnorrSignature", c_int, [c_void_p, c_char_p, c_int_p, c_bool_p]),  # noqa: E501
        ("CfdComputeSchnorrSigPoint", c_int, [c_void_p, c_char_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdVerifySchnorr", c_int, [c_void_p, c_char_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdSplitSchnorrSignature", c_int, [c_void_p, c_char_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdEncodeSignatureByDer", c_int, [c_void_p, c_char_p, c_int, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdDecodeSignatureFromDer", c_int, [c_void_p, c_char_p, c_char_p_p, c_int_p, c_bool_p]),  # noqa: E501
        ("CfdNormalizeSignature", c_int, [c_void_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdCreateKeyPair", c_int, [c_void_p, c_bool, c_int, c_char_p_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdGetPrivkeyFromWif", c_int, [c_void_p, c_char_p, c_int, c_char_p_p]),  # noqa: E501
        ("CfdGetPrivkeyWif", c_int, [c_void_p, c_char_p, c_int, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdParsePrivkeyWif", c_int, [c_void_p, c_char_p, c_char_p_p, c_int_p, c_bool_p]),  # noqa: E501
        ("CfdGetPubkeyFromPrivkey", c_int, [c_void_p, c_char_p, c_char_p, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdGetPubkeyFingerprint", c_int, [c_void_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdCompressPubkey", c_int, [c_void_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdUncompressPubkey", c_int, [c_void_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdInitializeCombinePubkey", c_int, [c_void_p, c_void_p_p]),  # noqa: E501
        ("CfdAddCombinePubkey", c_int, [c_void_p, c_void_p, c_char_p]),  # noqa: E501
        ("CfdFinalizeCombinePubkey", c_int, [c_void_p, c_void_p, c_char_p_p]),  # noqa: E501
        ("CfdFreeCombinePubkeyHandle", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdPubkeyTweakAdd", c_int, [c_void_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdPubkeyTweakMul", c_int, [c_void_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdNegatePubkey", c_int, [c_void_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdPrivkeyTweakAdd", c_int, [c_void_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdPrivkeyTweakMul", c_int, [c_void_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdNegatePrivkey", c_int, [c_void_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdCreateExtkeyFromSeed", c_int, [c_void_p, c_char_p, c_int, c_int, c_char_p_p]),  # noqa: E501
        ("CfdCreateExtkey", c_int, [c_void_p, c_int, c_int, c_char_p, c_char_p, c_char_p, c_char_p, c_ubyte, c_uint32, c_char_p_p]),  # noqa: E501
        ("CfdCreateExtkeyFromParent", c_int, [c_void_p, c_char_p, c_uint32, c_bool, c_int, c_int, c_char_p_p]),  # noqa: E501
        ("CfdCreateExtkeyFromParentPath", c_int, [c_void_p, c_char_p, c_char_p, c_int, c_int, c_char_p_p]),  # noqa: E501
        ("CfdCreateExtPubkey", c_int, [c_void_p, c_char_p, c_int, c_char_p_p]),  # noqa: E501
        ("CfdGetPrivkeyFromExtkey", c_int, [c_void_p, c_char_p, c_int, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdGetPubkeyFromExtkey", c_int, [c_void_p, c_char_p, c_int, c_char_p_p]),  # noqa: E501
        ("CfdGetParentExtkeyPathData", c_int, [c_void_p, c_char_p, c_char_p, c_int, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdGetExtkeyInformation", c_int, [c_void_p, c_char_p, c_char_p_p, c_char_p_p, c_char_p_p, c_uint32_p, c_uint32_p]),  # noqa: E501
        ("CfdGetExtkeyInfo", c_int, [c_void_p, c_char_p, c_char_p_p, c_char_p_p, c_char_p_p, c_uint32_p, c_uint32_p, c_int_p, c_int_p]),  # noqa: E501
        ("CfdInitializeMnemonicWordList", c_int, [c_void_p, c_char_p, c_void_p_p, c_uint32_p]),  # noqa: E501
        ("CfdGetMnemonicWord", c_int, [c_void_p, c_void_p, c_uint32, c_char_p_p]),  # noqa: E501
        ("CfdFreeMnemonicWordList", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdConvertMnemonicToSeed", c_int, [c_void_p, c_char_p, c_char_p, c_bool, c_char_p, c_bool, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdConvertEntropyToMnemonic", c_int, [c_void_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdInitializeTxSerializeForLedger", c_int, [c_void_p, c_void_p_p]),  # noqa: E501
        ("CfdAddTxOutMetaDataForLedger", c_int, [c_void_p, c_void_p, c_uint32, c_char_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdFinalizeTxSerializeForLedger", c_int, [c_void_p, c_void_p, c_int, c_char_p, c_bool, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdFinalizeTxSerializeHashForLedger", c_int, [c_void_p, c_void_p, c_int, c_char_p, c_bool, c_bool, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdFreeTxSerializeForLedger", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdCreatePsbtHandle", c_int, [c_void_p, c_int, c_char_p, c_char_p, c_uint32, c_uint32, c_void_p_p]),  # noqa: E501
        ("CfdFreePsbtHandle", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdGetPsbtData", c_int, [c_void_p, c_void_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdGetPsbtGlobalData", c_int, [c_void_p, c_void_p, c_uint32_p, c_char_p_p, c_uint32_p, c_uint32_p]),  # noqa: E501
        ("CfdJoinPsbt", c_int, [c_void_p, c_void_p, c_char_p]),  # noqa: E501
        ("CfdSignPsbt", c_int, [c_void_p, c_void_p, c_char_p, c_bool]),  # noqa: E501
        ("CfdCombinePsbt", c_int, [c_void_p, c_void_p, c_char_p]),  # noqa: E501
        ("CfdFinalizePsbt", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdExtractPsbtTransaction", c_int, [c_void_p, c_void_p, c_char_p_p]),  # noqa: E501
        ("CfdIsFinalizedPsbt", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdIsFinalizedPsbtInput", c_int, [c_void_p, c_void_p, c_char_p, c_uint32]),  # noqa: E501
        ("CfdAddPsbtTxInWithPubkey", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_uint32, c_int64, c_char_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdAddPsbtTxInWithScript", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_uint32, c_int64, c_char_p, c_char_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdSetPsbtTxInUtxo", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_int64, c_char_p, c_char_p]),  # noqa: E501
        ("CfdSetPsbtTxInBip32Pubkey", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_char_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdSetPsbtSignature", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_char_p, c_char_p]),  # noqa: E501
        ("CfdSetPsbtSighashType", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_int]),  # noqa: E501
        ("CfdSetPsbtFinalizeScript", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_char_p]),  # noqa: E501
        ("CfdClearPsbtSignData", c_int, [c_void_p, c_void_p, c_char_p, c_uint32]),  # noqa: E501
        ("CfdGetPsbtSighashType", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_int_p]),  # noqa: E501
        ("CfdGetPsbtUtxoData", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_int64_p, c_char_p_p, c_char_p_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdGetPsbtUtxoDataByIndex", c_int, [c_void_p, c_void_p, c_uint32, c_char_p_p, c_uint32_p, c_int64_p, c_char_p_p, c_char_p_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdAddPsbtTxOutWithPubkey", c_int, [c_void_p, c_void_p, c_int64, c_char_p, c_char_p, c_uint32_p]),  # noqa: E501
        ("CfdAddPsbtTxOutWithScript", c_int, [c_void_p, c_void_p, c_int64, c_char_p, c_char_p, c_char_p, c_uint32_p]),  # noqa: E501
        ("CfdSetPsbtTxOutBip32Pubkey", c_int, [c_void_p, c_void_p, c_uint32, c_char_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdGetPsbtTxInIndex", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_uint32_p]),  # noqa: E501
        ("CfdGetPsbtPubkeyRecord", c_int, [c_void_p, c_void_p, c_int, c_uint32, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdIsFindPsbtPubkeyRecord", c_int, [c_void_p, c_void_p, c_int, c_uint32, c_char_p]),  # noqa: E501
        ("CfdGetPsbtBip32Data", c_int, [c_void_p, c_void_p, c_int, c_uint32, c_char_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdGetPsbtPubkeyList", c_int, [c_void_p, c_void_p, c_int, c_uint32, c_uint32_p, c_void_p_p]),  # noqa: E501
        ("CfdGetPsbtPubkeyListData", c_int, [c_void_p, c_void_p, c_uint32, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdGetPsbtPubkeyListBip32Data", c_int, [c_void_p, c_void_p, c_uint32, c_char_p_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdFreePsbtPubkeyList", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdGetPsbtByteDataList", c_int, [c_void_p, c_void_p, c_int, c_uint32, c_uint32_p, c_void_p_p]),  # noqa: E501
        ("CfdGetPsbtByteDataItem", c_int, [c_void_p, c_void_p, c_uint32, c_char_p_p]),  # noqa: E501
        ("CfdFreePsbtByteDataList", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdAddPsbtGlobalXpubkey", c_int, [c_void_p, c_void_p, c_char_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdSetPsbtRedeemScript", c_int, [c_void_p, c_void_p, c_int, c_uint32, c_char_p]),  # noqa: E501
        ("CfdAddPsbtRecord", c_int, [c_void_p, c_void_p, c_int, c_uint32, c_char_p, c_char_p]),  # noqa: E501
        ("CfdGetPsbtRecord", c_int, [c_void_p, c_void_p, c_int, c_uint32, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdIsFindPsbtRecord", c_int, [c_void_p, c_void_p, c_int, c_uint32, c_char_p]),  # noqa: E501
        ("CfdVerifyPsbtTxIn", c_int, [c_void_p, c_void_p, c_char_p, c_uint32]),  # noqa: E501
        ("CfdInitializeFundPsbt", c_int, [c_void_p, c_void_p_p]),  # noqa: E501
        ("CfdFundPsbtAddToUtxoList", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_int64, c_char_p, c_char_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdSetOptionFundPsbt", c_int, [c_void_p, c_void_p, c_int, c_int64, c_double, c_bool]),  # noqa: E501
        ("CfdFinalizeFundPsbt", c_int, [c_void_p, c_void_p, c_void_p, c_char_p, c_int64_p, c_uint32_p]),  # noqa: E501
        ("CfdGetFundPsbtUsedUtxo", c_int, [c_void_p, c_void_p, c_uint32, c_uint32_p, c_char_p_p, c_uint32_p, c_int64_p, c_char_p_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdFreeFundPsbt", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdParseScript", c_int, [c_void_p, c_char_p, c_void_p_p, c_uint32_p]),  # noqa: E501
        ("CfdGetScriptItem", c_int, [c_void_p, c_void_p, c_uint32, c_char_p_p]),  # noqa: E501
        ("CfdFreeScriptItemHandle", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdConvertScriptAsmToHex", c_int, [c_void_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdInitializeMultisigScriptSig", c_int, [c_void_p, c_void_p_p]),  # noqa: E501
        ("CfdAddMultisigScriptSigData", c_int, [c_void_p, c_void_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdAddMultisigScriptSigDataToDer", c_int, [c_void_p, c_void_p, c_char_p, c_int, c_bool, c_char_p]),  # noqa: E501
        ("CfdFinalizeMultisigScriptSig", c_int, [c_void_p, c_void_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdFreeMultisigScriptSigHandle", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdInitializeTaprootScriptTree", c_int, [c_void_p, c_void_p_p]),  # noqa: E501
        ("CfdSetInitialTapLeaf", c_int, [c_void_p, c_void_p, c_char_p, c_uint8]),  # noqa: E501
        ("CfdSetInitialTapBranchByHash", c_int, [c_void_p, c_void_p, c_char_p]),  # noqa: E501
        ("CfdSetScriptTreeFromString", c_int, [c_void_p, c_void_p, c_char_p, c_char_p, c_uint8, c_char_p]),  # noqa: E501
        ("CfdSetTapScriptByWitnessStack", c_int, [c_void_p, c_void_p, c_char_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdAddTapBranchByHash", c_int, [c_void_p, c_void_p, c_char_p]),  # noqa: E501
        ("CfdAddTapBranchByScriptTree", c_int, [c_void_p, c_void_p, c_void_p]),  # noqa: E501
        ("CfdAddTapBranchByScriptTreeString", c_int, [c_void_p, c_void_p, c_char_p]),  # noqa: E501
        ("CfdAddTapBranchByTapLeaf", c_int, [c_void_p, c_void_p, c_char_p, c_uint8]),  # noqa: E501
        ("CfdGetBaseTapLeaf", c_int, [c_void_p, c_void_p, c_uint8_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdGetTapBranchCount", c_int, [c_void_p, c_void_p, c_uint32_p]),  # noqa: E501
        ("CfdGetTapBranchData", c_int, [c_void_p, c_void_p, c_uint8, c_bool, c_char_p_p, c_uint8_p, c_char_p_p, c_uint8_p]),  # noqa: E501
        ("CfdGetTapBranchHandle", c_int, [c_void_p, c_void_p, c_uint8, c_char_p_p, c_void_p_p]),  # noqa: E501
        ("CfdGetTaprootScriptTreeHash", c_int, [c_void_p, c_void_p, c_char_p, c_char_p_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdGetTaprootTweakedPrivkey", c_int, [c_void_p, c_void_p, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdGetTaprootScriptTreeSrting", c_int, [c_void_p, c_void_p, c_char_p_p]),  # noqa: E501
        ("CfdFreeTaprootScriptTreeHandle", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdInitializeTransaction", c_int, [c_void_p, c_int, c_uint32, c_uint32, c_char_p, c_void_p_p]),  # noqa: E501
        ("CfdAddTransactionInput", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_uint32]),  # noqa: E501
        ("CfdAddTransactionOutput", c_int, [c_void_p, c_void_p, c_int64, c_char_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdSplitTxOut", c_int, [c_void_p, c_void_p, c_void_p, c_uint32]),  # noqa: E501
        ("CfdUpdateWitnessStack", c_int, [c_void_p, c_void_p, c_int, c_char_p, c_uint32, c_uint32, c_char_p]),  # noqa: E501
        ("CfdClearWitnessStack", c_int, [c_void_p, c_void_p, c_char_p, c_uint32]),  # noqa: E501
        ("CfdUpdateTxInScriptSig", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_char_p]),  # noqa: E501
        ("CfdUpdateTxInSequence", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_uint32]),  # noqa: E501
        ("CfdSetTransactionUtxoData", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_int64, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_bool]),  # noqa: E501
        ("CfdCreateSighashByHandle", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_int, c_bool, c_char_p, c_char_p, c_char_p, c_uint32, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdAddSignWithPrivkeyByHandle", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_char_p, c_int, c_bool, c_bool, c_char_p, c_char_p]),  # noqa: E501
        ("CfdVerifyTxSignByHandle", c_int, [c_void_p, c_void_p, c_char_p, c_uint32]),  # noqa: E501
        ("CfdAddTxSignByHandle", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_int, c_char_p, c_bool, c_int, c_bool, c_bool]),  # noqa: E501
        ("CfdAddTaprootSignByHandle", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_char_p, c_char_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdAddPubkeyHashSignByHandle", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_int, c_char_p, c_char_p, c_bool, c_int, c_bool]),  # noqa: E501
        ("CfdAddScriptHashLastSignByHandle", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_int, c_char_p]),  # noqa: E501
        ("CfdFinalizeTransaction", c_int, [c_void_p, c_void_p, c_char_p_p]),  # noqa: E501
        ("CfdFreeTransactionHandle", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdCreateSplitTxOutHandle", c_int, [c_void_p, c_void_p, c_void_p_p]),  # noqa: E501
        ("CfdAddSplitTxOutData", c_int, [c_void_p, c_void_p, c_int64, c_char_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdFreeSplitTxOutHandle", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdUpdateTxOutAmount", c_int, [c_void_p, c_int, c_char_p, c_uint32, c_int64, c_char_p_p]),  # noqa: E501
        ("CfdAddTxSign", c_int, [c_void_p, c_int, c_char_p, c_char_p, c_uint32, c_int, c_char_p, c_bool, c_int, c_bool, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdAddPubkeyHashSign", c_int, [c_void_p, c_int, c_char_p, c_char_p, c_uint32, c_int, c_char_p, c_char_p, c_bool, c_int, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdAddScriptHashSign", c_int, [c_void_p, c_int, c_char_p, c_char_p, c_uint32, c_int, c_char_p, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdAddSignWithPrivkeySimple", c_int, [c_void_p, c_int, c_char_p, c_char_p, c_uint32, c_int, c_char_p, c_char_p, c_int64, c_int, c_bool, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdInitializeMultisigSign", c_int, [c_void_p, c_void_p_p]),  # noqa: E501
        ("CfdAddMultisigSignData", c_int, [c_void_p, c_void_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdAddMultisigSignDataToDer", c_int, [c_void_p, c_void_p, c_char_p, c_int, c_bool, c_char_p]),  # noqa: E501
        ("CfdFinalizeMultisigSign", c_int, [c_void_p, c_void_p, c_int, c_char_p, c_char_p, c_uint32, c_int, c_char_p, c_char_p_p]),  # noqa: E501
        ("CfdFreeMultisigSignHandle", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdVerifySignature", c_int, [c_void_p, c_int, c_char_p, c_char_p, c_int, c_char_p, c_char_p, c_char_p, c_uint32, c_int, c_bool, c_int64, c_char_p]),  # noqa: E501
        ("CfdVerifyTxSign", c_int, [c_void_p, c_int, c_char_p, c_char_p, c_uint32, c_char_p, c_int, c_char_p, c_int64, c_char_p]),  # noqa: E501
        ("CfdCreateSighash", c_int, [c_void_p, c_int, c_char_p, c_char_p, c_uint32, c_int, c_char_p, c_char_p, c_int64, c_int, c_bool, c_char_p_p]),  # noqa: E501
        ("CfdGetTxInfo", c_int, [c_void_p, c_int, c_char_p, c_char_p_p, c_char_p_p, c_uint32_p, c_uint32_p, c_uint32_p, c_uint32_p, c_uint32_p]),  # noqa: E501
        ("CfdGetTxIn", c_int, [c_void_p, c_int, c_char_p, c_uint32, c_char_p_p, c_uint32_p, c_uint32_p, c_char_p_p]),  # noqa: E501
        ("CfdGetTxInWitness", c_int, [c_void_p, c_int, c_char_p, c_uint32, c_uint32, c_char_p_p]),  # noqa: E501
        ("CfdGetTxOut", c_int, [c_void_p, c_int, c_char_p, c_uint32, c_int64_p, c_char_p_p]),  # noqa: E501
        ("CfdGetTxInCount", c_int, [c_void_p, c_int, c_char_p, c_uint32_p]),  # noqa: E501
        ("CfdGetTxInWitnessCount", c_int, [c_void_p, c_int, c_char_p, c_uint32, c_uint32_p]),  # noqa: E501
        ("CfdGetTxOutCount", c_int, [c_void_p, c_int, c_char_p, c_uint32_p]),  # noqa: E501
        ("CfdGetTxInIndex", c_int, [c_void_p, c_int, c_char_p, c_char_p, c_uint32, c_uint32_p]),  # noqa: E501
        ("CfdGetTxOutIndex", c_int, [c_void_p, c_int, c_char_p, c_char_p, c_char_p, c_uint32_p]),  # noqa: E501
        ("CfdInitializeTxDataHandle", c_int, [c_void_p, c_int, c_char_p, c_void_p_p]),  # noqa: E501
        ("CfdFreeTxDataHandle", c_int, [c_void_p, c_void_p]),  # noqa: E501
        ("CfdGetModifiedTxByHandle", c_int, [c_void_p, c_void_p, c_char_p_p]),  # noqa: E501
        ("CfdGetTxInfoByHandle", c_int, [c_void_p, c_void_p, c_char_p_p, c_char_p_p, c_uint32_p, c_uint32_p, c_uint32_p, c_uint32_p, c_uint32_p]),  # noqa: E501
        ("CfdGetTxInByHandle", c_int, [c_void_p, c_void_p, c_uint32, c_char_p_p, c_uint32_p, c_uint32_p, c_char_p_p]),  # noqa: E501
        ("CfdGetTxInWitnessByHandle", c_int, [c_void_p, c_void_p, c_int, c_uint32, c_uint32, c_char_p_p]),  # noqa: E501
        ("CfdGetTxOutByHandle", c_int, [c_void_p, c_void_p, c_uint32, c_int64_p, c_char_p_p, c_char_p_p]),  # noqa: E501
        ("CfdGetTxInCountByHandle", c_int, [c_void_p, c_void_p, c_uint32_p]),  # noqa: E501
        ("CfdGetTxInWitnessCountByHandle", c_int, [c_void_p, c_void_p, c_int, c_uint32, c_uint32_p]),  # noqa: E501
        ("CfdGetTxOutCountByHandle", c_int, [c_void_p, c_void_p, c_uint32_p]),  # noqa: E501
        ("CfdGetTxInIndexByHandle", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_uint32_p]),  # noqa: E501
        ("CfdGetTxOutIndexByHandle", c_int, [c_void_p, c_void_p, c_char_p, c_char_p, c_uint32_p]),  # noqa: E501
        ("CfdGetTxOutIndexWithOffsetByHandle", c_int, [c_void_p, c_void_p, c_uint32, c_char_p, c_char_p, c_uint32_p]),  # noqa: E501
        ("CfdInitializeFundRawTx", c_int, [c_void_p, c_int, c_uint32, c_char_p, c_void_p_p]),  # noqa: E501
        ("CfdAddTxInForFundRawTx", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_int64, c_char_p, c_char_p, c_bool, c_bool, c_bool, c_uint32, c_char_p]),  # noqa: E501
        ("CfdAddTxInTemplateForFundRawTx", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_int64, c_char_p, c_char_p, c_bool, c_bool, c_bool, c_uint32, c_char_p, c_char_p]),  # noqa: E501
        ("CfdAddTxInputForFundRawTx", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_int64, c_char_p, c_char_p, c_bool, c_bool, c_bool, c_char_p, c_uint32, c_uint32, c_char_p]),  # noqa: E501
        ("CfdAddUtxoForFundRawTx", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_int64, c_char_p, c_char_p]),  # noqa: E501
        ("CfdAddUtxoTemplateForFundRawTx", c_int, [c_void_p, c_void_p, c_char_p, c_uint32, c_int64, c_char_p, c_char_p, c_char_p]),  # noqa: E501
        ("CfdAddTargetAmountForFundRawTx", c_int, [c_void_p, c_void_p, c_uint32, c_int64, c_char_p, c_char_p]),  # noqa: E501
        ("CfdSetOptionFundRawTx", c_int, [c_void_p, c_void_p, c_int, c_int64, c_double, c_bool]),  # noqa: E501
        ("CfdFinalizeFundRawTx", c_int, [c_void_p, c_void_p, c_char_p, c_double, c_int64_p, c_uint32_p, c_char_p_p]),  # noqa: E501
        ("CfdGetAppendTxOutFundRawTx", c_int, [c_void_p, c_void_p, c_uint32, c_char_p_p]),  # noqa: E501
        ("CfdFreeFundRawTxHandle", c_int, [c_void_p, c_void_p]),  # noqa: E501
    ]

    ##
    # @brief get instance.
    # @return utility instance.
    @ classmethod
    def get_instance(cls):
        if not hasattr(cls, "_instance"):
            cls._instance = cls()
        return cls._instance

    ##
    # @var free_str_func
    # free native string buffer function.
    ##
    # @var _cfd
    # cfd dll object.
    ##
    # @var _func_map
    # cfd function map.

    ##
    # @brief constructor.
    def __init__(self):
        self._func_map = {}

        lib_path = self._collect_lib_path()
        try:
            """
            TODO: python 3.7 or lower for windows is used dll
            on the current dir only or under.
            """
            self._cfd = CDLL(lib_path)
        except OSError as e:
            print('OSError: dll path = ' + lib_path)
            raise e
        except FileNotFoundError as e:
            print('FileNotFoundError: dll path = ' + lib_path)
            raise e

        free_func = self._cfd.CfdFreeStringBuffer
        free_func.restype, free_func.argtypes = c_int, [c_char_p]
        self.free_str_func = free_func
        self._load_functions()

    ##
    # @brief collect library path.
    # @return cfd library path.
    def _collect_lib_path(self):
        has_win = platform.system() == 'Windows'
        has_mac = platform.system() == 'Darwin'
        abs_path = os.path.dirname(os.path.abspath(__file__)) + '/'

        so_ext = 'dylib' if has_mac else 'dll' if has_win else 'so'
        so_prefix = '' if has_win else 'lib'
        lib_name = '{}cfd.{}'.format(so_prefix, so_ext)
        lib_path = lib_name
        root_dir = './'
        is_find = isfile(root_dir + lib_path)

        if not is_find:
            for depth in [0, 1, 2]:
                root_dir = abs_path + '../' * depth
                if isfile(root_dir + lib_path):
                    is_find = True
                    break

        if not is_find:
            lib_path = os.path.join('cmake_build', 'Release', lib_path)
            for depth in [0, 1, 2]:
                root_dir = abs_path + '../' * depth
                if isfile(root_dir + lib_path):
                    is_find = True
                    break

        if not is_find:
            lib_path = lib_name
            if has_win:
                paths = os.getenv('PATH').split(';')
                for path in paths:
                    try:
                        fs = os.listdir(path)
                        for f in fs:
                            if f == 'lib' and isfile(
                                    os.path.join(path, 'lib', lib_name)):
                                root_dir = os.path.join(path, 'lib') + '/'
                    except WindowsError:
                        pass
            else:
                paths = ['/usr/local/lib/', '/usr/local/lib64/']
                for path in paths:
                    if isfile(path + lib_name):
                        root_dir = path

        if has_mac:
            root_dir = abspath(root_dir) + '/'
        elif has_win:
            root_dir = root_dir.replace('/', '\\')
        return root_dir + lib_path

    ##
    # @brief load cfd functions.
    # @return void
    def _load_functions(self):
        def bind_fn(name, res, args):
            try:
                fn = getattr(self._cfd, name)
                if args:
                    fn.restype, fn.argtypes = res, args
                else:
                    fn.restype = res
            except Exception as err:
                print('Exception: ' + str(err))
                print('name: ' + name)
                print('response: ' + res)
                print('parameters: ' + args)
                raise err
            # print('bind: {}, {}, {}'.format(name, res, args))
            return fn

        def in_string_fn_wrapper(fn, pos, *args):
            if isinstance(args[pos], str):
                new_args = [a for a in args]
                new_args[pos] = new_args[pos].encode('utf-8')
                return fn(*new_args)
            return fn(*args)

        def string_fn_wrapper(fn, *args):
            new_args = None
            try:
                # Return output string parameters directly without leaking
                p = c_char_p()
                new_args = [a for a in args] + [byref(p)]
                ret = fn(*new_args)
                ret_str = None if p.value is None else p.value.decode('utf-8')
                self.free_str_func(p)
                if isinstance(ret, tuple):
                    return [ret_str, ((ret[0],) + (ret_str,) + ret[1:])][True]
                else:
                    return [ret_str, (ret, ret_str)][True]
            except ArgumentError as err:
                print('Exception: ' + str(err))
                print('name: ' + str(fn))
                print('new_args: {}'.format(new_args))
                raise err

        def value_fn_wrapper(p, fn, *args):
            new_args = [a for a in args] + [byref(p)]
            ret = fn(*new_args)
            if isinstance(ret, tuple):
                return [p.value, ((ret[0],) + (p.value,) + ret[1:])][True]
            else:
                return [p.value, (ret, p.value)][True]

        def make_str_fn(f):
            return lambda *args: string_fn_wrapper(f, *args)

        def make_void_fn(fn):
            return lambda *args: value_fn_wrapper(c_void_p(), fn, *args)

        def make_bool_fn(fn):
            return lambda *args: value_fn_wrapper(c_bool(), fn, *args)

        def make_int_fn(fn):
            return lambda *args: value_fn_wrapper(c_int(), fn, *args)

        def make_uint32_fn(fn):
            return lambda *args: value_fn_wrapper(c_uint32(), fn, *args)

        def make_uint8_fn(fn):
            return lambda *args: value_fn_wrapper(c_uint8(), fn, *args)

        def make_int32_fn(fn):
            return lambda *args: value_fn_wrapper(c_int32(), fn, *args)

        def make_uint64_fn(fn):
            return lambda *args: value_fn_wrapper(c_uint64(), fn, *args)

        def make_int64_fn(fn):
            return lambda *args: value_fn_wrapper(c_int64(), fn, *args)

        def make_input_str_fn(fn, pos):
            return lambda *args: in_string_fn_wrapper(fn, pos, *args)

        for func_info in CfdUtil._FUNC_LIST:
            name, restype, argtypes = func_info

            in_str_pos = [i for (i, t) in enumerate(argtypes) if t == c_char_p]
            str_pos = [i for (i, t) in enumerate(argtypes) if t == c_char_p_p]
            void_pos = [i for (i, t) in enumerate(argtypes) if t == c_void_p_p]
            bool_pos = [i for (i, t) in enumerate(argtypes) if t == c_bool_p]
            int_pos = [i for (i, t) in enumerate(argtypes) if t == c_int_p]
            int32_pos = [i for (i, t) in enumerate(argtypes) if t == c_int32_p]
            uint32_pos = [i for (i, t) in enumerate(
                argtypes) if t == c_uint32_p]
            uint8_pos = [i for (i, t) in enumerate(
                argtypes) if t == c_uint8_p]
            int64_pos = [i for (i, t) in enumerate(argtypes) if t == c_int64_p]
            uint64_pos = [i for (i, t) in enumerate(
                argtypes) if t == c_uint64_p]
            for i in range(len(argtypes)):
                if isinstance(argtypes[i], CCharPP):
                    argtypes[i] = POINTER(c_char_p)
                elif isinstance(argtypes[i], CVoidPP):
                    argtypes[i] = POINTER(c_void_p)
                elif isinstance(argtypes[i], CBoolP):
                    argtypes[i] = POINTER(c_bool)
                elif isinstance(argtypes[i], CIntP):
                    argtypes[i] = POINTER(c_int)
                elif isinstance(argtypes[i], CInt32P):
                    argtypes[i] = POINTER(c_int32)
                elif isinstance(argtypes[i], CUint32P):
                    argtypes[i] = POINTER(c_uint32)
                elif isinstance(argtypes[i], CUint8P):
                    argtypes[i] = POINTER(c_uint8)
                elif isinstance(argtypes[i], CInt64P):
                    argtypes[i] = POINTER(c_int64)
                elif isinstance(argtypes[i], CUint64P):
                    argtypes[i] = POINTER(c_uint64)

            fn = bind_fn(name, restype, argtypes)

            i = len(argtypes) - 1
            while i >= 0:
                if len(str_pos) > 0 and i in str_pos:
                    fn = make_str_fn(fn)
                elif len(void_pos) > 0 and i in void_pos:
                    fn = make_void_fn(fn)
                elif len(bool_pos) > 0 and i in bool_pos:
                    fn = make_bool_fn(fn)
                elif len(int_pos) > 0 and i in int_pos:
                    fn = make_int_fn(fn)
                elif len(int32_pos) > 0 and i in int32_pos:
                    fn = make_int32_fn(fn)
                elif len(uint32_pos) > 0 and i in uint32_pos:
                    fn = make_uint32_fn(fn)
                elif len(uint8_pos) > 0 and i in uint8_pos:
                    fn = make_uint8_fn(fn)
                elif len(int64_pos) > 0 and i in int64_pos:
                    fn = make_int64_fn(fn)
                elif len(uint64_pos) > 0 and i in uint64_pos:
                    fn = make_uint64_fn(fn)
                i -= 1

            if len(in_str_pos) > 0 and fn:
                for pos in in_str_pos:
                    fn = make_input_str_fn(fn, pos)
            self._func_map[name] = fn

    ##
    # @brief call cfd function.
    # @param[in] name       function name.
    # @param[in] *args      function arguments.
    # @return response data.
    # @throw CfdError   occurred error.
    def call_func(self, name, *args):
        # print('call: {}{}'.format(name, args))
        ret = self._func_map[name](*args)
        err_code = ret
        if isinstance(ret, tuple):
            err_code = ret[0]
        if err_code != 0:
            message = 'Error: ' + name
            if len(args) > 0 and \
                    args[0] != 'CfdCreateSimpleHandle' and \
                    args[0] != 'CfdFreeHandle' and \
                    args[0] != 'CfdFreeBuffer':
                temp_ret, err_msg = self._func_map['CfdGetLastErrorMessage'](
                    args[0])
                if temp_ret == 0:
                    message = err_msg
            raise CfdError(error_code=err_code, message=message)
        if isinstance(ret, tuple) is False:
            return
        elif len(ret) == 1:
            return ret[0]
        elif len(ret) == 2:
            return ret[1]
        else:
            return ret[1:]

    ##
    # @brief create cfd handle.
    # @return cfd handle
    # @throw CfdError   occurred error.
    def create_handle(self) -> 'CfdHandle':
        ret, handle = self._func_map['CfdCreateSimpleHandle']()
        if ret != 0:
            raise CfdError(
                error_code=ret,
                message='Error: CfdCreateSimpleHandle')
        return CfdHandle(handle)

    ##
    # @brief free cfd handle.
    # @param[in] handle     cfd handle
    # @return result
    def free_handle(self, handle) -> c_int:
        return self._func_map['CfdFreeHandle'](handle)


##
# @brief get utility object.
# @return utility object.
def get_util() -> 'CfdUtil':
    return CfdUtil.get_instance()


##
# All import target.
__all__ = [
    'CfdError',
    'ByteData',
    'ReverseByteData'
]
