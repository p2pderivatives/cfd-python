# -*- coding: utf-8 -*-
##
# @file script.py
# @brief bitcoin script function implements file.
# @note Copyright 2020 CryptoGarage
from typing import List, Union
from .util import CfdError, to_hex_string, get_util, JobHandle
from .key import SignParameter, SigHashType
from enum import Enum


##
# @class HashType
# @brief Hash Type
class HashType(Enum):
    ##
    # HashType: p2sh
    P2SH = 1
    ##
    # HashType: p2pkh
    P2PKH = 2
    ##
    # HashType: p2wsh
    P2WSH = 3
    ##
    # HashType: p2wpkh
    P2WPKH = 4
    ##
    # HashType: p2sh-p2wsh
    P2SH_P2WSH = 5
    ##
    # HashType: p2sh-p2wpkh
    P2SH_P2WPKH = 6
    ##
    # HashType: taproot
    TAPROOT = 7
    ##
    # HashType: unknown
    UNKNOWN = 255

    ##
    # @brief get string.
    # @return name.
    def __str__(self) -> str:
        return self.name.lower().replace('_', '-')

    ##
    # @brief get string.
    # @return name.
    def as_str(self) -> str:
        return self.name.lower().replace('_', '-')

    ##
    # @brief get object.
    # @param[in] hashtype  hashtype
    # @return object
    @classmethod
    def get(cls, hashtype) -> 'HashType':
        if (isinstance(hashtype, HashType)):
            return hashtype
        elif (isinstance(hashtype, int)):
            _num = int(hashtype)
            for hash_type in HashType:
                if _num == hash_type.value:
                    return hash_type
        else:
            _hash_type = str(hashtype).lower()
            for hash_type in HashType:
                if _hash_type == hash_type.name.lower():
                    return hash_type
            if _hash_type == 'p2sh-p2wsh':
                return HashType.P2SH_P2WSH
            elif _hash_type == 'p2sh-p2wpkh':
                return HashType.P2SH_P2WPKH
        raise CfdError(
            error_code=1,
            message='Error: Invalid hash type: {}'.format(hashtype))


##
# @class Script
# @brief Script
class Script:
    ##
    # @var hex
    # script hex
    hex: str
    ##
    # @var asm
    # asm
    asm: str

    ##
    # @brief get script from asm.
    # @param[in] script_items  asm strings (list or string)
    # @return script object
    @classmethod
    def from_asm(cls, script_items: Union[List[str], str]) -> 'Script':
        _asm = script_items
        if isinstance(script_items, list):
            _asm = ' '.join(script_items)
        if len(_asm) == 0:
            raise CfdError(
                error_code=1,
                message='Error: empty script items.')
        util = get_util()
        with util.create_handle() as handle:
            _hex = util.call_func(
                'CfdConvertScriptAsmToHex', handle.get_handle(), _asm)
            return Script(_hex)

    ##
    # @brief create multisig scriptsig.
    # @param[in] redeem_script          multisig script
    # @param[in] sign_parameter_list    signature list
    # @return script object
    @classmethod
    def create_multisig_scriptsig(
            cls, redeem_script,
            sign_parameter_list: List['SignParameter']) -> 'Script':
        _script = to_hex_string(redeem_script)
        util = get_util()
        with util.create_handle() as handle:
            work_handle = util.call_func(
                'CfdInitializeMultisigScriptSig', handle.get_handle())
            with JobHandle(
                    handle,
                    work_handle,
                    'CfdFreeMultisigScriptSigHandle') as script_handle:
                for param in sign_parameter_list:
                    if isinstance(param, SignParameter) is False:
                        raise CfdError(
                            error_code=1,
                            message='Error: Invalid sign_parameter_list item.')
                    if (len(param.hex) <= 130) and param.use_der_encode:
                        _sighashtype = SigHashType.get(param.sighashtype)
                        util.call_func(
                            'CfdAddMultisigScriptSigDataToDer',
                            handle.get_handle(), script_handle.get_handle(),
                            param.hex, _sighashtype.value,
                            _sighashtype.anyone_can_pay(),
                            param.related_pubkey)
                    else:
                        util.call_func(
                            'CfdAddMultisigScriptSigData',
                            handle.get_handle(), script_handle.get_handle(),
                            param.hex, param.related_pubkey)
                scriptsig = util.call_func(
                    'CfdFinalizeMultisigScriptSig',
                    handle.get_handle(), script_handle.get_handle(),
                    _script)
                return Script(scriptsig)

    ##
    # @brief constructor.
    # @param[in] script     script
    def __init__(self, script):
        if isinstance(script, Script):
            self.hex = script.hex
            self.asm = script.asm
        else:
            self.hex = to_hex_string(script)
            self.asm = Script._parse(self.hex)

    ##
    # @brief get string.
    # @return script hex.
    def __str__(self) -> str:
        return self.hex

    ##
    # @brief parse script.
    # @param[in] script     script
    # @return script asm
    @classmethod
    def _parse(cls, script):
        util = get_util()
        script_list = []
        if not script:
            return ''

        with util.create_handle() as handle:
            work_handle, max_index = util.call_func(
                'CfdParseScript', handle.get_handle(), script)
            with JobHandle(
                    handle,
                    work_handle,
                    'CfdFreeScriptItemHandle') as script_handle:
                for i in range(max_index):
                    item = util.call_func(
                        'CfdGetScriptItem',
                        handle.get_handle(), script_handle.get_handle(), i)
                    script_list.append(item)
        return ' '.join(script_list)


##
# All import target.
__all__ = [
    'Script',
    'HashType'
]
