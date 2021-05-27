# -*- coding: utf-8 -*-
##
# @file descriptor.py
# @brief hdwallet function implements file.
# @note Copyright 2020 CryptoGarage
from typing import List, Optional, Tuple, Union
from .util import get_util, JobHandle, CfdError
from .address import Address, AddressUtil
from .key import Network, Pubkey, SchnorrPubkey
from .hdwallet import ExtPubkey, ExtPrivkey
from .script import HashType, Script
from enum import Enum


##
# @class DescriptorScriptType
# @brief Descriptor script type
class DescriptorScriptType(Enum):
    ##
    # null
    NULL = 0
    ##
    # p2sh
    SH = 1
    ##
    # p2wsh
    WSH = 2
    ##
    # p2pk
    PK = 3
    ##
    # p2pkh
    PKH = 4
    ##
    # p2wpkh
    WPKH = 5
    ##
    # combo
    COMBO = 6
    ##
    # multi
    MULTI = 7
    ##
    # sorted multi
    SORTED_MULTI = 8
    ##
    # address
    ADDR = 9
    ##
    # raw
    RAW = 10
    ##
    # miniscript(internal)
    MINISCRIPT = 11
    ##
    # taproot
    TAPROOT = 12

    ##
    # @brief get string.
    # @return name.
    def as_str(self) -> str:
        return self.name.lower().replace('_', '')

    ##
    # @brief get object.
    # @param[in] desc_type      descriptor type
    # @return object.
    @classmethod
    def get(cls, desc_type) -> 'DescriptorScriptType':
        if (isinstance(desc_type, DescriptorScriptType)):
            return desc_type
        elif (isinstance(desc_type, int)):
            _num = int(desc_type)
            for type_data in DescriptorScriptType:
                if _num == type_data.value:
                    return type_data
        else:
            _type = str(desc_type).lower()
            for type_data in DescriptorScriptType:
                if _type == type_data.name.lower():
                    return type_data
        raise CfdError(
            error_code=1,
            message='Error: Invalid type.')


##
# @class DescriptorKeyType
# @brief Descriptor key type
class DescriptorKeyType(Enum):
    ##
    # null
    NULL = 0
    ##
    # public key
    PUBLIC = 1
    ##
    # bip32 (ext pubkey)
    BIP32 = 2
    ##
    # bip32 (ext privkey)
    BIP32_PRIV = 3
    ##
    # schnorr pubkey
    SCHNORR_PUBKEY = 4

    ##
    # @brief get string.
    # @return name.
    def as_str(self) -> str:
        if self == DescriptorKeyType.PUBLIC:
            return 'pubkey'
        elif self == DescriptorKeyType.BIP32:
            return 'extPubkey'
        elif self == DescriptorKeyType.BIP32_PRIV:
            return 'extPrivkey'
        elif self == DescriptorKeyType.SCHNORR_PUBKEY:
            return 'schnorrPubkey'
        return self.name

    ##
    # @brief get object.
    # @param[in] desc_type      descriptor type
    # @return object.
    @classmethod
    def get(cls, desc_type) -> 'DescriptorKeyType':
        if (isinstance(desc_type, DescriptorKeyType)):
            return desc_type
        elif (isinstance(desc_type, int)):
            _num = int(desc_type)
            for type_data in DescriptorKeyType:
                if _num == type_data.value:
                    return type_data
        else:
            _type = str(desc_type).lower()
            for type_data in DescriptorKeyType:
                if _type == type_data.name.lower():
                    return type_data
            if _type == 'pubkey':
                return DescriptorKeyType.PUBLIC
            elif _type == 'extpubkey':
                return DescriptorKeyType.BIP32
            elif _type == 'extprivkey':
                return DescriptorKeyType.BIP32_PRIV
            elif _type == 'schnorrpubkey':
                return DescriptorKeyType.SCHNORR_PUBKEY
        raise CfdError(
            error_code=1,
            message='Error: Invalid type.')


##
# @class DescriptorKeyData
# @brief Descriptor key data
class DescriptorKeyData:
    ##
    # @var key_type
    # key type
    key_type: 'DescriptorKeyType'
    ##
    # @var pubkey
    # pubkey
    pubkey: Union['Pubkey', str]
    ##
    # @var ext_pubkey
    # ext pubkey
    ext_pubkey: Union['ExtPubkey', str]
    ##
    # @var ext_privkey
    # ext privkey
    ext_privkey: Union['ExtPrivkey', str]
    ##
    # @var schnorr_pubkey
    # schnorr pubkey
    schnorr_pubkey: Union['SchnorrPubkey', str]

    ##
    # @brief constructor.
    # @param[in] key_type       key type
    # @param[in] pubkey         pubkey
    # @param[in] ext_pubkey     ext pubkey
    # @param[in] ext_privkey    ext privkey
    # @param[in] schnorr_pubkey     schnorr pubkey
    def __init__(
            self,
            key_type=DescriptorKeyType.NULL,
            pubkey='',
            ext_pubkey='',
            ext_privkey='',
            schnorr_pubkey=''):
        self.key_type = DescriptorKeyType.get(key_type)
        if pubkey is None:
            self.pubkey = ''
        elif self.key_type == DescriptorKeyType.SCHNORR_PUBKEY:
            self.pubkey = ''
        else:
            self.pubkey = pubkey if isinstance(pubkey, str) else Pubkey(pubkey)
        if ext_pubkey is None:
            self.ext_pubkey = ''
        elif isinstance(ext_pubkey, str):
            self.ext_pubkey = ext_pubkey
        else:
            self.ext_pubkey = ExtPubkey(ext_pubkey)
        if ext_privkey is None:
            self.ext_privkey = ''
        elif isinstance(ext_privkey, str):
            self.ext_privkey = ext_privkey
        else:
            self.ext_privkey = ExtPrivkey(ext_privkey)

        if schnorr_pubkey is None:
            self.schnorr_pubkey = ''
        elif isinstance(schnorr_pubkey, str):
            self.schnorr_pubkey = schnorr_pubkey
        else:
            self.schnorr_pubkey = SchnorrPubkey(schnorr_pubkey)
        if self.key_type == DescriptorKeyType.SCHNORR_PUBKEY and (
                not self.schnorr_pubkey):
            self.schnorr_pubkey = str(pubkey)

    ##
    # @brief get string.
    # @return descriptor.
    def __str__(self) -> str:
        if self.key_type == DescriptorKeyType.PUBLIC:
            return str(self.pubkey)
        elif self.key_type == DescriptorKeyType.BIP32:
            return str(self.ext_pubkey)
        elif self.key_type == DescriptorKeyType.BIP32_PRIV:
            return str(self.ext_privkey)
        elif self.key_type == DescriptorKeyType.SCHNORR_PUBKEY:
            return str(self.schnorr_pubkey)
        return ''


##
# @class DescriptorScriptData
# @brief Descriptor script data
class DescriptorScriptData:
    ##
    # @var script_type
    # script type
    script_type: 'DescriptorScriptType'
    ##
    # @var depth
    # depth
    depth: int
    ##
    # @var hash_type
    # hash type
    hash_type: 'HashType'
    ##
    # @var address
    # address
    address: Union[str, 'Address']
    ##
    # @var locking_script
    # locking script
    locking_script: Union[str, 'Script']
    ##
    # @var redeem_script
    # redeem script for script hash
    redeem_script: Union[str, 'Script']
    ##
    # @var tree_string
    # taproot script tree string.
    tree_string: str
    ##
    # @var key_data
    # key data
    key_data: Optional['DescriptorKeyData']
    ##
    # @var key_list
    # key list
    key_list: List['DescriptorKeyData']
    ##
    # @var multisig_require_num
    # multisig require num
    multisig_require_num: int

    ##
    # @brief constructor.
    # @param[in] script_type    script type
    # @param[in] depth          depth
    # @param[in] hash_type      hash type
    # @param[in] address        address
    # @param[in] locking_script locking script
    # @param[in] redeem_script  redeem script
    # @param[in] key_data       key data
    # @param[in] key_list       key list
    # @param[in] multisig_require_num   multisig require num
    # @param[in] tree_string            taproot script tree string.
    def __init__(
            self, script_type: 'DescriptorScriptType', depth: int,
            hash_type: 'HashType', address,
            locking_script,
            redeem_script='',
            key_data: Optional['DescriptorKeyData'] = None,
            key_list: List['DescriptorKeyData'] = [],
            multisig_require_num: int = 0,
            tree_string: str = ''):
        self.script_type = script_type
        self.depth = depth
        self.hash_type = hash_type
        self.address = address if isinstance(
            address, Address) else str(address)
        self.locking_script = locking_script
        self.redeem_script = redeem_script
        self.key_data = key_data
        self.key_list = key_list
        self.multisig_require_num = multisig_require_num
        self.tree_string = tree_string


##
# @class Descriptor
# @brief Descriptor data
class Descriptor:
    ##
    # @var path
    # bip32 path
    path: str
    ##
    # @var descriptor
    # descriptor string
    descriptor: str
    ##
    # @var network
    # network
    network: 'Network'
    ##
    # @var script_list
    # script list
    script_list: List['DescriptorScriptData']
    ##
    # @var data
    # reference data
    data: 'DescriptorScriptData'

    ##
    # @brief constructor.
    # @param[in] descriptor     descriptor
    # @param[in] network        network
    # @param[in] path           bip32 path
    def __init__(self, descriptor, network=Network.MAINNET, path: str = ''):
        self.network = Network.get(network)
        self.path = str(path)
        self.descriptor = self._verify(str(descriptor))
        parse_data = self._parse()
        self.script_list = parse_data[0]
        self.data = parse_data[1]

    ##
    # @brief verify descriptor.
    # @param[in] descriptor     descriptor
    # @return append checksum descriptor
    def _verify(self, descriptor: str) -> str:
        util = get_util()
        with util.create_handle() as handle:
            return util.call_func(
                'CfdGetDescriptorChecksum', handle.get_handle(),
                self.network.value, descriptor)

    ##
    # @brief parse descriptor.
    # @retval[0] script list
    # @retval[1] root script
    def _parse(self) -> Tuple[
            List['DescriptorScriptData'], 'DescriptorScriptData']:
        util = get_util()
        with util.create_handle() as handle:
            work_handle, max_index = util.call_func(
                'CfdParseDescriptor', handle.get_handle(),
                self.descriptor, self.network.value, self.path)
            with JobHandle(
                    handle,
                    work_handle,
                    'CfdFreeDescriptorHandle') as desc_handle:

                def get_key(index):
                    return util.call_func(
                        'CfdGetDescriptorMultisigKey',
                        handle.get_handle(), desc_handle.get_handle(),
                        index)

                script_type, locking_script,\
                    address, hash_type, redeem_script, key_type,\
                    pubkey, ext_pubkey, ext_privkey, schnorr_pubkey,\
                    tree_string, is_multisig, max_key_num, \
                    req_sig_num = util.call_func(
                        'CfdGetDescriptorRootData',
                        handle.get_handle(), desc_handle.get_handle())
                all_key_list = []
                if key_type != 0:
                    key_data = DescriptorKeyData(
                        key_type, pubkey, ext_pubkey, ext_privkey,
                        schnorr_pubkey)
                    all_key_list.append(key_data)
                _script_type = DescriptorScriptType.get(script_type)
                _hash_type = HashType.P2SH
                if _script_type != DescriptorScriptType.RAW:
                    _hash_type = HashType.get(hash_type)
                root_data = DescriptorScriptData(
                    _script_type, 0, _hash_type, address,
                    locking_script, redeem_script,
                    key_list=all_key_list,
                    multisig_require_num=req_sig_num,
                    tree_string=tree_string)

                script_list = []
                for i in range(max_index + 1):
                    max_index, depth, script_type, locking_script,\
                        address, hash_type, redeem_script, key_type,\
                        pubkey, ext_pubkey, ext_privkey, is_multisig,\
                        max_key_num, req_sig_num = util.call_func(
                            'CfdGetDescriptorData',
                            handle.get_handle(), desc_handle.get_handle(), i)
                    _script_type = DescriptorScriptType.get(script_type)
                    _hash_type = HashType.P2SH
                    if _script_type != DescriptorScriptType.RAW:
                        _hash_type = HashType.get(hash_type)
                    data = DescriptorScriptData(
                        _script_type, depth, _hash_type, address,
                        locking_script)
                    if _script_type in {
                            DescriptorScriptType.COMBO,
                            DescriptorScriptType.PK,
                            DescriptorScriptType.PKH,
                            DescriptorScriptType.WPKH,
                            DescriptorScriptType.TAPROOT}:
                        data.key_data = DescriptorKeyData(
                            key_type, pubkey, ext_pubkey, ext_privkey)
                        data.address = AddressUtil.parse(address, hash_type)
                    elif _script_type in {
                            DescriptorScriptType.SH,
                            DescriptorScriptType.WSH,
                            DescriptorScriptType.MULTI,
                            DescriptorScriptType.SORTED_MULTI}:
                        data.address = AddressUtil.parse(address, hash_type)
                        data.redeem_script = redeem_script
                        if is_multisig:
                            key_list = []
                            for i in range(max_key_num):
                                key_info = DescriptorKeyData(*get_key(i))
                                key_list.append(key_info)
                                all_key_list.append(key_info)
                            data.key_list = key_list
                            data.multisig_require_num = req_sig_num
                    elif _script_type == DescriptorScriptType.RAW:
                        pass
                    elif _script_type == DescriptorScriptType.ADDR:
                        data.address = AddressUtil.parse(address, hash_type)

                    script_list.append(data)
                    if _script_type == DescriptorScriptType.COMBO:
                        # TODO: combo data is top only.
                        break
                root_data.key_list = all_key_list
                return script_list, root_data

    ##
    # @brief get string.
    # @return descriptor.
    def __str__(self):
        return self.descriptor


##
# @brief parse descriptor.
# @param[in] descriptor     descriptor
# @param[in] network        network
# @param[in] path           bip32 path
# @retval Descriptor        descriptor object
def parse_descriptor(descriptor, network=Network.MAINNET,
                     path: str = '') -> 'Descriptor':
    return Descriptor(descriptor, network=network, path=path)


##
# All import target.
__all__ = [
    'parse_descriptor',
    'Descriptor',
    'DescriptorScriptType',
    'DescriptorKeyType',
    'DescriptorScriptData',
    'DescriptorKeyData'
]
