# -*- coding: utf-8 -*-
##
# @file address.py
# @brief address function implements file.
# @note Copyright 2020 CryptoGarage
import typing
from .util import get_util, CfdError, JobHandle, to_hex_string
from .key import Network, Pubkey
from .script import HashType, Script


##
# @class Address
# @brief Address data.
class Address:
    ##
    # @var address
    # address string
    address: str
    ##
    # @var locking_script
    # locking script (scriptPubkey)
    locking_script: typing.Union[str, 'Script']
    ##
    # @var pubkey
    # pubkey for pubkey hash.
    pubkey: typing.Union[str, 'Pubkey']
    ##
    # @var redeem_script
    # redeem script for script hash.
    redeem_script: typing.Union[str, 'Script']
    ##
    # @var p2sh_wrapped_script
    # witness locking script for p2sh.
    p2sh_wrapped_script: typing.Union[str, 'Script']
    ##
    # @var hash_type
    # hash type.
    hash_type: 'HashType'
    ##
    # @var network
    # network.
    network: 'Network'
    ##
    # @var witness_version
    # witness version.
    witness_version: int

    ##
    # @brief constructor.
    # @param[in] address          address
    # @param[in] locking_script   locking script
    # @param[in] hash_type        hash type
    # @param[in] network          network
    # @param[in] pubkey           public key
    # @param[in] redeem_script    redeem script
    # @param[in] p2sh_wrapped_script    witness locking script for p2sh
    def __init__(
            self,
            address: str,
            locking_script,
            hash_type=HashType.P2SH,
            network=Network.MAINNET,
            pubkey='',
            redeem_script='',
            p2sh_wrapped_script=''):
        _locking_script = to_hex_string(locking_script)
        _redeem_script = to_hex_string(redeem_script)
        _pubkey = to_hex_string(pubkey)
        self.address = address
        self.locking_script = _locking_script if len(
            _locking_script) == 0 else Script(locking_script)
        self.pubkey = _pubkey if len(_pubkey) == 0 else Pubkey(pubkey)
        self.redeem_script = _redeem_script if len(
            _redeem_script) == 0 else Script(redeem_script)
        self.p2sh_wrapped_script = p2sh_wrapped_script
        self.hash_type = HashType.get(hash_type)
        self.network = Network.get(network)
        self.witness_version = -1
        if p2sh_wrapped_script and len(p2sh_wrapped_script) > 2:
            if int(_locking_script[0:2], 16) < 16:
                self.witness_version = int(p2sh_wrapped_script[0:2])
        elif len(_locking_script) > 2:
            if int(_locking_script[0:2], 16) < 16:
                self.witness_version = int(_locking_script[0:2])

    ##
    # @brief get string.
    # @return address.
    def __str__(self):
        return self.address


##
# @class AddressUtil
# @brief Address utility.
class AddressUtil:
    ##
    # @brief parse address string.
    # @param[in] address          address string
    # @param[in] hash_type        hash type
    # @return address object.
    @classmethod
    def parse(cls, address, hash_type=HashType.P2WPKH) -> 'Address':
        util = get_util()
        with util.create_handle() as handle:
            network, _hash_type, _witness_version,\
                locking_script, _ = util.call_func(
                    'CfdGetAddressInfo', handle.get_handle(), str(address))
            _hash_type = HashType.get(_hash_type)
            try:
                if _hash_type == HashType.P2SH:
                    tmp_hash_type = HashType.get(hash_type)
                    if tmp_hash_type in {
                            HashType.P2SH_P2WPKH, HashType.P2SH_P2WSH}:
                        _hash_type = tmp_hash_type
            except CfdError:
                pass
            return Address(
                str(address),
                locking_script,
                hash_type=_hash_type,
                network=Network.get(network))

    ##
    # @brief get p2pkh address.
    # @param[in] pubkey           public key
    # @param[in] network          network
    # @return address object.
    @classmethod
    def p2pkh(cls, pubkey, network=Network.MAINNET) -> 'Address':
        return cls.from_pubkey_hash(
            pubkey, HashType.P2PKH, network)

    ##
    # @brief get p2wpkh address.
    # @param[in] pubkey           public key
    # @param[in] network          network
    # @return address object.
    @classmethod
    def p2wpkh(cls, pubkey, network=Network.MAINNET) -> 'Address':
        return cls.from_pubkey_hash(
            pubkey, HashType.P2WPKH, network)

    ##
    # @brief get p2sh-p2wpkh address.
    # @param[in] pubkey           public key
    # @param[in] network          network
    # @return address object.
    @classmethod
    def p2sh_p2wpkh(cls, pubkey, network=Network.MAINNET) -> 'Address':
        return cls.from_pubkey_hash(
            pubkey, HashType.P2SH_P2WPKH, network)

    ##
    # @brief get p2sh address.
    # @param[in] redeem_script    redeem script
    # @param[in] network          network
    # @return address object.
    @classmethod
    def p2sh(cls, redeem_script, network=Network.MAINNET) -> 'Address':
        return cls.from_script_hash(
            redeem_script, HashType.P2SH, network)

    ##
    # @brief get p2wsh address.
    # @param[in] redeem_script    redeem script
    # @param[in] network          network
    # @return address object.
    @classmethod
    def p2wsh(cls, redeem_script, network=Network.MAINNET) -> 'Address':
        return cls.from_script_hash(
            redeem_script, HashType.P2WSH, network)

    ##
    # @brief get p2sh-p2wsh address.
    # @param[in] redeem_script    redeem script
    # @param[in] network          network
    # @return address object.
    @classmethod
    def p2sh_p2wsh(cls, redeem_script, network=Network.MAINNET) -> 'Address':
        return cls.from_script_hash(
            redeem_script, HashType.P2SH_P2WSH, network)

    ##
    # @brief get pubkey hash address.
    # @param[in] pubkey           public key
    # @param[in] hash_type        hash type
    # @param[in] network          network
    # @return address object.
    @classmethod
    def from_pubkey_hash(
            cls,
            pubkey,
            hash_type,
            network=Network.MAINNET) -> 'Address':
        _pubkey = str(pubkey)
        _hash_type = HashType.get(hash_type)
        _network = Network.get(network)
        util = get_util()
        with util.create_handle() as handle:
            addr, locking_script, segwit_locking_script = util.call_func(
                'CfdCreateAddress',
                handle.get_handle(), _hash_type.value, _pubkey,
                '', _network.value)
            return Address(
                addr,
                locking_script,
                hash_type=_hash_type,
                network=_network,
                pubkey=Pubkey(_pubkey),
                p2sh_wrapped_script=segwit_locking_script)

    ##
    # @brief get script hash address.
    # @param[in] redeem_script    redeem script
    # @param[in] hash_type        hash type
    # @param[in] network          network
    # @return address object.
    @classmethod
    def from_script_hash(
            cls,
            redeem_script,
            hash_type,
            network=Network.MAINNET) -> 'Address':
        _script = str(redeem_script)
        _hash_type = HashType.get(hash_type)
        _network = Network.get(network)
        util = get_util()
        with util.create_handle() as handle:
            addr, locking_script, segwit_locking_script = util.call_func(
                'CfdCreateAddress',
                handle.get_handle(), _hash_type.value, '',
                _script, _network.value)
            return Address(
                addr,
                locking_script,
                hash_type=_hash_type,
                network=_network,
                redeem_script=Script(_script),
                p2sh_wrapped_script=segwit_locking_script)

    ##
    # @brief get multisig address.
    # @param[in] require_num      require signature num
    # @param[in] pubkey_list      pubkey list
    # @param[in] hash_type        hash type
    # @param[in] network          network
    # @return address object.
    @classmethod
    def multisig(
            cls,
            require_num: int,
            pubkey_list,
            hash_type,
            network=Network.MAINNET) -> 'Address':
        if isinstance(require_num, int) is False:
            raise CfdError(
                error_code=1, message='Error: Invalid require_num type.')
        if (isinstance(pubkey_list, list) is False) or (
                len(pubkey_list) == 0):
            raise CfdError(
                error_code=1, message='Error: Invalid pubkey_list.')
        _hash_type = HashType.get(hash_type)
        _network = Network.get(network)
        util = get_util()
        with util.create_handle() as handle:
            word_handle = util.call_func(
                'CfdInitializeMultisigScript', handle.get_handle(),
                _network.value, _hash_type.value)
            with JobHandle(
                    handle,
                    word_handle,
                    'CfdFreeMultisigScriptHandle') as addr_handle:
                for pubkey in pubkey_list:
                    util.call_func(
                        'CfdAddMultisigScriptData',
                        handle.get_handle(), addr_handle.get_handle(),
                        to_hex_string(pubkey))

                addr, redeem_script, witness_script = util.call_func(
                    'CfdFinalizeMultisigScript',
                    handle.get_handle(), addr_handle.get_handle(),
                    require_num)
                if _hash_type == HashType.P2SH:
                    witness_script = redeem_script
                    redeem_script = ''

                addr_obj = AddressUtil.parse(addr)
                return Address(
                    addr,
                    addr_obj.locking_script,
                    hash_type=_hash_type,
                    network=_network,
                    redeem_script=Script(witness_script),
                    p2sh_wrapped_script=redeem_script)

    ##
    # @brief get address from locking script.
    # @param[in] locking_script   locking script
    # @param[in] network          network
    # @return address object.
    @classmethod
    def from_locking_script(
            cls,
            locking_script,
            network=Network.MAINNET) -> 'Address':
        _script = str(locking_script)
        _network = Network.get(network)
        util = get_util()
        with util.create_handle() as handle:
            addr = util.call_func(
                'CfdGetAddressFromLockingScript',
                handle.get_handle(), _script, _network.value)
            return cls.parse(addr)

    ##
    # @brief get multisig pubkey addresses.
    # @param[in] redeem_script    multisig script
    # @param[in] hash_type        hash type
    # @param[in] network          network
    # @return address object list.
    @classmethod
    def get_multisig_address_list(
            cls,
            redeem_script,
            hash_type,
            network=Network.MAINNET) -> typing.List['Address']:
        _script = str(redeem_script)
        _hash_type = HashType.get(hash_type)
        _network = Network.get(network)
        util = get_util()
        addr_list = []
        with util.create_handle() as handle:
            word_handle, max_index = util.call_func(
                'CfdGetAddressesFromMultisig', handle.get_handle(),
                _script, _network.value, _hash_type.value)
            with JobHandle(
                    handle,
                    word_handle,
                    'CfdFreeAddressesMultisigHandle') as addr_handle:
                for i in range(max_index):
                    addr, pubkey = util.call_func(
                        'CfdGetAddressFromMultisigKey',
                        handle.get_handle(), addr_handle.get_handle(), i)
                    _addr = cls.parse(addr)
                    _addr.pubkey = pubkey
                    addr_list.append(_addr)
        return addr_list


##
# All import target.
__all__ = ['Address', 'AddressUtil']
