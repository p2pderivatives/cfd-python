# -*- coding: utf-8 -*-
##
# @file address.py
# @brief address function implements file.
# @note Copyright 2020 CryptoGarage
from typing import Tuple, Union, Optional, List
from .util import get_util, CfdError, JobHandle, to_hex_string
from .key import Network, Pubkey, SchnorrPubkey
from .script import HashType, Script
from .taproot import TaprootScriptTree


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
    locking_script: Union[str, 'Script']
    ##
    # @var pubkey
    # pubkey for pubkey hash.
    pubkey: Union[str, 'Pubkey', 'SchnorrPubkey']
    ##
    # @var redeem_script
    # redeem script for script hash.
    redeem_script: Union[str, 'Script']
    ##
    # @var p2sh_wrapped_script
    # witness locking script for p2sh.
    p2sh_wrapped_script: Union[str, 'Script']
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
    # @var taproot_script_tree
    # Taproot script tree.
    taproot_script_tree: Optional['TaprootScriptTree'] = None

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
        if len(_pubkey) == 0:
            self.pubkey = _pubkey
        elif hash_type == HashType.TAPROOT:
            self.pubkey = SchnorrPubkey(pubkey)
        else:
            self.pubkey = Pubkey(pubkey)
        self.redeem_script = _redeem_script if len(
            _redeem_script) == 0 else Script(redeem_script)
        self.p2sh_wrapped_script = p2sh_wrapped_script
        self.hash_type = HashType.get(hash_type)
        self.network = Network.get(network)
        self.witness_version = -1
        self.taproot_script_tree = None
        if p2sh_wrapped_script and len(p2sh_wrapped_script) > 2:
            if int(p2sh_wrapped_script[0:2], 16) == 0:
                self.witness_version = 0
        elif len(_locking_script) > 2:
            ver = int(_locking_script[0:2], 16)
            if ver > 80:
                ver -= 80
            if ver <= 16:
                self.witness_version = ver

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
            network, _hash_type, _, locking_script, _ = util.call_func(
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
    # @brief get taproot address.
    # @param[in] pubkey     schnorr public key
    #   (or taproot script tree contain internal pubkey)
    # @param[in] network    network
    # @param[in] script_tree    taproot script tree
    # @return address object.
    @classmethod
    def taproot(
            cls, pubkey: Union['SchnorrPubkey', 'TaprootScriptTree'],
            network=Network.MAINNET,
            script_tree: Optional['TaprootScriptTree'] = None) -> 'Address':
        if isinstance(pubkey, TaprootScriptTree):
            pk, _, _, _ = pubkey.get_taproot_data()
            addr = cls.from_pubkey_hash(pk, HashType.TAPROOT, network)
            addr.taproot_script_tree = script_tree
            return addr
        elif isinstance(script_tree, TaprootScriptTree):
            pk, _, _, _ = script_tree.get_taproot_data(pubkey)
            addr = cls.from_pubkey_hash(pk, HashType.TAPROOT, network)
            addr.taproot_script_tree = script_tree
            return addr
        else:
            return cls.from_pubkey_hash(pubkey, HashType.TAPROOT, network)

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
                pubkey=_pubkey,
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
            work_handle = util.call_func(
                'CfdInitializeMultisigScript', handle.get_handle(),
                _network.value, _hash_type.value)
            with JobHandle(
                    handle,
                    work_handle,
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
            network=Network.MAINNET) -> List['Address']:
        _script = str(redeem_script)
        _hash_type = HashType.get(hash_type)
        _network = Network.get(network)
        util = get_util()
        addr_list = []
        with util.create_handle() as handle:
            work_handle, max_index = util.call_func(
                'CfdGetAddressesFromMultisig', handle.get_handle(),
                _script, _network.value, _hash_type.value)
            with JobHandle(
                    handle,
                    work_handle,
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
    # @brief get pegin address.
    # @param[in] fedpeg_script          fedpeg script
    # @param[in] pubkey                 pubkey
    # @param[in] redeem_script          redeem script
    # @param[in] hash_type              script hash type
    # @param[in] mainchain_network      mainchain network type
    # @retval [0]      pegin address.
    # @retval [1]      claim script.
    # @retval [2]      tweaked fedpeg script.
    @classmethod
    def get_pegin_address(
            cls,
            fedpeg_script: Union['Script', str],
            pubkey='',
            redeem_script='',
            hash_type: Union['HashType', str] = HashType.P2SH_P2WSH,
            mainchain_network=Network.MAINNET,
    ) -> Tuple['Address', 'Script', 'Script']:
        _fedpeg_script = to_hex_string(fedpeg_script)
        _hash_type = HashType.get(hash_type)
        _network = Network.get(mainchain_network)
        _pubkey = '' if pubkey is None else to_hex_string(pubkey)
        _script = '' if redeem_script is None else to_hex_string(redeem_script)
        if (not _pubkey) and (not _script):
            raise CfdError(
                error_code=1,
                message='Error: Both pubkey and redeem_script is empty.')
        elif not _script:
            _ = Pubkey(_pubkey)  # check pubkey

        util = get_util()
        with util.create_handle() as handle:
            addr, claim_script, tweaked_fedpeg = util.call_func(
                'CfdGetPeginAddress',
                handle.get_handle(), _network.value, _fedpeg_script,
                _hash_type.value, _pubkey, _script)
            return cls.parse(addr), Script(claim_script), Script(
                tweaked_fedpeg)


##
# All import target.
__all__ = ['Address', 'AddressUtil']
