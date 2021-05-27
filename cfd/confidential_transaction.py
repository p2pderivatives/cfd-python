# -*- coding: utf-8 -*-
##
# @file confidential_transaction.py
# @brief elements confidential transaction function implements file.
# @note Copyright 2020 CryptoGarage
from typing import Dict, List, Optional, Tuple, Union
import typing
from .util import ReverseByteData, CfdError, JobHandle,\
    CfdErrorCode, to_hex_string, get_util, ByteData
from .address import Address, AddressUtil
from .descriptor import Descriptor, parse_descriptor
from .key import Network, SigHashType, Privkey, Pubkey
from .script import HashType, Script
from .transaction import UtxoData, OutPoint, Txid, TxIn, TxOut, _FundTxOpt,\
    _TransactionBase, BlockHash, Transaction
from .confidential_address import ConfidentialAddress
from enum import Enum
import copy
import ctypes


##
# empty blinder
EMPTY_BLINDER = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]


##
# @class BlindFactor
# @brief blind factor (blinder) class.
class BlindFactor(ReverseByteData):
    ##
    # @var hex
    # hex string
    hex: str

    ##
    # @brief constructor.
    # @param[in] data   blind factor
    # @return BlindFactor
    @classmethod
    def create(cls, data=''):
        if isinstance(data, str) and (len(data) == 0):
            return BlindFactor(EMPTY_BLINDER)
        else:
            return BlindFactor(data)

    ##
    # @brief constructor.
    # @param[in] data   blind factor
    def __init__(self, data):
        super().__init__(data)
        if len(self.hex) != 64:
            raise CfdError(
                error_code=1, message='Error: Invalid blind factor.')

    ##
    # @brief check empty.
    # @retval True   empty
    # @retval False  not empty
    def is_empty(self):
        return True if self.hex == '0' * 64 else False


##
# @class ConfidentialNonce
# @brief elements nonce class.
class ConfidentialNonce:
    ##
    # @var hex
    # hex
    hex: str

    ##
    # @brief constructor.
    # @param[in] data   confidential key or nonce commitment
    def __init__(self, data=''):
        self.hex = to_hex_string(data)
        if len(self.hex) not in {0, 66}:
            raise CfdError(
                error_code=1, message='Error: Invalid nonce.')

    ##
    # @brief get string.
    # @return hex.
    def __str__(self) -> str:
        return self.hex

    ##
    # @brief check empty.
    # @retval True      empty.
    # @retval False     value exist.
    def is_empty(self) -> bool:
        return (len(self.hex) == 0)


##
# @class ConfidentialAsset
# @brief elements asset class.
class ConfidentialAsset:
    ##
    # @var hex
    # hex
    hex: str

    ##
    # @brief constructor.
    # @param[in] data   asset or asset commitment
    def __init__(self, data):
        if isinstance(data, ConfidentialAsset):
            self.hex = data.hex
            return
        self.hex = to_hex_string(data)
        if len(self.hex) == 64:
            self.hex = str(ReverseByteData(data))
        if len(self.hex) not in {0, 64, 66}:
            raise CfdError(
                error_code=1, message='Error: Invalid asset.')

    ##
    # @brief get string.
    # @return hex.
    def __str__(self) -> str:
        return self.hex

    ##
    # @brief get blind state.
    # @retval True      blinded.
    # @retval False     unblind.
    def has_blind(self) -> bool:
        if (len(self.hex) == 66) and (self.hex[0] == '0') and (
                self.hex[1].lower() in {'a', 'b'}):
            return True
        return False

    ##
    # @brief get commitment. (can use unblind only)
    # @param[in] asset_blind_factor     asset blind factor
    # @return asset commitment
    def get_commitment(self, asset_blind_factor) -> 'ConfidentialAsset':
        if self.has_blind():
            raise CfdError(
                error_code=1, message='Error: Blind asset.')
        util = get_util()
        with util.create_handle() as handle:
            commitment = util.call_func(
                'CfdGetAssetCommitment', handle.get_handle(),
                self.hex, to_hex_string(asset_blind_factor))
            return ConfidentialAsset(commitment)


##
# @class ConfidentialValue
# @brief elements value class.
class ConfidentialValue:
    ##
    # @var hex
    # hex
    hex: str
    ##
    # @var amount
    # amount
    amount: int

    ##
    # @brief create instance.
    # @param[in] value      value
    # @param[in] amount     amount
    # @return ConfidentialValue
    @classmethod
    def create(cls, value, amount: int) -> 'ConfidentialValue':
        _value_hex = to_hex_string(value)
        if isinstance(value, ConfidentialValue):
            return value
        elif len(value) == 66:
            return ConfidentialValue(_value_hex)
        else:
            return ConfidentialValue(amount)

    ##
    # @brief get hex string from amount.
    # @param[in] amount     amount
    # @return hex string
    @classmethod
    def _byte_from_amount(cls, amount: int) -> str:
        util = get_util()
        with util.create_handle() as handle:
            value_hex = util.call_func(
                'CfdGetConfidentialValueHex', handle.get_handle(),
                amount, False)
            return value_hex

    ##
    # @brief constructor.
    # @param[in] data   value or value commitment or amount
    def __init__(self, data):
        if isinstance(data, int):
            self.amount = data
            self.hex = self._byte_from_amount(self.amount)
        elif isinstance(data, float) or isinstance(data, complex):
            raise CfdError(
                error_code=1, message='Error: Invalid amount format.')
        else:
            self.hex = to_hex_string(data)
            self.amount = 0
        if len(self.hex) not in {0, 18, 66}:
            raise CfdError(
                error_code=1, message='Error: Invalid value.')

    ##
    # @brief get string.
    # @return hex or amount.
    def __str__(self) -> str:
        return str(self.amount) if self.amount != 0 else self.hex

    ##
    # @brief get blind state.
    # @retval True      blinded.
    # @retval False     unblind.
    def has_blind(self) -> bool:
        return (len(self.hex) == 66)

    ##
    # @brief get commitment. (can use unblind only)
    # @param[in] asset_commitment   asset commitment
    # @param[in] blind_factor       amount blind factor
    # @return amount commitment
    def get_commitment(self, asset_commitment,
                       blind_factor) -> 'ConfidentialValue':
        if self.has_blind():
            raise CfdError(
                error_code=1, message='Error: Blind value.')
        if isinstance(asset_commitment, ConfidentialAsset) and (
                asset_commitment.has_blind() is False):
            raise CfdError(
                error_code=1, message='Error: Unblind asset.')
        util = get_util()
        with util.create_handle() as handle:
            commitment = util.call_func(
                'CfdGetValueCommitment', handle.get_handle(),
                self.amount, to_hex_string(asset_commitment),
                to_hex_string(blind_factor))
            return ConfidentialValue(commitment)


##
# @class ElementsUtxoData
# @brief elements utxo class.
class ElementsUtxoData(UtxoData):
    ##
    # @var outpoint
    # outpoint (for UtxoData class)
    outpoint: 'OutPoint'
    ##
    # @var amount
    # amount (for UtxoData class)
    amount: int
    ##
    # @var value
    # value
    value: 'ConfidentialValue'
    ##
    # @var asset
    # asset
    asset: 'ConfidentialAsset'
    ##
    # @var is_issuance
    # is issuance
    is_issuance: bool
    ##
    # @var is_blind_issuance
    # is blinded issuance
    is_blind_issuance: bool
    ##
    # @var is_pegin
    # is pegin
    is_pegin: bool
    ##
    # @var pegin_btc_tx_size
    # pegin btc transaction size
    pegin_btc_tx_size: int
    ##
    # @var fedpeg_script
    # fedpeg script
    fedpeg_script: 'Script'
    ##
    # @var asset_blinder
    # asset blind factor
    asset_blinder: 'BlindFactor'
    ##
    # @var amount_blinder
    # amount blind factor
    amount_blinder: 'BlindFactor'

    ##
    # @brief constructor.
    # @param[in] outpoint               outpoint
    # @param[in] txid                   txid
    # @param[in] vout                   vout
    # @param[in] amount                 amount
    # @param[in] descriptor             descriptor
    # @param[in] scriptsig_template     scriptsig template
    # @param[in] value                  value
    # @param[in] asset                  asset
    # @param[in] is_issuance            issuance flag
    # @param[in] is_blind_issuance      blinded issuance flag
    # @param[in] is_pegin               pegin flag
    # @param[in] pegin_btc_tx_size      pegin btc tx size
    # @param[in] fedpeg_script          fedpeg script
    # @param[in] asset_blinder          asset blind factor
    # @param[in] amount_blinder         amount blind factor
    def __init__(
            self, outpoint: Optional['OutPoint'] = None,
            txid='', vout: int = 0, amount: int = 0,
            descriptor: Union[str, 'Descriptor'] = '',
            scriptsig_template='',
            value='', asset='',
            is_issuance: bool = False, is_blind_issuance: bool = False,
            is_pegin: bool = False,
            pegin_btc_tx_size: int = 0, fedpeg_script='',
            asset_blinder='', amount_blinder=''):
        super().__init__(
            outpoint=outpoint, txid=txid, vout=vout,
            amount=amount, descriptor=descriptor,
            scriptsig_template=scriptsig_template)
        self.value = ConfidentialValue.create(value, amount)
        self.asset = ConfidentialAsset(asset)
        self.is_issuance = is_issuance
        self.is_blind_issuance = is_blind_issuance
        self.is_pegin = is_pegin
        self.pegin_btc_tx_size = int(pegin_btc_tx_size)
        self.fedpeg_script = Script(fedpeg_script)
        self.asset_blinder = BlindFactor.create(asset_blinder)
        self.amount_blinder = BlindFactor.create(amount_blinder)
        if self.amount == 0:
            self.amount = self.value.amount

    ##
    # @brief equal method.
    # @param[in] other      other object.
    # @return true or false.
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ElementsUtxoData):
            return NotImplemented
        return self.outpoint == other.outpoint

    ##
    # @brief diff method.
    # @param[in] other      other object.
    # @return true or false.
    def __lt__(self, other: 'ElementsUtxoData') -> bool:
        if not isinstance(other, ElementsUtxoData):
            return NotImplemented
        return (self.outpoint) < (other.outpoint)

    ##
    # @brief equal method.
    # @param[in] other      other object.
    # @return true or false.
    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    ##
    # @brief diff method.
    # @param[in] other      other object.
    # @return true or false.
    def __le__(self, other: 'ElementsUtxoData') -> bool:
        return self.__lt__(other) or self.__eq__(other)

    ##
    # @brief diff method.
    # @param[in] other      other object.
    # @return true or false.
    def __gt__(self, other: 'ElementsUtxoData') -> bool:
        return not self.__le__(other)

    ##
    # @brief diff method.
    # @param[in] other      other object.
    # @return true or false.
    def __ge__(self, other: 'ElementsUtxoData') -> bool:
        return not self.__lt__(other)


##
# @class UnblindData
# @brief unblind data class.
class UnblindData:
    ##
    # @var asset
    # asset
    asset: Union[str, 'ConfidentialAsset']
    ##
    # @var value
    # value
    value: 'ConfidentialValue'
    ##
    # @var asset_blinder
    # asset blind factor
    asset_blinder: 'BlindFactor'
    ##
    # @var amount_blinder
    # amount blind factor
    amount_blinder: 'BlindFactor'

    ##
    # @brief constructor.
    # @param[in] asset              asset
    # @param[in] amount             amount
    # @param[in] asset_blinder      asset blind factor
    # @param[in] amount_blinder     amount blind factor
    def __init__(self, asset, amount: int,
                 asset_blinder, amount_blinder):
        self.asset = asset
        self.value = ConfidentialValue(amount)
        self.asset_blinder = BlindFactor(asset_blinder)
        self.amount_blinder = BlindFactor(amount_blinder)

    ##
    # @brief get string.
    # @return hex
    def __str__(self) -> str:
        return '{},{}'.format(self.asset, self.value)


##
# @class BlindData
# @brief blind data class.
class BlindData(UnblindData):
    ##
    # @var vout
    # txout array index
    vout: int
    ##
    # @var is_issuance
    # issuance flag
    is_issuance: bool

    ##
    # @brief constructor.
    # @param[in] vout               txout array index
    # @param[in] asset              asset
    # @param[in] amount             amount
    # @param[in] asset_blinder      asset blind factor
    # @param[in] amount_blinder     amount blind factor
    def __init__(self, vout: int, asset, amount: int,
                 asset_blinder, amount_blinder):
        super().__init__(asset, amount, asset_blinder, amount_blinder)
        self.vout = vout
        self.is_issuance = False


##
# @class IssuanceAssetBlindData
# @brief issuance asset blind data class.
class IssuanceAssetBlindData(BlindData):
    ##
    # @var outpoint
    # issuance outpoint
    outpoint: 'OutPoint'
    ##
    # @var is_issuance
    # issuance flag
    is_issuance: bool

    ##
    # @brief constructor.
    # @param[in] outpoint           txin outpoint
    # @param[in] vout               txin array index
    # @param[in] asset              asset
    # @param[in] amount             amount
    # @param[in] amount_blinder     amount blind factor
    def __init__(self, outpoint: OutPoint, vout: int, asset,
                 amount: int, amount_blinder):
        super().__init__(vout, asset, amount, EMPTY_BLINDER, amount_blinder)
        self.outpoint = outpoint
        self.is_issuance = True


##
# @class IssuanceTokenBlindData
# @brief issuance token blind data class.
class IssuanceTokenBlindData(BlindData):
    ##
    # @var outpoint
    # issuance outpoint
    outpoint: 'OutPoint'
    ##
    # @var is_issuance
    # issuance flag
    is_issuance: bool

    ##
    # @brief constructor.
    # @param[in] outpoint           txin outpoint
    # @param[in] vout               txin array index
    # @param[in] asset              asset
    # @param[in] amount             amount
    # @param[in] amount_blinder     amount blind factor
    def __init__(self, outpoint: OutPoint, vout: int, asset,
                 amount: int, amount_blinder):
        super().__init__(vout, asset, amount, EMPTY_BLINDER, amount_blinder)
        self.outpoint = outpoint
        self.is_issuance = True


##
# @class Issuance
# @brief Issuance data class.
class Issuance:
    ##
    # @var entropy
    # entropy
    entropy: 'BlindFactor'
    ##
    # @var nonce
    # nonce
    nonce: 'BlindFactor'
    ##
    # @var asset_value
    # asset value
    asset_value: 'ConfidentialValue'
    ##
    # @var token_value
    # token value
    token_value: 'ConfidentialValue'

    ##
    # @brief constructor.
    # @param[in] entropy          entropy
    # @param[in] nonce            nonce
    # @param[in] asset_value      asset amount
    # @param[in] token_value      token amount
    def __init__(self, entropy='', nonce='',
                 asset_value: int = 0, token_value: int = 0):
        self.entropy = BlindFactor.create(entropy)
        self.nonce = BlindFactor.create(nonce)
        self.asset_value = ConfidentialValue(asset_value)
        self.token_value = ConfidentialValue(token_value)

    ##
    # @brief get string.
    # @return hex
    def __str__(self) -> str:
        return '{},{},{}'.format(
            str(self.entropy), self.asset_value, self.token_value)


##
# @class IssuanceKeyPair
# @brief Issuance blinding key pair class.
class IssuanceKeyPair:
    ##
    # @var asset_key
    # asset blinding key
    asset_key: Optional['Privkey']
    ##
    # @var token_key
    # token blinding key
    token_key: Optional['Privkey']

    ##
    # @brief constructor.
    # @param[in] asset_key  asset blinding key
    # @param[in] token_key  token blinding key
    def __init__(self, asset_key='', token_key=''):
        self.asset_key = Privkey.from_hex_ignore_error(asset_key)
        self.token_key = Privkey.from_hex_ignore_error(token_key)

    ##
    # @brief get string.
    # @return hex
    def __str__(self) -> str:
        return 'IssuanceKeyPair'


##
# @class ConfidentialTxIn
# @brief elements transaction input class.
class ConfidentialTxIn(TxIn):
    ##
    # @var pegin_witness_stack
    # pegin witness stack
    pegin_witness_stack: List[Union['ByteData', 'Script']]
    ##
    # @var issuance
    # issuance
    issuance: 'Issuance'

    ##
    # @brief constructor.
    # @param[in] outpoint   outpoint
    # @param[in] txid       txid
    # @param[in] vout       vout
    # @param[in] sequence   sequence
    def __init__(self, outpoint: Optional['OutPoint'] = None,
                 txid='', vout: int = 0,
                 sequence: int = TxIn.SEQUENCE_DISABLE):
        super().__init__(outpoint, txid, vout, sequence)
        self.pegin_witness_stack = []
        self.issuance = Issuance()


##
# @class ConfidentialTxOut
# @brief elements transaction output class.
class ConfidentialTxOut(TxOut):
    ##
    # @var value
    # value
    value: 'ConfidentialValue'
    ##
    # @var asset
    # asset
    asset: 'ConfidentialAsset'
    ##
    # @var nonce
    # nonce
    nonce: 'ConfidentialNonce'
    ##
    # @var surjectionproof
    # surjection proof
    surjectionproof: Union[List[int], str, 'ByteData']
    ##
    # @var rangeproof
    # range proof
    rangeproof: Union[List[int], str, 'ByteData']

    ##
    # @brief get destroy amount txout.
    # @param[in] amount     amount
    # @param[in] asset      asset
    # @param[in] nonce      nonce
    # @return ConfidentialTxOut
    @classmethod
    def for_destroy_amount(
            cls, amount: int, asset, nonce='') -> 'ConfidentialTxOut':
        return ConfidentialTxOut(amount, asset=asset, nonce=nonce,
                                 locking_script='6a')

    ##
    # @brief get fee txout.
    # @param[in] amount     amount
    # @param[in] asset      asset
    # @return ConfidentialTxOut
    @classmethod
    def for_fee(cls, amount: int, asset) -> 'ConfidentialTxOut':
        return ConfidentialTxOut(amount, asset=asset)

    ##
    # @brief create instance.
    # @param[in] amount             amount
    # @param[in] address            address or confidential address
    # @param[in] locking_script     locking script
    # @param[in] value              value
    # @param[in] asset              asset
    # @param[in] nonce              nonce
    # @return ConfidentialTxOut
    @classmethod
    def new(cls, amount=0, address='', locking_script='',
            value='', asset='', nonce='') -> 'ConfidentialTxOut':
        _nonce = nonce
        _addr = address
        if ConfidentialAddress.valid(_addr):
            _ca = ConfidentialAddress.parse(_addr)
            _addr = _ca.address
            _nonce = _ca.confidential_key
        return ConfidentialTxOut(
            amount, address=_addr, locking_script=locking_script,
            value=value, asset=asset, nonce=_nonce)

    ##
    # @brief constructor.
    # @param[in] amount             amount
    # @param[in] address            address
    # @param[in] locking_script     locking script
    # @param[in] value              value
    # @param[in] asset              asset
    # @param[in] nonce              nonce
    def __init__(
            self, amount=0, address='', locking_script='',
            value='', asset='', nonce=''):
        super().__init__(
            amount=amount, address=address, locking_script=locking_script)
        self.value = ConfidentialValue.create(value, amount)
        self.asset = ConfidentialAsset(asset)
        self.nonce = ConfidentialNonce(nonce)
        self.surjectionproof = []
        self.rangeproof = []

    ##
    # @brief check fee.
    # @retval true   fee txout.
    # @retval false  other.
    def is_fee(self):
        return str(self.locking_script) == ''

    ##
    # @brief get blind state.
    # @retval True      blinded.
    # @retval False     unblind.
    def has_blind(self):
        return self.value.has_blind()

    ##
    # @brief constructor.
    # @param[in] network   network
    # @param[in] is_confidential  Returns Confidential Address if possible.
    # @return address.
    def _get_address(self, network=Network.LIQUID_V1,
                     is_confidential: bool = False,
                     ) -> Union['Address', 'ConfidentialAddress', None]:
        _network = Network.get(network)
        if _network not in [Network.LIQUID_V1, Network.ELEMENTS_REGTEST]:
            raise CfdError(error_code=1,
                           message='Error: Invalid network type.')
        if isinstance(self.address, ConfidentialAddress):
            return self.address if is_confidential else self.address.address
        addr = self.address if isinstance(self.address, Address) else None
        if (addr is None) and (self.address != ''):
            if ConfidentialAddress.valid(self.address):
                ca = ConfidentialAddress.parse(self.address)
                return ca if is_confidential else ca.address
            addr = AddressUtil.parse(self.address)
        if (addr is None) and ((is_confidential is False) or (
                len(self.locking_script.hex) > 0)):
            addr = AddressUtil.from_locking_script(
                self.locking_script, _network)

        if self.has_blind() or self.nonce.is_empty() or (
                not is_confidential) or (addr is None):
            return addr
        else:
            return ConfidentialAddress(addr, Pubkey(self.nonce))

    ##
    # @brief get address.
    # @param[in] network   network
    # @return address.
    def get_address(self, network=Network.LIQUID_V1) -> 'Address':
        ret = self._get_address(network, False)
        if isinstance(ret, Address):
            return ret
        raise CfdError(error_code=-2, message='Error: Internal error.')

    ##
    # @brief get confidential address.
    # @param[in] network   network
    # @return address.
    def get_confidential_address(
            self,
            network=Network.LIQUID_V1) -> Optional['ConfidentialAddress']:
        addr = self._get_address(network, True)
        return addr if isinstance(addr, ConfidentialAddress) else None


##
# @class TargetAmountData
# @brief target amount data for fund transaction.
class TargetAmountData:
    ##
    # @var amount
    # amount
    amount: int
    ##
    # @var asset
    # asset
    asset: ConfidentialAsset
    ##
    # @var reserved_address
    # reserved address
    reserved_address: Union[str, 'Address', 'ConfidentialAddress']

    ##
    # @brief constructor.
    # @param[in] amount             amount
    # @param[in] asset              asset
    # @param[in] reserved_address   reserved address
    def __init__(self,
                 amount: int,
                 asset,
                 reserved_address: Union[str,
                                         'Address',
                                         'ConfidentialAddress'] = ''):
        self.amount = amount
        self.asset = ConfidentialAsset(asset)
        if isinstance(reserved_address, Address) or \
                isinstance(reserved_address, ConfidentialAddress):
            self.reserved_address = reserved_address
        else:
            self.reserved_address = str(reserved_address)


##
# @class ConfidentialTransaction
# @brief elements transaction.
class ConfidentialTransaction(_TransactionBase):
    ##
    # @var hex
    # transaction hex string
    hex: str
    ##
    # @var txin_list
    # transaction input list
    txin_list: List['ConfidentialTxIn']
    ##
    # @var txout_list
    # transaction output list
    txout_list: List['ConfidentialTxOut']
    ##
    # @var txid
    # txid
    txid: 'Txid'
    ##
    # @var wtxid
    # wtxid
    wtxid: 'Txid'
    ##
    # @var wit_hash
    # wit_hash
    wit_hash: str
    ##
    # @var size
    # transaction size
    size: int
    ##
    # @var vsize
    # transaction vsize
    vsize: int
    ##
    # @var weight
    # transaction size weight
    weight: int
    ##
    # @var version
    # version
    version: int
    ##
    # @var locktime
    # locktime
    locktime: int

    ##
    # bitcoin network value.
    NETWORK: int = Network.LIQUID_V1.value
    ##
    # blind minimumBits on default.
    DEFAULT_BLIND_MINIMUM_BITS: int = 52
    ##
    # transaction's free function name.
    FREE_FUNC_NAME = 'CfdFreeTransactionHandle'

    ##
    # @brief parse transaction to json.
    # @param[in] hex        transaction hex
    # @param[in] network    network
    # @param[in] full_dump  full_dump flag
    # @return json string
    @classmethod
    def parse_to_json(cls, hex: str, network=Network.LIQUID_V1,
                      full_dump: bool = False) -> str:
        _network = Network.get(network)
        mainchain_str = 'mainnet'
        network_str = 'liquidv1'
        if _network != Network.LIQUID_V1:
            mainchain_str = 'regtest'
            network_str = 'regtest'
        full_dump_str = 'true' if full_dump else 'false'
        cmd = '{{"hex":"{}","network":"{}","{}":"{}","fullDump":{}}}'
        request_json = cmd.format(
            hex, network_str, 'mainchainNetwork', mainchain_str,
            full_dump_str)
        util = get_util()
        with util.create_handle() as handle:
            return util.call_func(
                'CfdRequestExecuteJson', handle.get_handle(),
                'ElementsDecodeRawTransaction', request_json)

    ##
    # @brief get blinding key for elemens default.
    # @param[in] master_blinding_key    master blinding key
    # @param[in] locking_script         locking script
    # @return blinding key
    @classmethod
    def get_default_blinding_key(
            cls, master_blinding_key, locking_script) -> 'Privkey':
        _key = to_hex_string(master_blinding_key)
        _script = to_hex_string(locking_script)
        util = get_util()
        with util.create_handle() as handle:
            key = util.call_func(
                'CfdGetDefaultBlindingKey', handle.get_handle(),
                _key, _script)
            return Privkey(hex=key)

    ##
    # @brief get issuance blinding key for elemens default.
    # @param[in] master_blinding_key    master blinding key
    # @param[in] txid                   txid
    # @param[in] vout                   vout
    # @return blinding key
    @classmethod
    def get_issuance_blinding_key(
            cls, master_blinding_key, txid, vout: int) -> 'Privkey':
        _key = to_hex_string(master_blinding_key)
        _txid = to_hex_string(txid)
        util = get_util()
        with util.create_handle() as handle:
            key = util.call_func(
                'CfdGetIssuanceBlindingKey', handle.get_handle(),
                _key, _txid, vout)
            return Privkey(hex=key)

    ##
    # @brief create transaction.
    # @param[in] version        version
    # @param[in] locktime       locktime
    # @param[in] txins          txin list
    # @param[in] txouts         txout list
    # @param[in] enable_cache   enable tx cache
    # @return transaction object
    @classmethod
    def create(cls, version: int, locktime: int,
               txins: List[Union['ConfidentialTxIn', 'TxIn']] = [],
               txouts: List['ConfidentialTxOut'] = [],
               enable_cache: bool = True) -> 'ConfidentialTransaction':
        util = get_util()
        with util.create_handle() as handle:
            _tx_handle = util.call_func(
                'CfdInitializeTransaction', handle.get_handle(),
                cls.NETWORK, version, locktime, '')
            with JobHandle(
                    handle, _tx_handle, cls.FREE_FUNC_NAME) as tx_handle:
                for txin in txins:
                    sec = TxIn.get_sequence_number(locktime, txin.sequence)
                    util.call_func(
                        'CfdAddTransactionInput', handle.get_handle(),
                        tx_handle.get_handle(), str(txin.outpoint.txid),
                        txin.outpoint.vout, sec)
                for txout in txouts:
                    util.call_func(
                        'CfdAddConfidentialTxOutput', handle.get_handle(),
                        tx_handle.get_handle(), txout.amount,
                        str(txout.address),
                        str(txout.locking_script),
                        str(txout.asset), str(txout.nonce))
                hex = util.call_func(
                    'CfdFinalizeTransaction', handle.get_handle(),
                    tx_handle.get_handle())
        return ConfidentialTransaction(hex, enable_cache)

    ##
    # @brief get transaction from hex.
    # @param[in] hex            tx hex
    # @param[in] enable_cache   enable tx cache
    # @return transaction object
    @classmethod
    def from_hex(
            cls,
            hex,
            enable_cache: bool = True) -> 'ConfidentialTransaction':
        return ConfidentialTransaction(hex, enable_cache)

    ##
    # @brief constructor.
    # @param[in] hex            tx hex
    # @param[in] enable_cache   enable tx cache
    def __init__(self, hex, enable_cache: bool = True):
        super().__init__(hex, self.NETWORK, enable_cache)
        self.txin_list = []
        self.txout_list = []
        self._update_tx_all()

    ##
    # @brief get transaction input.
    # @param[in] handle     cfd handle
    # @param[in] tx_handle  tx handle
    # @param[in] index      index
    # @param[in] outpoint   outpoint
    # @retval [0] txin
    # @retval [1] index
    def _get_txin(self, handle, tx_handle, index=0,
                  outpoint: Optional['OutPoint'] = None,
                  ) -> typing.Tuple['ConfidentialTxIn', int]:
        util = get_util()

        if isinstance(outpoint, OutPoint):
            index = util.call_func(
                'CfdGetTxInIndexByHandle', handle.get_handle(),
                tx_handle.get_handle(), str(outpoint.txid),
                outpoint.vout)

        txid, vout, seq, script = util.call_func(
            'CfdGetTxInByHandle', handle.get_handle(),
            tx_handle.get_handle(), index)
        txin = ConfidentialTxIn(txid=txid, vout=vout, sequence=seq)
        txin.script_sig = script

        txin.witness_stack = []
        _count = util.call_func(
            'CfdGetTxInWitnessCountByHandle', handle.get_handle(),
            tx_handle.get_handle(), 0, index)
        for i in range(_count):
            data = util.call_func(
                'CfdGetTxInWitnessByHandle', handle.get_handle(),
                tx_handle.get_handle(), 0, index, i)
            txin.witness_stack.append(data)

        entropy, nonce, asset_amount, asset_value, token_amount,\
            toke_value, _, _ = util.call_func(
                'CfdGetTxInIssuanceInfoByHandle',
                handle.get_handle(), tx_handle.get_handle(), index)
        txin.issuance.entropy = entropy
        txin.issuance.nonce = nonce
        txin.issuance.asset_value = ConfidentialValue.create(
            asset_value, asset_amount)
        txin.issuance.token_value = ConfidentialValue.create(
            toke_value, token_amount)

        txin.pegin_witness_stack = []
        _count = util.call_func(
            'CfdGetTxInWitnessCountByHandle', handle.get_handle(),
            tx_handle.get_handle(), 1, index)
        for i in range(_count):
            data = util.call_func(
                'CfdGetTxInWitnessByHandle', handle.get_handle(),
                tx_handle.get_handle(), 1, index, i)
            txin.pegin_witness_stack.append(data)
        return txin, index

    ##
    # @brief update transaction information.
    # @return void
    def _update_info(self) -> None:
        if self.enable_cache is False:
            return
        util = get_util()
        with util.create_handle() as handle:
            ret = util.call_func(
                'CfdGetConfidentialTxInfo', handle.get_handle(), self.hex)
            # for doxygen
            self.txid = Txid(ret[0])
            self.wtxid = Txid(ret[1])
            self.wit_hash = ret[2]
            self.size = ret[3]
            self.vsize = ret[4]
            self.weight = ret[5]
            self.version = ret[6]
            self.locktime = ret[7]

    ##
    # @brief update transaction input.
    # @param[in] outpoint       outpoint
    # @param[in] handle         cfd handle
    # @param[in] tx_handle      tx handle
    # @return void
    def _update_txin_internal(self, handle, tx_handle, outpoint: 'OutPoint'):
        if self.enable_cache is False:
            return
        util = get_util()
        self.txid, self.wtxid, self.wit_hash, self.size, self.vsize,\
            self.weight, self.version, self.locktime = util.call_func(
                'CfdGetConfidentialTxInfoByHandle',
                handle.get_handle(), tx_handle.get_handle())
        self.txid = Txid(self.txid)
        self.wtxid = Txid(self.wtxid)
        # update txin
        txin, index = self._get_txin(
            handle, tx_handle, outpoint=outpoint)
        self.txin_list[index] = txin

    ##
    # @brief update transaction input.
    # @param[in] outpoint       outpoint
    # @return void
    def _update_txin(self, outpoint: 'OutPoint'):
        if self.enable_cache is False:
            return
        util = get_util()
        with util.create_handle() as handle, super()._get_handle(
                handle, self.network) as tx_handle:
            self._update_txin_internal(handle, tx_handle, outpoint)

    ##
    # @brief get transaction all data.
    # @retval [0]   txin list
    # @retval [1]   txout list
    def get_tx_all(self) -> typing.Tuple[
            List['ConfidentialTxIn'], List['ConfidentialTxOut']]:
        def get_txin_list(handle, tx_handle):
            txin_list = []
            _count = util.call_func(
                'CfdGetTxInCountByHandle', handle.get_handle(),
                tx_handle.get_handle())
            for i in range(_count):
                txin, _ = self._get_txin(handle, tx_handle, i)
                txin_list.append(txin)
            return txin_list

        def get_txout_list(handle, tx_handle):
            txout_list = []
            _count = util.call_func(
                'CfdGetTxOutCountByHandle', handle.get_handle(),
                tx_handle.get_handle())
            for i in range(_count):
                # CfdGetConfidentialTxOutByHandle
                asset, amount, value_commitment, nonce,\
                    script = util.call_func(
                        'CfdGetConfidentialTxOutSimpleByHandle',
                        handle.get_handle(), tx_handle.get_handle(), i)
                txout = ConfidentialTxOut(
                    amount=amount, locking_script=script,
                    asset=asset, value=value_commitment, nonce=nonce)
                txout_list.append(txout)
            return txout_list

        util = get_util()
        with util.create_handle() as handle, super()._get_handle(
                handle, self.network) as tx_handle:
            self.txid, self.wtxid, self.wit_hash, self.size, self.vsize,\
                self.weight, self.version, self.locktime = util.call_func(
                    'CfdGetConfidentialTxInfoByHandle',
                    handle.get_handle(), tx_handle.get_handle())
            self.txid = Txid(self.txid)
            self.wtxid = Txid(self.wtxid)
            self.txin_list = get_txin_list(handle, tx_handle)
            self.txout_list = get_txout_list(handle, tx_handle)
            return self.txin_list, self.txout_list

    ##
    # @brief get transaction output fee index.
    # @return index
    def get_txout_fee_index(self) -> int:
        return self.get_txout_index()

    ##
    # @brief add transaction input.
    # @param[in] outpoint   outpoint
    # @param[in] sequence   sequence
    # @param[in] txid       txid
    # @param[in] vout       vout
    # @return void
    def add_txin(self, outpoint: Optional['OutPoint'] = None,
                 sequence: int = -1, txid='', vout: int = 0) -> None:
        sec = TxIn.get_sequence_number(self.locktime, sequence)
        txin = ConfidentialTxIn(
            outpoint=outpoint, sequence=sec, txid=txid, vout=vout)
        self.add([txin], [])

    ##
    # @brief add transaction output.
    # @param[in] amount             amount
    # @param[in] address            address
    # @param[in] locking_script     locking script
    # @param[in] value              value
    # @param[in] asset              asset
    # @param[in] nonce              nonce
    # @return void
    def add_txout(self, amount: int = 0, address='',
                  locking_script='', value='', asset='', nonce='') -> None:
        txout = ConfidentialTxOut(
            amount, address, locking_script, value, asset, nonce)
        self.add([], [txout])

    ##
    # @brief add transaction fee output.
    # @param[in] amount             amount
    # @param[in] asset              asset
    # @return void
    def add_fee_txout(self, amount: int, asset) -> None:
        self.add_txout(amount, asset=asset)

    ##
    # @brief add transaction destroy amount output.
    # @param[in] amount     amount
    # @param[in] asset      asset
    # @param[in] nonce      nonce
    # @return void
    def add_destroy_amount_txout(
            self, amount: int, asset, nonce='') -> None:
        self.add_txout(amount, locking_script='6a', asset=asset, nonce=nonce)

    ##
    # @brief add transaction.
    # @param[in] txins          txin list
    # @param[in] txouts         txout list
    # @return void
    def add(self, txins: List['ConfidentialTxIn'],
            txouts: List['ConfidentialTxOut']) -> None:
        util = get_util()
        with util.create_handle() as handle, super()._get_handle(
                handle, self.network) as tx_handle:
            for txin in txins:
                sec = TxIn.get_sequence_number(
                    self.locktime, txin.sequence)
                util.call_func(
                    'CfdAddTransactionInput', handle.get_handle(),
                    tx_handle.get_handle(), str(txin.outpoint.txid),
                    txin.outpoint.vout, sec)
            for txout in txouts:
                util.call_func(
                    'CfdAddConfidentialTxOutput',
                    handle.get_handle(),
                    tx_handle.get_handle(), txout.amount,
                    str(txout.address),
                    str(txout.locking_script),
                    str(txout.asset), str(txout.nonce))
            self.hex = util.call_func(
                'CfdFinalizeTransaction', handle.get_handle(),
                tx_handle.get_handle())
            self.txid, self.wtxid, self.wit_hash, self.size, self.vsize,\
                self.weight, self.version, self.locktime = util.call_func(
                    'CfdGetConfidentialTxInfoByHandle',
                    handle.get_handle(), tx_handle.get_handle())
            self.txid = Txid(self.txid)
            self.wtxid = Txid(self.wtxid)
            self.txin_list += copy.deepcopy(txins)
            self.txout_list += copy.deepcopy(txouts)

    ##
    # @brief add pegin input.
    # @param[in] outpoint           mainchain utxo outpoint
    # @param[in] amount             amount (satoshi)
    # @param[in] asset              asset
    # @param[in] mainchain_genesis_block_hash   genesis block hash
    # @param[in] claim_script       claim script
    # @param[in] mainchain_tx       mainchain transaction
    # @param[in] txout_proof        utxo txout proof
    # @param[in] txid               mainchain outpoint txid
    # @param[in] vout               mainchain outpoint vout
    # @return void
    def add_pegin_input(self, outpoint: Optional['OutPoint'],
                        amount: int,
                        asset: Union['ConfidentialAsset', str],
                        mainchain_genesis_block_hash: Union['BlockHash', str],
                        claim_script: Union['Script', str],
                        mainchain_tx: Union['Transaction', 'ByteData', str],
                        txout_proof: Union['ByteData', str],
                        txid='', vout: int = 0):
        util = get_util()
        _txid = txid
        _vout = vout
        if outpoint:
            _txid = outpoint.txid
            _vout = outpoint.vout
        with util.create_handle() as handle, self._get_handle(
                handle, self.network) as tx_handle:
            util.call_func(
                'CfdAddTxPeginInput', handle.get_handle(),
                tx_handle.get_handle(), to_hex_string(_txid), _vout,
                amount, to_hex_string(asset),
                to_hex_string(mainchain_genesis_block_hash),
                to_hex_string(claim_script), to_hex_string(mainchain_tx),
                to_hex_string(txout_proof))
            self.hex = util.call_func(
                'CfdFinalizeTransaction', handle.get_handle(),
                tx_handle.get_handle())
        self._update_tx_all()

    ##
    # @brief update pegin witness stack.
    # @param[in] outpoint       outpoint
    # @param[in] stack_index    witness stack index.
    # @param[in] data           stack data
    # @return void
    def update_pegin_witness_stack(
            self, outpoint: 'OutPoint', stack_index: int, data) -> None:
        _data = to_hex_string(data)
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                handle, self.network) as tx_handle:
            self.hex = util.call_func(
                'CfdUpdateWitnessStack', handle.get_handle(),
                tx_handle.get_handle(), 1, str(outpoint.txid),
                outpoint.vout, stack_index, _data)
            self.hex = util.call_func(
                'CfdFinalizeTransaction', handle.get_handle(),
                tx_handle.get_handle())
            self._update_txin_internal(handle, tx_handle, outpoint)

    ##
    # @brief add pegout output.
    # @param[in] asset              asset
    # @param[in] amount             amount (satoshi)
    # @param[in] mainchain_network_type     mainchain network type
    # @param[in] elements_network_type      elements network type
    # @param[in] mainchain_genesis_block_hash   genesis block hash
    # @param[in] online_pubkey      online pubkey
    # @param[in] master_online_key  online privkey
    # @param[in] mainchain_output_descriptor    mainchain address descriptor
    # @param[in] bip32_counter                  address descriptor counter
    # @param[in] whitelist                      pegout whitelist
    # @return mainchain address
    def add_pegout_output(
            self,
            asset: Union['ConfidentialAsset', str],
            amount: int,
            mainchain_network_type,
            elements_network_type,
            mainchain_genesis_block_hash: Union['BlockHash', str],
            online_pubkey: Union['Pubkey', str],
            master_online_key: Union['Privkey', str],
            mainchain_output_descriptor: Union['Descriptor', str],
            bip32_counter: int,
            whitelist: Union['ByteData', str]) -> 'Address':
        util = get_util()
        mainchain_nw = Network.get(mainchain_network_type)
        elements_nw = Network.get(elements_network_type)
        if isinstance(mainchain_output_descriptor, Descriptor):
            addr_type = mainchain_output_descriptor.data.hash_type
        else:
            desc = parse_descriptor(mainchain_output_descriptor,
                                    mainchain_nw, path=str(bip32_counter))
            addr_type = desc.data.hash_type
        with util.create_handle() as handle, self._get_handle(
                handle, self.network) as tx_handle:
            addr = util.call_func(
                'CfdAddTxPegoutOutput', handle.get_handle(),
                tx_handle.get_handle(), to_hex_string(asset), amount,
                mainchain_nw.value, elements_nw.value,
                to_hex_string(mainchain_genesis_block_hash),
                to_hex_string(online_pubkey), str(master_online_key),
                str(mainchain_output_descriptor), bip32_counter,
                to_hex_string(whitelist))
            self.hex = util.call_func(
                'CfdFinalizeTransaction', handle.get_handle(),
                tx_handle.get_handle())
        self._update_tx_all()
        return AddressUtil.parse(addr, hash_type=addr_type)

    ##
    # @brief update transaction output amount.
    # @param[in] index      index
    # @param[in] amount     amount
    # @return void
    def update_txout_amount(self, index: int, amount: int) -> None:
        util = get_util()
        with util.create_handle() as handle:
            self.hex = util.call_func(
                'CfdUpdateTxOutAmount', handle.get_handle(),
                self.NETWORK, self.hex, index, amount)
            self._update_info()
            self.txout_list[index].amount = amount

    ##
    # @brief update transaction output fee amount.
    # @param[in] amount     amount
    # @return void
    def update_txout_fee_amount(self, amount: int) -> None:
        index = self.get_txout_index()
        self.update_txout_amount(index, amount)

    ##
    # @brief split transaction output.
    # @param[in] index              target txout index
    # @param[in] txout_list         append split data list
    # @return void
    def split_txout(self, index: int, txout_list: List['ConfidentialTxOut']):
        util = get_util()

        def get_split_handle(handle, tx_handle) -> 'JobHandle':
            work_handle = util.call_func(
                'CfdCreateSplitTxOutHandle', handle.get_handle(),
                tx_handle.get_handle())
            return JobHandle(handle, work_handle, 'CfdFreeSplitTxOutHandle')

        with util.create_handle() as handle, self._get_handle(
                handle, self.network) as tx_handle, get_split_handle(
                    handle, tx_handle) as split_handle:
            for txout in txout_list:
                _script = '' if txout.address else txout.locking_script
                util.call_func(
                    'CfdAddSplitTxOutData', handle.get_handle(),
                    split_handle.get_handle(), txout.amount,
                    str(txout.address), to_hex_string(_script),
                    str(txout.nonce))
            util.call_func(
                'CfdSplitTxOut', handle.get_handle(),
                tx_handle.get_handle(), split_handle.get_handle(), index)
            self.hex = util.call_func(
                'CfdFinalizeTransaction', handle.get_handle(),
                tx_handle.get_handle())
        self._update_tx_all()

    ##
    # @brief blind transaction output.
    # @param[in] utxo_list                      utxo list
    # @param[in] confidential_address_list      confidential address list
    # @param[in] direct_confidential_key_map    direct confidential key map
    # @param[in] minimum_range_value            minimum range value
    # @param[in] exponent                       exponent
    # @param[in] minimum_bits                   minimum bits
    # @param[in] collect_blinder                blinder collect flag.
    # @return blinder_list (if collect_blinder is true)
    def blind_txout(self, utxo_list: List['ElementsUtxoData'],
                    confidential_address_list=[],
                    direct_confidential_key_map={},
                    minimum_range_value: int = 1, exponent: int = 0,
                    minimum_bits: int = -1,
                    collect_blinder: bool = False) -> List['BlindData']:
        return self.blind(
            utxo_list=utxo_list,
            confidential_address_list=confidential_address_list,
            direct_confidential_key_map=direct_confidential_key_map,
            minimum_range_value=minimum_range_value,
            exponent=exponent, minimum_bits=minimum_bits,
            collect_blinder=collect_blinder)

    ##
    # @brief blind transaction output.
    # @param[in] utxo_list                      utxo list
    # @param[in] issuance_key_map               issuance key map
    # @param[in] confidential_address_list      confidential address list
    # @param[in] direct_confidential_key_map    direct confidential key map
    # @param[in] minimum_range_value            minimum range value
    # @param[in] exponent                       exponent
    # @param[in] minimum_bits                   minimum bits
    # @param[in] collect_blinder                blinder collect flag.
    # @return blinder_list (if collect_blinder is true)
    def blind(
        self, utxo_list: List['ElementsUtxoData'],
        issuance_key_map={},
        confidential_address_list=[],
        direct_confidential_key_map={},
        minimum_range_value: int = 1, exponent: int = 0,
        minimum_bits: int = -1, collect_blinder: bool = False,
    ) -> List[Union['BlindData', 'IssuanceAssetBlindData',
                    'IssuanceTokenBlindData']]:
        if minimum_bits == -1:
            minimum_bits = self.DEFAULT_BLIND_MINIMUM_BITS

        def set_opt(handle, tx_handle, key, i_val=0):
            val = i_val
            if isinstance(val, bool):
                val = 1 if val is True else 0
            util.call_func(
                'CfdSetBlindTxOption', handle.get_handle(),
                tx_handle.get_handle(), key.value, val)

        util = get_util()
        with util.create_handle() as handle:
            _tx_handle = util.call_func(
                'CfdInitializeBlindTx', handle.get_handle())
            with JobHandle(
                    handle, _tx_handle, 'CfdFreeBlindHandle') as tx_handle:
                issuance_count = 0
                for txin in utxo_list:
                    asset_key, token_key = '', ''
                    if str(txin.outpoint) in issuance_key_map:
                        item = issuance_key_map[str(txin.outpoint)]
                        asset_key = str(item.asset_key)
                        token_key = str(item.token_key)
                        issuance_count += 1
                    util.call_func(
                        'CfdAddBlindTxInData', handle.get_handle(),
                        tx_handle.get_handle(),
                        to_hex_string(txin.outpoint.txid),
                        txin.outpoint.vout, to_hex_string(txin.asset),
                        to_hex_string(txin.asset_blinder),
                        to_hex_string(txin.amount_blinder),
                        txin.amount, asset_key, token_key)
                if issuance_count != len(issuance_key_map):
                    raise CfdError(
                        error_code=1,
                        message='Error: Issuance Txid is not found.')
                for addr in confidential_address_list:
                    util.call_func(
                        'CfdAddBlindTxOutByAddress', handle.get_handle(),
                        tx_handle.get_handle(), str(addr))
                for key_index in direct_confidential_key_map.keys():
                    key = direct_confidential_key_map[key_index]
                    util.call_func(
                        'CfdAddBlindTxOutData', handle.get_handle(),
                        tx_handle.get_handle(), int(key_index),
                        to_hex_string(key))
                set_opt(handle, tx_handle,
                        _BlindOpt.MINIMUM_RANGE_VALUE, minimum_range_value)
                set_opt(handle, tx_handle, _BlindOpt.EXPONENT, exponent)
                set_opt(handle, tx_handle,
                        _BlindOpt.MINIMUM_BITS, minimum_bits)
                set_opt(handle, tx_handle, _BlindOpt.COLLECT_BLINDER,
                        bool(collect_blinder))
                self.hex = util.call_func(
                    'CfdFinalizeBlindTx', handle.get_handle(),
                    tx_handle.get_handle(), self.hex)
                self._update_tx_all()
                blinder_list: List[Union['BlindData', 'IssuanceAssetBlindData',
                                         'IssuanceTokenBlindData']] = []
                if bool(collect_blinder):
                    try:
                        i = 0
                        while True:
                            vout, asset, amount, asset_blinder,\
                                value_blinder, issuance_txid,\
                                issuance_vout, is_issue_asset,\
                                is_issue_token = util.call_func(
                                    'CfdGetBlindTxBlindData',
                                    handle.get_handle(),
                                    tx_handle.get_handle(), i)
                            if is_issue_asset:
                                blinder_list.append(IssuanceAssetBlindData(
                                    OutPoint(issuance_txid, issuance_vout),
                                    vout, asset, amount,
                                    value_blinder))
                            elif is_issue_token:
                                blinder_list.append(IssuanceTokenBlindData(
                                    OutPoint(issuance_txid, issuance_vout),
                                    vout, asset, amount, value_blinder))
                            else:
                                blinder_list.append(BlindData(
                                    vout, asset, amount,
                                    asset_blinder, value_blinder))
                            i += 1
                    except CfdError as err:
                        if err.error_code != CfdErrorCode.OUT_OF_RANGE.value:
                            raise err
                return blinder_list

    ##
    # @brief unblind transaction output.
    # @param[in] index          txout index
    # @param[in] blinding_key   blinding key
    # @return UnblindData
    def unblind_txout(self, index: int, blinding_key) -> 'UnblindData':
        util = get_util()
        with util.create_handle() as handle:
            asset, asset_amount, asset_blinder,\
                amount_blinder = util.call_func(
                    'CfdUnblindTxOut', handle.get_handle(),
                    self.hex, index, to_hex_string(blinding_key))
            return UnblindData(
                asset, asset_amount, asset_blinder, amount_blinder)

    ##
    # @brief unblind transaction issuance.
    # @param[in] index          txout index
    # @param[in] asset_key      asset blinding key
    # @param[in] token_key      token blinding key
    # @retval [0]   asset unblind data
    # @retval [1]   token unblind data
    def unblind_issuance(self, index: int, asset_key,
                         token_key='') -> Tuple['UnblindData', 'UnblindData']:
        util = get_util()
        with util.create_handle() as handle:
            asset, asset_amount, asset_blinder, amount_blinder, token,\
                token_amount, token_blinder,\
                token_amount_blinder = util.call_func(
                    'CfdUnblindIssuance', handle.get_handle(),
                    self.hex, index, to_hex_string(asset_key),
                    to_hex_string(token_key))
            asset_data = UnblindData(
                asset, asset_amount, asset_blinder, amount_blinder)
            token_data = UnblindData(
                token, token_amount, token_blinder, token_amount_blinder)
            return asset_data, token_data

    ##
    # @brief set issuance asset.
    # @param[in] outpoint           mainchain utxo outpoint
    # @param[in] asset_amount       issuance asset amount (satoshi)
    # @param[in] asset_address      sending asset address
    # @param[in] token_amount       issuance token amount (satoshi)
    # @param[in] token_address      sending token address
    # @param[in] is_blind_asset     use blind issuance asset
    # @param[in] contract_hash      contract hash (32-byte)
    # @param[in] asset_locking_script      sending asset by locking script
    # @param[in] token_locking_script      sending token by locking script
    # @param[in] txid               mainchain outpoint txid
    # @param[in] vout               mainchain outpoint vout
    # @retval [0] entropy
    # @retval [1] issuance asset
    # @retval [2] token asset
    def set_raw_issue_asset(
        self, outpoint: Optional['OutPoint'],
        asset_amount: Union[int, 'ConfidentialValue'],
        asset_address: Union['Address', 'ConfidentialAddress', str],
        token_amount: Union[int, 'ConfidentialValue'],
        token_address: Union['Address', 'ConfidentialAddress', str],
        is_blind_asset: bool = False,
        contract_hash: Union['ByteData', str] = '',
        asset_locking_script: Union['Script', str] = '',
        token_locking_script: Union['Script', str] = '',
        txid='', vout: int = 0,
    ) -> Tuple['BlindFactor', 'ConfidentialAsset', 'ConfidentialAsset']:
        util = get_util()
        _asset_amount = asset_amount
        if isinstance(asset_amount, ConfidentialValue):
            _asset_amount = asset_amount.amount
        _token_amount = token_amount
        if isinstance(token_amount, ConfidentialValue):
            _token_amount = token_amount.amount
        _txid = txid
        _vout = vout
        if outpoint:
            _txid = outpoint.txid
            _vout = outpoint.vout
        with util.create_handle() as handle, self._get_handle(
                handle, self.network) as tx_handle:
            entropy, asset, token = util.call_func(
                'CfdSetIssueAsset', handle.get_handle(),
                tx_handle.get_handle(), to_hex_string(_txid), _vout,
                to_hex_string(contract_hash), _asset_amount,
                str(asset_address), to_hex_string(asset_locking_script),
                _token_amount, str(token_address),
                to_hex_string(token_locking_script), is_blind_asset)
            self.hex = util.call_func(
                'CfdFinalizeTransaction', handle.get_handle(),
                tx_handle.get_handle())
            self._update_txin_internal(
                handle, tx_handle, OutPoint(_txid, _vout))
            return BlindFactor(entropy), ConfidentialAsset(
                asset), ConfidentialAsset(token)

    ##
    # @brief set reissue asset.
    # @param[in] utxo           utxo data
    # @param[in] amount         amount
    # @param[in] address        address
    # @param[in] entropy        entropy
    # @param[in] locking_script     direct locking_script
    # @return reissue asset
    def set_raw_reissue_asset(self, utxo: 'ElementsUtxoData',
                              amount: Union[int, 'ConfidentialValue'],
                              address, entropy,
                              locking_script='') -> 'ConfidentialAsset':
        _amount = amount
        if isinstance(amount, ConfidentialValue):
            _amount = amount.amount
        _txid = to_hex_string(utxo.outpoint.txid)
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                handle, self.network) as tx_handle:
            asset = util.call_func(
                'CfdSetReissueAsset', handle.get_handle(),
                tx_handle.get_handle(), _txid, utxo.outpoint.vout,
                _amount, to_hex_string(utxo.asset_blinder),
                to_hex_string(entropy),
                str(address), to_hex_string(locking_script))
            self.hex = util.call_func(
                'CfdFinalizeTransaction', handle.get_handle(),
                tx_handle.get_handle())
            self._update_txin_internal(
                handle, tx_handle, OutPoint(_txid, utxo.outpoint.vout))
            return ConfidentialAsset(asset)

    ##
    # @brief get signature hash.
    # @param[in] outpoint       outpoint
    # @param[in] hash_type      hash type
    # @param[in] value          value
    # @param[in] pubkey         pubkey
    # @param[in] redeem_script  redeem script
    # @param[in] sighashtype    sighash type
    # @return sighash
    def get_sighash(
            self,
            outpoint: 'OutPoint',
            hash_type,
            value,
            pubkey='',
            redeem_script='',
            sighashtype=SigHashType.ALL) -> 'ByteData':
        _hash_type = HashType.get(hash_type)
        _pubkey = to_hex_string(pubkey)
        _script = to_hex_string(redeem_script)
        _sighashtype = SigHashType.get(sighashtype)
        _value = value
        if isinstance(value, ConfidentialValue) is False:
            _value = ConfidentialValue(value)
        util = get_util()
        with util.create_handle() as handle:
            sighash = util.call_func(
                'CfdCreateConfidentialSighash', handle.get_handle(),
                self.hex, str(outpoint.txid), outpoint.vout,
                _hash_type.value, _pubkey, _script,
                _value.amount, _value.hex, _sighashtype.value,
                _sighashtype.anyone_can_pay())
            return ByteData(sighash)

    ##
    # @brief add sign with private key.
    # @param[in] outpoint       outpoint
    # @param[in] hash_type      hash type
    # @param[in] privkey        privkey
    # @param[in] value          value
    # @param[in] sighashtype    sighash type
    # @param[in] grind_r        grind-R flag
    # @return void
    def sign_with_privkey(
            self, outpoint: 'OutPoint', hash_type, privkey, value,
            sighashtype=SigHashType.ALL, grind_r: bool = True) -> None:
        _hash_type = HashType.get(hash_type)
        if isinstance(privkey, Privkey):
            _privkey = privkey
        elif isinstance(privkey, str) and (len(privkey) != 64):
            _privkey = Privkey(wif=privkey)
        else:
            _privkey = Privkey(hex=privkey)
        _pubkey = _privkey.pubkey
        _sighashtype = SigHashType.get(sighashtype)
        _value = value
        if isinstance(value, ConfidentialValue) is False:
            _value = ConfidentialValue(value)
        util = get_util()
        with util.create_handle() as handle:
            self.hex = util.call_func(
                'CfdAddConfidentialTxSignWithPrivkeySimple',
                handle.get_handle(), self.hex, str(outpoint.txid),
                outpoint.vout, _hash_type.value, str(_pubkey),
                str(_privkey), _value.amount, _value.hex,
                _sighashtype.value,
                _sighashtype.anyone_can_pay(), grind_r)
            self._update_txin(outpoint)

    ##
    # @brief verify sign.
    # @param[in] outpoint       outpoint
    # @param[in] address        address
    # @param[in] hash_type      hash type
    # @param[in] value          value
    # @return void
    def verify_sign(self, outpoint: 'OutPoint', address, hash_type,
                    value) -> None:
        _hash_type = HashType.get(hash_type)
        _value = value
        if isinstance(value, ConfidentialValue) is False:
            _value = ConfidentialValue(value)
        util = get_util()
        with util.create_handle() as handle:
            util.call_func(
                'CfdVerifyTxSign', handle.get_handle(),
                self.NETWORK, self.hex, str(outpoint.txid),
                outpoint.vout, str(address), _hash_type.value,
                '', _value.amount, _value.hex)

    ##
    # @brief verify signature.
    # @param[in] outpoint       outpoint
    # @param[in] signature      signature
    # @param[in] hash_type      hash type
    # @param[in] pubkey         pubkey
    # @param[in] value          value
    # @param[in] redeem_script  redeem script
    # @param[in] sighashtype    sighash type
    # @retval True      signature valid.
    # @retval False     signature invalid.
    def verify_signature(
            self, outpoint: 'OutPoint', signature,
            hash_type, pubkey, value,
            redeem_script='', sighashtype=SigHashType.ALL) -> bool:
        _signature = to_hex_string(signature)
        _pubkey = to_hex_string(pubkey)
        _script = to_hex_string(redeem_script)
        _hash_type = HashType.get(hash_type)
        _sighashtype = SigHashType.get(sighashtype)
        _value = value
        if isinstance(value, ConfidentialValue) is False:
            _value = ConfidentialValue(value)
        try:
            util = get_util()
            with util.create_handle() as handle:
                util.call_func(
                    'CfdVerifySignature', handle.get_handle(),
                    self.NETWORK, self.hex, _signature, _hash_type.value,
                    _pubkey, _script, str(outpoint.txid),
                    outpoint.vout, _sighashtype.value,
                    _sighashtype.anyone_can_pay(), _value.amount, _value.hex)
                return True
        except CfdError as err:
            if err.error_code == CfdErrorCode.SIGN_VERIFICATION.value:
                return False
            else:
                raise err

    ##
    # @brief select coins.
    # @param[in] utxo_list              utxo list
    # @param[in] tx_fee_amount          txout fee amount
    # @param[in] target_list            collect target list
    # @param[in] fee_asset              fee asset
    # @param[in] effective_fee_rate     effective fee rate
    # @param[in] long_term_fee_rate     long term fee rate
    # @param[in] dust_fee_rate          dust fee rate
    # @param[in] knapsack_min_change    minimum change threshold for knapsack
    # @param[in] exponent               exponent
    # @param[in] minimum_bits           minimum bits
    # @retval [0]      select utxo list.
    # @retval [1]      utxo fee.
    # @retval [2]      total tx fee.
    @classmethod
    def select_coins(
            cls,
            utxo_list: List['ElementsUtxoData'],
            tx_fee_amount: int,
            target_list: List['TargetAmountData'],
            fee_asset,
            effective_fee_rate: float = 0.11, long_term_fee_rate: float = 0.11,
            dust_fee_rate: float = 3.0, knapsack_min_change: int = -1,
            exponent: int = 0, minimum_bits: int = 52,
    ) -> typing.Tuple[List['ElementsUtxoData'], int, Dict[str, int]]:
        if (isinstance(utxo_list, list) is False) or (
                len(utxo_list) == 0):
            raise CfdError(error_code=1, message='Error: Invalid utxo_list.')
        util = get_util()

        def set_opt(handle, tx_handle, key, i_val=0, f_val=0, b_val=False):
            util.call_func(
                'CfdSetOptionCoinSelection', handle.get_handle(),
                tx_handle.get_handle(), key.value,
                int(i_val), float(f_val), b_val)

        with util.create_handle() as handle:
            work_handle = util.call_func(
                'CfdInitializeCoinSelection', handle.get_handle(),
                len(utxo_list), len(target_list), str(fee_asset),
                int(tx_fee_amount), float(effective_fee_rate),
                float(long_term_fee_rate), float(dust_fee_rate),
                int(knapsack_min_change))
            with JobHandle(handle, work_handle,
                           'CfdFreeCoinSelectionHandle') as tx_handle:
                for index, utxo in enumerate(utxo_list):
                    util.call_func(
                        'CfdAddCoinSelectionUtxoTemplate',
                        handle.get_handle(), tx_handle.get_handle(), index,
                        str(utxo.outpoint.txid), utxo.outpoint.vout,
                        utxo.amount,
                        str(utxo.asset),
                        str(utxo.descriptor),
                        to_hex_string(utxo.scriptsig_template))

                total_collect_amount = 0
                for index, target in enumerate(target_list):
                    util.call_func(
                        'CfdAddCoinSelectionAmount',
                        handle.get_handle(), tx_handle.get_handle(), index,
                        target.amount, str(target.asset))
                    total_collect_amount += target.amount

                set_opt(handle, tx_handle, _CoinSelectionOpt.EXPONENT,
                        i_val=exponent)
                set_opt(handle, tx_handle, _CoinSelectionOpt.MINIMUM_BITS,
                        i_val=minimum_bits)

                _utxo_fee = util.call_func(
                    'CfdFinalizeCoinSelection',
                    handle.get_handle(), tx_handle.get_handle())

                selected_utxo_list = []
                total_amount_map = {}
                if (total_collect_amount > 0) or (_utxo_fee > 0):
                    for i in range(len(utxo_list)):
                        _utxo_index = util.call_func(
                            'CfdGetSelectedCoinIndex',
                            handle.get_handle(), tx_handle.get_handle(), i)
                        if _utxo_index < 0:
                            break
                        elif _utxo_index < len(utxo_list):
                            selected_utxo_list.append(utxo_list[_utxo_index])

                    for index, target in enumerate(target_list):
                        total_amount = util.call_func(
                            'CfdGetSelectedCoinAssetAmount',
                            handle.get_handle(), tx_handle.get_handle(), index)
                        key = str(target.asset)  # not optimisation
                        total_amount_map[key] = total_amount
                return selected_utxo_list, _utxo_fee, total_amount_map

    ##
    # @brief estimate fee.
    # @param[in] utxo_list      txin utxo list
    # @param[in] fee_asset      fee asset
    # @param[in] fee_rate       fee rate
    # @param[in] is_blind       blind flag
    # @param[in] exponent       exponent
    # @param[in] minimum_bits   minimum bits
    # @retval [0]      total tx fee. (txout fee + utxo fee)
    # @retval [1]      txout fee.
    # @retval [2]      utxo fee.
    def estimate_fee(self, utxo_list: List['ElementsUtxoData'],
                     fee_asset,
                     fee_rate: float = 0.11, is_blind: bool = True,
                     exponent: int = 0, minimum_bits: int = 52,
                     ) -> typing.Tuple[int, int, int]:
        _fee_asset = ConfidentialAsset(fee_asset)
        if (isinstance(utxo_list, list) is False) or (
                len(utxo_list) == 0):
            raise CfdError(
                error_code=1, message='Error: Invalid utxo_list.')
        util = get_util()

        def set_opt(handle, tx_handle, key, i_val=0, f_val=0, b_val=False):
            util.call_func(
                'CfdSetOptionEstimateFee', handle.get_handle(),
                tx_handle.get_handle(), key.value,
                int(i_val), float(f_val), b_val)

        with util.create_handle() as handle:
            work_handle = ctypes.c_void_p()
            util.call_func(
                'CfdInitializeEstimateFee', handle.get_handle(),
                ctypes.byref(work_handle), True)
            with JobHandle(handle, work_handle.value,
                           'CfdFreeEstimateFeeHandle') as tx_handle:
                for utxo in utxo_list:
                    util.call_func(
                        'CfdAddTxInTemplateForEstimateFee',
                        handle.get_handle(), tx_handle.get_handle(),
                        str(utxo.outpoint.txid), utxo.outpoint.vout,
                        str(utxo.descriptor), str(utxo.asset),
                        utxo.is_issuance, utxo.is_blind_issuance,
                        utxo.is_pegin, int(utxo.pegin_btc_tx_size),
                        to_hex_string(utxo.fedpeg_script),
                        to_hex_string(utxo.scriptsig_template))

                set_opt(handle, tx_handle, _FeeOpt.EXPONENT, i_val=exponent)
                set_opt(handle, tx_handle, _FeeOpt.MINIMUM_BITS,
                        i_val=minimum_bits)

                _txout_fee = ctypes.c_int64()
                _utxo_fee = ctypes.c_int64()
                util.call_func(
                    'CfdFinalizeEstimateFee',
                    handle.get_handle(), tx_handle.get_handle(),
                    self.hex, str(_fee_asset), ctypes.byref(_txout_fee),
                    ctypes.byref(_utxo_fee), is_blind, fee_rate)
                txout_fee, utxo_fee = _txout_fee.value, _utxo_fee.value
                return (txout_fee + utxo_fee), txout_fee, utxo_fee

    ##
    # @brief fund transaction.
    # @param[in] txin_utxo_list         txin list
    # @param[in] utxo_list              utxo list
    # @param[in] target_list            collect target list
    # @param[in] fee_asset              fee asset
    # @param[in] effective_fee_rate     effective fee rate
    # @param[in] long_term_fee_rate     long term fee rate
    # @param[in] dust_fee_rate          dust fee rate
    # @param[in] knapsack_min_change    minimum change threshold for knapsack
    # @param[in] is_blind               blind flag
    # @param[in] exponent               exponent
    # @param[in] minimum_bits           minimum bits
    # @retval [0]      total tx fee.
    # @retval [1]      used reserved address. (None or reserved_address)
    def fund_raw_transaction(
            self, txin_utxo_list: List['ElementsUtxoData'],
            utxo_list: List['ElementsUtxoData'],
            target_list: List['TargetAmountData'],
            fee_asset,
            effective_fee_rate: float = 0.11,
            long_term_fee_rate: float = -1.0,
            dust_fee_rate: float = -1.0,
            knapsack_min_change: int = -1, is_blind: bool = True,
            exponent: int = 0,
            minimum_bits: int = 52) -> typing.Tuple[int, List[str]]:
        util = get_util()

        def set_opt(handle, tx_handle, key, i_val=0, f_val=0, b_val=False):
            util.call_func(
                'CfdSetOptionFundRawTx', handle.get_handle(),
                tx_handle.get_handle(), key.value,
                int(i_val), float(f_val), b_val)

        network = self.NETWORK
        for target in target_list:
            if len(str(target.reserved_address)) > 0:
                check_addr = target.reserved_address
                if ConfidentialAddress.valid(check_addr):
                    if isinstance(check_addr, ConfidentialAddress):
                        check_addr = check_addr.address
                    else:
                        check_addr = ConfidentialAddress.parse(
                            check_addr).address
                if not isinstance(check_addr, Address):
                    check_addr = AddressUtil.parse(check_addr)
                temp_network = Network.get(check_addr.network)
                if temp_network in [Network.LIQUID_V1,
                                    Network.ELEMENTS_REGTEST]:
                    network = temp_network.value
                    break

        with util.create_handle() as handle:
            work_handle = util.call_func(
                'CfdInitializeFundRawTx', handle.get_handle(),
                network, len(target_list), str(fee_asset))
            with JobHandle(handle, work_handle,
                           'CfdFreeFundRawTxHandle') as tx_handle:
                for utxo in txin_utxo_list:
                    util.call_func(
                        'CfdAddTxInTemplateForFundRawTx',
                        handle.get_handle(), tx_handle.get_handle(),
                        str(utxo.outpoint.txid), utxo.outpoint.vout,
                        utxo.amount, str(utxo.descriptor),
                        str(utxo.asset),
                        utxo.is_issuance, utxo.is_blind_issuance,
                        utxo.is_pegin, int(utxo.pegin_btc_tx_size),
                        to_hex_string(utxo.fedpeg_script),
                        to_hex_string(utxo.scriptsig_template))
                for utxo in utxo_list:
                    util.call_func(
                        'CfdAddUtxoTemplateForFundRawTx',
                        handle.get_handle(), tx_handle.get_handle(),
                        str(utxo.outpoint.txid), utxo.outpoint.vout,
                        utxo.amount, str(utxo.descriptor), str(utxo.asset),
                        to_hex_string(utxo.scriptsig_template))

                for index, target in enumerate(target_list):
                    util.call_func(
                        'CfdAddTargetAmountForFundRawTx',
                        handle.get_handle(), tx_handle.get_handle(),
                        index, target.amount, str(target.asset),
                        str(target.reserved_address))

                set_opt(handle, tx_handle, _FundTxOpt.DUST_FEE_RATE,
                        f_val=dust_fee_rate)
                set_opt(handle, tx_handle, _FundTxOpt.LONG_TERM_FEE_RATE,
                        f_val=long_term_fee_rate)
                set_opt(handle, tx_handle, _FundTxOpt.KNAPSACK_MIN_CHANGE,
                        i_val=knapsack_min_change)
                set_opt(handle, tx_handle, _FundTxOpt.USE_BLIND,
                        b_val=is_blind)
                set_opt(handle, tx_handle, _FundTxOpt.EXPONENT,
                        i_val=exponent)
                set_opt(handle, tx_handle, _FundTxOpt.MINIMUM_BITS,
                        i_val=minimum_bits)

                _tx_fee, _append_txout_count, _new_hex = util.call_func(
                    'CfdFinalizeFundRawTx',
                    handle.get_handle(), tx_handle.get_handle(),
                    self.hex, effective_fee_rate)

                _used_addr_list = []
                for i in range(_append_txout_count):
                    _used_addr = util.call_func(
                        'CfdGetAppendTxOutFundRawTx',
                        handle.get_handle(), tx_handle.get_handle(), i)
                    _used_addr_list.append(_used_addr)

                self.hex = _new_hex
                self._update_tx_all()
                return _tx_fee, _used_addr_list


##
# @class _BlindOpt
# @brief Blind option class.
class _BlindOpt(Enum):
    ##
    # blind minimum range value (for elements)
    MINIMUM_RANGE_VALUE = 1
    ##
    # blind exponent (for elements)
    EXPONENT = 2
    ##
    # blind minimum bits (for elements)
    MINIMUM_BITS = 3
    ##
    # collect blinder (for elements)
    COLLECT_BLINDER = 4


##
# @class _CoinSelectionOpt
# @brief CoinSelection option class.
class _CoinSelectionOpt(Enum):
    ##
    # blind exponent (for elements)
    EXPONENT = 1
    ##
    # blind minimum bits (for elements)
    MINIMUM_BITS = 2


##
# @class _FeeOpt
# @brief EstimateFee option class.
class _FeeOpt(Enum):
    ##
    # blind exponent (for elements)
    EXPONENT = 1
    ##
    # blind minimum bits (for elements)
    MINIMUM_BITS = 2


##
# All import target.
__all__ = [
    'BlindFactor',
    'ConfidentialNonce',
    'ConfidentialAsset',
    'ConfidentialValue',
    'ElementsUtxoData',
    'Issuance',
    'IssuanceKeyPair',
    'UnblindData',
    'BlindData',
    'IssuanceAssetBlindData',
    'IssuanceTokenBlindData',
    'TargetAmountData',
    'ConfidentialTxIn',
    'ConfidentialTxOut',
    'ConfidentialTransaction'
]
