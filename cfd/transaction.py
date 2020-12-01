# -*- coding: utf-8 -*-
##
# @file transaction.py
# @brief transaction function implements file.
# @note Copyright 2020 CryptoGarage
from typing import AnyStr, List, Optional, Tuple, Union
import typing
from .util import get_util, JobHandle, CfdError, to_hex_string,\
    CfdErrorCode, ReverseByteData, ByteData
from .address import Address, AddressUtil
from .key import Network, SigHashType, SignParameter, Privkey
from .script import HashType, Script
from .descriptor import Descriptor
from enum import Enum
import ctypes
import copy


##
# @class Txid
# @brief Txid class.
class Txid(ReverseByteData):
    ##
    # @brief constructor.
    # @param[in] txid   txid
    def __init__(self, txid):
        super().__init__(txid)
        if len(self.hex) != 64:
            raise CfdError(
                error_code=1, message='Error: Invalid txid.')


##
# @class OutPoint
# @brief OutPoint class.
class OutPoint:
    ##
    # @var txid
    # txid
    txid: 'Txid'
    ##
    # @var vout
    # vout
    vout: int

    ##
    # @brief constructor.
    # @param[in] txid   txid
    # @param[in] vout   vout
    def __init__(self, txid, vout: int):
        self.txid = Txid(txid)
        self.vout = vout
        if isinstance(vout, int) is False:
            raise CfdError(
                error_code=1,
                message='Error: Invalid vout type.')

    ##
    # @brief get string.
    # @return txid.
    def __str__(self) -> str:
        return '{},{}'.format(str(self.txid), self.vout)

    ##
    # @brief equal method.
    # @param[in] other      other object.
    # @return true or false.
    def __eq__(self, other: 'OutPoint') -> bool:
        if not isinstance(other, OutPoint):
            return NotImplemented
        return (self.txid.hex == other.txid.hex) and (
            self.vout == other.vout)

    ##
    # @brief diff method.
    # @param[in] other      other object.
    # @return true or false.
    def __lt__(self, other: 'OutPoint') -> bool:
        if not isinstance(other, OutPoint):
            return NotImplemented
        return (self.txid.hex, self.vout) < (other.txid.hex, other.vout)

    ##
    # @brief equal method.
    # @param[in] other      other object.
    # @return true or false.
    def __ne__(self, other: 'OutPoint') -> bool:
        return not self.__eq__(other)

    ##
    # @brief diff method.
    # @param[in] other      other object.
    # @return true or false.
    def __le__(self, other: 'OutPoint') -> bool:
        return self.__lt__(other) or self.__eq__(other)

    ##
    # @brief diff method.
    # @param[in] other      other object.
    # @return true or false.
    def __gt__(self, other: 'OutPoint') -> bool:
        return not self.__le__(other)

    ##
    # @brief diff method.
    # @param[in] other      other object.
    # @return true or false.
    def __ge__(self, other: 'OutPoint') -> bool:
        return not self.__lt__(other)


##
# @class UtxoData
# @brief UtxoData class.
class UtxoData:
    ##
    # @var outpoint
    # outpoint
    outpoint: 'OutPoint'
    ##
    # @var amount
    # amount
    amount: int
    ##
    # @var descriptor
    # descriptor
    descriptor: Union[str, 'Descriptor']
    ##
    # @var scriptsig_template
    # scriptsig template
    scriptsig_template: Union['Script', 'ByteData', AnyStr]

    ##
    # @brief constructor.
    # @param[in] outpoint               outpoint
    # @param[in] txid                   txid
    # @param[in] vout                   vout
    # @param[in] amount                 amount
    # @param[in] descriptor             descriptor
    # @param[in] scriptsig_template     scriptsig template
    def __init__(
            self, outpoint: Optional['OutPoint'] = None,
            txid='', vout: int = 0,
            amount: int = 0, descriptor: Union[str, 'Descriptor'] = '',
            scriptsig_template: Union['Script', 'ByteData', AnyStr] = ''):
        if isinstance(outpoint, OutPoint):
            self.outpoint = outpoint
        else:
            self.outpoint = OutPoint(txid, vout)
        self.amount = amount
        self.descriptor = descriptor
        self.scriptsig_template = scriptsig_template

    ##
    # @brief get string.
    # @return hex.
    def __str__(self):
        return str(self.outpoint)

    ##
    # @brief equal method.
    # @param[in] other      other object.
    # @return true or false.
    def __eq__(self, other):
        if not isinstance(other, UtxoData):
            return NotImplemented
        return self.outpoint == other.outpoint

    ##
    # @brief diff method.
    # @param[in] other      other object.
    # @return true or false.
    def __lt__(self, other):
        if not isinstance(other, UtxoData):
            return NotImplemented
        return (self.outpoint) < (other.outpoint)

    ##
    # @brief equal method.
    # @param[in] other      other object.
    # @return true or false.
    def __ne__(self, other):
        return not self.__eq__(other)

    ##
    # @brief diff method.
    # @param[in] other      other object.
    # @return true or false.
    def __le__(self, other):
        return self.__lt__(other) or self.__eq__(other)

    ##
    # @brief diff method.
    # @param[in] other      other object.
    # @return true or false.
    def __gt__(self, other):
        return not self.__le__(other)

    ##
    # @brief diff method.
    # @param[in] other      other object.
    # @return true or false.
    def __ge__(self, other):
        return not self.__lt__(other)


##
# @class TxIn
# @brief Transacton input.
class TxIn:
    ##
    # @var outpoint
    # outpoint
    outpoint: 'OutPoint'
    ##
    # @var sequence
    # sequence
    sequence: int
    ##
    # @var script_sig
    # script sig
    script_sig: 'Script'
    ##
    # @var witness_stack
    # witness stack
    witness_stack: List[Union['Script', 'ByteData', AnyStr]]

    ##
    # sequence disable.
    SEQUENCE_DISABLE = 0xffffffff
    ##
    # sequence final.
    SEQUENCE_FINAL = 0xfffffffe

    ##
    # @brief get sequence number.
    # @param[in] locktime   locktime
    # @param[in] sequence   sequence
    # @return sequence number.
    @classmethod
    def get_sequence_number(cls, locktime: int = 0, sequence: int = SEQUENCE_DISABLE):
        if sequence not in [-1, TxIn.SEQUENCE_DISABLE]:
            return sequence
        elif locktime == 0:
            return TxIn.SEQUENCE_DISABLE
        else:
            return TxIn.SEQUENCE_FINAL

    ##
    # @brief constructor.
    # @param[in] outpoint   outpoint
    # @param[in] txid       txid
    # @param[in] vout       vout
    # @param[in] sequence   sequence
    def __init__(self, outpoint: Optional['OutPoint'] = None,
                 txid='', vout: int = 0, sequence: int = SEQUENCE_DISABLE):
        if isinstance(outpoint, OutPoint):
            self.outpoint = outpoint
        else:
            self.outpoint = OutPoint(txid=txid, vout=vout)
        self.sequence = sequence
        self.script_sig = Script('')
        self.witness_stack = []

    ##
    # @brief get string.
    # @return hex.
    def __str__(self) -> str:
        return str(self.outpoint)


##
# @class TxOut
# @brief Transacton output.
class TxOut:
    ##
    # @var amount
    # amount
    amount: int
    ##
    # @var address
    # address
    address: Union['Address', str]
    ##
    # @var locking_script
    # locking script
    locking_script: 'Script'

    ##
    # @brief constructor.
    # @param[in] amount             amount
    # @param[in] address            address
    # @param[in] locking_script     locking script
    def __init__(self, amount: int, address='', locking_script=''):
        self.amount = amount
        if address != '':
            self.address = address if isinstance(
                address, Address) else str(address)
            self.locking_script = Script('')
        else:
            self.locking_script = Script(locking_script)
            self.address = ''

    ##
    # @brief constructor.
    # @param[in] network    network
    # @return address.
    def get_address(self, network=Network.MAINNET) -> 'Address':
        if isinstance(self.address, Address):
            return self.address
        if self.address != '':
            return AddressUtil.parse(self.address)
        return AddressUtil.from_locking_script(self.locking_script, network)

    ##
    # @brief get string.
    # @return address or script.
    def __str__(self) -> str:
        if (self.address != ''):
            return str(self.address)
        else:
            return str(self.locking_script)


##
# @class _TransactionBase
# @brief Transacton base.
class _TransactionBase:
    ##
    # @var hex
    # transaction hex string
    hex: str
    ##
    # @var network
    # transaction network type
    network: int
    ##
    # @var enable_cache
    # use transaction cache
    enable_cache: bool

    ##
    # @brief constructor.
    # @param[in] hex            transaction hex
    # @param[in] network        network
    # @param[in] enable_cache   enable_cache
    def __init__(self, hex, network, enable_cache=True):
        self.hex = to_hex_string(hex)
        self.enable_cache = enable_cache
        self.network = Network.get(network).value

    ##
    # @brief get string.
    # @return tx hex.
    def __str__(self) -> str:
        return self.hex

    ##
    # @brief update transaction cache all.
    # @return void
    def _update_tx_all(self):
        if self.enable_cache:
            self.get_tx_all()

    ##
    # @brief get transaction input.
    # @param[in] handle     cfd handle
    # @param[in] tx_handle  tx handle
    # @param[in] index      index
    # @param[in] outpoint   outpoint
    # @retval [0] txin
    # @retval [1] index
    def _get_txin(self, handle, tx_handle, index=0, outpoint=None):
        util = get_util()

        if isinstance(outpoint, OutPoint):
            index = util.call_func(
                'CfdGetTxInIndexByHandle', handle.get_handle(),
                tx_handle.get_handle(), str(outpoint.txid),
                outpoint.vout)

        txid, vout, seq, script = util.call_func(
            'CfdGetTxInByHandle', handle.get_handle(),
            tx_handle.get_handle(), index)
        txin = TxIn(txid=txid, vout=vout, sequence=seq)
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
        return txin, index

    ##
    # @brief get transaction input index.
    # @param[in] outpoint   outpoint
    # @param[in] txid       txid
    # @param[in] vout       vout
    # @return index
    def get_txin_index(self, outpoint: Optional['OutPoint'] = None,
                       txid='', vout=0) -> int:
        txin = TxIn(outpoint=outpoint, txid=txid, vout=vout)
        util = get_util()
        with util.create_handle() as handle:
            index = util.call_func(
                'CfdGetTxInIndex', handle.get_handle(),
                self.network, self.hex, str(txin.outpoint.txid),
                txin.outpoint.vout)
            return index

    ##
    # @brief get transaction output index.
    # @param[in] address            address
    # @param[in] locking_script     locking_script
    # @return index
    def get_txout_index(self, address='', locking_script='') -> int:
        # get first target only.
        _script = to_hex_string(locking_script)
        util = get_util()
        with util.create_handle() as handle:
            index = util.call_func(
                'CfdGetTxOutIndex', handle.get_handle(),
                self.network, self.hex, str(address), _script)
            return index

    ##
    # @brief add pubkey hash sign.
    # @param[in] outpoint       outpoint
    # @param[in] hash_type      hash type
    # @param[in] pubkey         pubkey
    # @param[in] signature      signature
    # @param[in] sighashtype    sighash type
    # @return void
    def add_pubkey_hash_sign(
            self, outpoint: 'OutPoint', hash_type, pubkey, signature,
            sighashtype=SigHashType.ALL) -> None:
        _hash_type = HashType.get(hash_type)
        _pubkey = to_hex_string(pubkey)
        _signature = to_hex_string(signature)
        _sighashtype = SigHashType.get(sighashtype)
        if isinstance(signature, SignParameter) and (
                _sighashtype == SigHashType.ALL):
            _sighashtype = SigHashType.get(signature.sighashtype)
        use_der_encode = (len(_signature) <= 130) is True
        util = get_util()
        with util.create_handle() as handle:
            self.hex = util.call_func(
                'CfdAddPubkeyHashSign', handle.get_handle(),
                self.network, self.hex, str(outpoint.txid),
                outpoint.vout, _hash_type.value, _pubkey,
                _signature, use_der_encode, _sighashtype.get_type(),
                _sighashtype.anyone_can_pay())
            self._update_txin(outpoint)

    ##
    # @brief add multisig sign.
    # @param[in] outpoint           outpoint
    # @param[in] hash_type          hash type
    # @param[in] redeem_script      redeem script
    # @param[in] signature_list     signature list
    # @return void
    def add_multisig_sign(
            self, outpoint: 'OutPoint', hash_type, redeem_script,
            signature_list) -> None:
        if (isinstance(signature_list, list) is False) or (
                len(signature_list) == 0):
            raise CfdError(
                error_code=1, message='Error: Invalid signature_list.')
        _hash_type = HashType.get(hash_type)
        _script = to_hex_string(redeem_script)
        util = get_util()
        with util.create_handle() as handle:
            word_handle = util.call_func(
                'CfdInitializeMultisigSign', handle.get_handle())
            with JobHandle(handle, word_handle,
                           'CfdFreeMultisigSignHandle') as tx_handle:
                for sig in signature_list:
                    _sig = to_hex_string(sig)
                    _sighashtype = SigHashType.ALL
                    _related_pubkey = ''
                    use_der = (len(_sig) in [128, 130])
                    if isinstance(sig, SignParameter):
                        _sighashtype = SigHashType.get(sig.sighashtype)
                        _related_pubkey = to_hex_string(sig.related_pubkey)
                        use_der = sig.use_der_encode
                    elif use_der:
                        raise CfdError(
                            error_code=1, message='Error: Invalid signature.')

                    if use_der:
                        util.call_func(
                            'CfdAddMultisigSignDataToDer',
                            handle.get_handle(), tx_handle.get_handle(),
                            _sig, _sighashtype.get_type(),
                            _sighashtype.anyone_can_pay(), _related_pubkey)
                    else:
                        util.call_func(
                            'CfdAddMultisigSignData',
                            handle.get_handle(), tx_handle.get_handle(),
                            _sig, _related_pubkey)

                self.hex = util.call_func(
                    'CfdFinalizeMultisigSign',
                    handle.get_handle(), tx_handle.get_handle(),
                    self.network, self.hex, str(outpoint.txid),
                    outpoint.vout, _hash_type.value, _script)
                self._update_txin(outpoint)

    ##
    # @brief add script hash sign.
    # @param[in] outpoint           outpoint
    # @param[in] hash_type          hash type
    # @param[in] redeem_script      redeem script
    # @param[in] signature_list     signature list
    # @return void
    def add_script_hash_sign(
            self, outpoint: 'OutPoint', hash_type, redeem_script,
            signature_list) -> None:
        if (isinstance(signature_list, list) is False) or (
                len(signature_list) == 0):
            raise CfdError(
                error_code=1, message='Error: Invalid signature_list.')
        _hash_type = HashType.get(hash_type)
        _script = to_hex_string(redeem_script)
        util = get_util()
        with util.create_handle() as handle:
            clear_stack = True
            for sig in signature_list:
                _sig = sig
                if not isinstance(sig, str):
                    _sig = to_hex_string(sig)
                _sighashtype = SigHashType.ALL
                use_der_encode = False
                if isinstance(sig, SignParameter):
                    _sighashtype = SigHashType.get(sig.sighashtype)
                    use_der_encode = sig.use_der_encode

                self.hex = util.call_func(
                    'CfdAddTxSign', handle.get_handle(),
                    self.network, self.hex, str(outpoint.txid),
                    outpoint.vout, _hash_type.value, _sig,
                    use_der_encode, _sighashtype.get_type(),
                    _sighashtype.anyone_can_pay(), clear_stack)
                clear_stack = False

            self.hex = util.call_func(
                'CfdAddScriptHashSign',
                handle.get_handle(), self.network, self.hex,
                str(outpoint.txid), outpoint.vout, _hash_type.value,
                _script, False)
            self._update_txin(outpoint)

    ##
    # @brief add sign.
    # @param[in] outpoint           outpoint
    # @param[in] hash_type          hash type
    # @param[in] sign_data          sign data
    # @param[in] clear_stack        clear stack
    # @param[in] use_der_encode     use der encode
    # @param[in] sighashtype        sighash type
    # @return void
    def add_sign(
            self, outpoint: 'OutPoint', hash_type, sign_data,
            clear_stack: bool = False, use_der_encode: bool = False,
            sighashtype=SigHashType.ALL) -> None:
        _hash_type = HashType.get(hash_type)
        _sign_data = sign_data
        if not isinstance(sign_data, str):
            _sign_data = to_hex_string(sign_data)
        _sighashtype = SigHashType.get(sighashtype)
        util = get_util()
        with util.create_handle() as handle:
            self.hex = util.call_func(
                'CfdAddTxSign', handle.get_handle(),
                self.network, self.hex, str(outpoint.txid),
                outpoint.vout, _hash_type.value, _sign_data,
                use_der_encode, _sighashtype.get_type(),
                _sighashtype.anyone_can_pay(), clear_stack)
            self._update_txin(outpoint)


##
# @class Transaction
# @brief Bitcoin Transacton.
class Transaction(_TransactionBase):
    ##
    # @var hex
    # transaction hex string
    hex: str
    ##
    # @var txin_list
    # transaction input list
    txin_list: List['TxIn']
    ##
    # @var txout_list
    # transaction output list
    txout_list: List['TxOut']
    ##
    # @var txid
    # txid
    txid: 'Txid'
    ##
    # @var wtxid
    # wtxid
    wtxid: 'Txid'
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
    NETWORK = Network.MAINNET.value
    ##
    # transaction's free function name.
    FREE_FUNC_NAME = 'CfdFreeTransactionHandle'

    ##
    # @brief parse transaction to json.
    # @param[in] hex        transaction hex
    # @param[in] network    network
    # @return json string
    @classmethod
    def parse_to_json(cls, hex: str, network=Network.MAINNET) -> str:
        _network = Network.get(network)
        network_str = 'mainnet'
        if _network == Network.TESTNET:
            network_str = 'testnet'
        elif _network == Network.REGTEST:
            network_str = 'regtest'
        request_json = '{{"hex":"{}","network":"{}"}}'.format(hex, network_str)
        util = get_util()
        with util.create_handle() as handle:
            return util.call_func(
                'CfdRequestExecuteJson', handle.get_handle(),
                'DecodeRawTransaction', request_json)

    ##
    # @brief create transaction.
    # @param[in] version        version
    # @param[in] locktime       locktime
    # @param[in] txins          txin list
    # @param[in] txouts         txout list
    # @param[in] enable_cache   enable tx cache
    # @return transaction object
    @classmethod
    def create(cls, version: int, locktime: int, txins: List['TxIn'],
               txouts: List['TxOut'], enable_cache: bool = True) -> 'Transaction':
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
                        'CfdAddTransactionOutput', handle.get_handle(),
                        tx_handle.get_handle(), txout.amount,
                        str(txout.address),
                        str(txout.locking_script), '')
                hex = util.call_func(
                    'CfdFinalizeTransaction', handle.get_handle(),
                    tx_handle.get_handle())
        return Transaction(hex, enable_cache)

    ##
    # @brief get transaction from hex.
    # @param[in] hex            tx hex
    # @param[in] enable_cache   enable tx cache
    # @return transaction object
    @classmethod
    def from_hex(cls, hex, enable_cache: bool = True) -> 'Transaction':
        return Transaction(hex, enable_cache)

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
    # @brief update transaction information.
    # @return void
    def _update_info(self):
        if self.enable_cache is False:
            return
        util = get_util()
        with util.create_handle() as handle:
            ret = util.call_func(
                'CfdGetTxInfo', handle.get_handle(),
                self.NETWORK, self.hex)
            # for doxygen
            self.txid = Txid(ret[0])
            self.wtxid = Txid(ret[1])
            self.size = ret[2]
            self.vsize = ret[3]
            self.weight = ret[4]
            self.version = ret[5]
            self.locktime = ret[6]

    ##
    # @brief update transaction input.
    # @param[in] outpoint       outpoint
    # @return void
    def _update_txin(self, outpoint):
        if self.enable_cache is False:
            return
        util = get_util()
        with util.create_handle() as handle:
            _tx_handle = util.call_func(
                'CfdInitializeTxDataHandle', handle.get_handle(),
                self.NETWORK, self.hex)
            with JobHandle(handle, _tx_handle,
                           self.FREE_FUNC_NAME) as tx_handle:
                self.txid, self.wtxid, self.size, self.vsize, self.weight,\
                    self.version, self.locktime = util.call_func(
                        'CfdGetTxInfoByHandle', handle.get_handle(),
                        tx_handle.get_handle())
                self.txid = Txid(self.txid)
                self.wtxid = Txid(self.wtxid)
                # update txin
                txin, index = self._get_txin(
                    handle, tx_handle, outpoint=outpoint)
                self.txin_list[index] = txin

    ##
    # @brief get transaction all data.
    # @retval [0]   txin list
    # @retval [1]   txout list
    def get_tx_all(self) -> typing.Tuple[List['TxIn'], List['TxOut']]:
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
                amount, script, _ = util.call_func(
                    'CfdGetTxOutByHandle', handle.get_handle(),
                    tx_handle.get_handle(), i)
                txout = TxOut(amount=amount, locking_script=script)
                txout_list.append(txout)
            return txout_list

        util = get_util()
        with util.create_handle() as handle:
            _tx_handle = util.call_func(
                'CfdInitializeTxDataHandle', handle.get_handle(),
                self.NETWORK, self.hex)
            with JobHandle(handle, _tx_handle,
                           self.FREE_FUNC_NAME) as tx_handle:
                self.txid, self.wtxid, self.size, self.vsize, self.weight,\
                    self.version, self.locktime = util.call_func(
                        'CfdGetTxInfoByHandle', handle.get_handle(),
                        tx_handle.get_handle())
                self.txid = Txid(self.txid)
                self.wtxid = Txid(self.wtxid)
                self.txin_list = get_txin_list(handle, tx_handle)
                self.txout_list = get_txout_list(handle, tx_handle)
                return self.txin_list, self.txout_list

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
        txin = TxIn(
            outpoint=outpoint, sequence=sec, txid=txid, vout=vout)
        self.add([txin], [])

    ##
    # @brief add transaction output.
    # @param[in] amount             amount
    # @param[in] address            address
    # @param[in] locking_script     locking script
    # @return void
    def add_txout(self, amount: int, address='', locking_script='') -> None:
        txout = TxOut(amount, address, locking_script)
        self.add([], [txout])

    ##
    # @brief add transaction.
    # @param[in] txins          txin list
    # @param[in] txouts         txout list
    # @return void
    def add(self, txins: List['TxIn'], txouts: List['TxOut']) -> None:
        util = get_util()
        with util.create_handle() as handle:
            _tx_handle = util.call_func(
                'CfdInitializeTransaction', handle.get_handle(),
                self.NETWORK, 0, 0, self.hex)
            with JobHandle(
                    handle, _tx_handle, self.FREE_FUNC_NAME) as tx_handle:
                for txin in txins:
                    sec = TxIn.get_sequence_number(
                        self.locktime, txin.sequence)
                    util.call_func(
                        'CfdAddTransactionInput', handle.get_handle(),
                        tx_handle.get_handle(), str(txin.outpoint.txid),
                        txin.outpoint.vout, sec)
                for txout in txouts:
                    util.call_func(
                        'CfdAddTransactionOutput', handle.get_handle(),
                        tx_handle.get_handle(), txout.amount,
                        str(txout.address),
                        str(txout.locking_script), '')
                self.hex = util.call_func(
                    'CfdFinalizeTransaction', handle.get_handle(),
                    tx_handle.get_handle())
                self.txid, self.wtxid, self.size, self.vsize, self.weight,\
                    self.version, self.locktime = util.call_func(
                        'CfdGetTxInfoByHandle', handle.get_handle(),
                        tx_handle.get_handle())
                self.txid = Txid(self.txid)
                self.wtxid = Txid(self.wtxid)
                self.txin_list += copy.deepcopy(txins)
                self.txout_list += copy.deepcopy(txouts)

    ##
    # @brief update transaction output amount.
    # @param[in] index      index
    # @param[in] amount     amount
    # @return void
    def update_txout_amount(self, index: int, amount: int):
        util = get_util()
        with util.create_handle() as handle:
            self.hex = util.call_func(
                'CfdUpdateTxOutAmount', handle.get_handle(),
                self.NETWORK, self.hex, index, amount)
            self._update_info()
            self.txout_list[index].amount = amount

    ##
    # @brief get signature hash.
    # @param[in] outpoint       outpoint
    # @param[in] hash_type      hash type
    # @param[in] amount         amount
    # @param[in] pubkey         pubkey
    # @param[in] redeem_script  redeem script
    # @param[in] sighashtype    sighash type
    # @return sighash
    def get_sighash(
            self,
            outpoint: 'OutPoint',
            hash_type,
            amount: int = 0,
            pubkey='',
            redeem_script='',
            sighashtype=SigHashType.ALL) -> 'ByteData':
        _hash_type = HashType.get(hash_type)
        _pubkey = to_hex_string(pubkey)
        _script = to_hex_string(redeem_script)
        _sighashtype = SigHashType.get(sighashtype)
        util = get_util()
        with util.create_handle() as handle:
            sighash = util.call_func(
                'CfdCreateSighash', handle.get_handle(),
                self.NETWORK, self.hex, str(outpoint.txid),
                outpoint.vout, _hash_type.value, _pubkey,
                _script, amount, _sighashtype.get_type(),
                _sighashtype.anyone_can_pay())
            return ByteData(sighash)

    ##
    # @brief add sign with private key.
    # @param[in] outpoint       outpoint
    # @param[in] hash_type      hash type
    # @param[in] privkey        privkey
    # @param[in] amount         amount
    # @param[in] sighashtype    sighash type
    # @param[in] grind_r        grind-R flag
    # @return void
    def sign_with_privkey(
            self,
            outpoint: 'OutPoint',
            hash_type,
            privkey,
            amount: int = 0,
            sighashtype=SigHashType.ALL,
            grind_r: bool = True) -> None:
        _hash_type = HashType.get(hash_type)
        if isinstance(privkey, Privkey):
            _privkey = privkey
        elif isinstance(privkey, str) and (len(privkey) != 64):
            _privkey = Privkey(wif=privkey)
        else:
            _privkey = Privkey(hex=privkey)
        _pubkey = _privkey.pubkey
        _sighashtype = SigHashType.get(sighashtype)
        util = get_util()
        with util.create_handle() as handle:
            self.hex = util.call_func(
                'CfdAddSignWithPrivkeySimple', handle.get_handle(),
                self.NETWORK, self.hex, str(outpoint.txid),
                outpoint.vout, _hash_type.value, str(_pubkey),
                str(_privkey), amount, _sighashtype.get_type(),
                _sighashtype.anyone_can_pay(), grind_r)
            self._update_txin(outpoint)

    ##
    # @brief verify sign.
    # @param[in] outpoint       outpoint
    # @param[in] address        address
    # @param[in] hash_type      hash type
    # @param[in] amount         amount
    # @return void
    def verify_sign(self, outpoint: 'OutPoint', address, hash_type,
                    amount: int) -> None:
        _hash_type = HashType.get(hash_type)
        util = get_util()
        with util.create_handle() as handle:
            util.call_func(
                'CfdVerifyTxSign', handle.get_handle(),
                self.NETWORK, self.hex, str(outpoint.txid),
                outpoint.vout, str(address), _hash_type.value,
                '', amount, '')

    ##
    # @brief verify signature.
    # @param[in] outpoint       outpoint
    # @param[in] signature      signature
    # @param[in] hash_type      hash type
    # @param[in] pubkey         pubkey
    # @param[in] amount         amount
    # @param[in] redeem_script  redeem script
    # @param[in] sighashtype    sighash type
    # @retval True      signature valid.
    # @retval False     signature invalid.
    def verify_signature(
            self, outpoint: 'OutPoint', signature, hash_type, pubkey,
            amount: int = 0, redeem_script='', sighashtype=SigHashType.ALL) -> bool:
        _signature = to_hex_string(signature)
        _pubkey = to_hex_string(pubkey)
        _script = to_hex_string(redeem_script)
        _hash_type = HashType.get(hash_type)
        _sighashtype = SigHashType.get(sighashtype)
        try:
            util = get_util()
            with util.create_handle() as handle:
                util.call_func(
                    'CfdVerifySignature', handle.get_handle(),
                    self.NETWORK, self.hex, _signature, _hash_type.value,
                    _pubkey, _script, str(outpoint.txid),
                    outpoint.vout, _sighashtype.get_type(),
                    _sighashtype.anyone_can_pay(), amount, '')
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
    # @param[in] target_amount          collect target amount
    # @param[in] effective_fee_rate     effective fee rate
    # @param[in] long_term_fee_rate     long term fee rate
    # @param[in] dust_fee_rate          dust fee rate
    # @param[in] knapsack_min_change    minimum change threshold for knapsack
    # @retval [0]      select utxo list.
    # @retval [1]      utxo fee.
    # @retval [2]      total tx fee.
    @classmethod
    def select_coins(cls, utxo_list: List['UtxoData'], tx_fee_amount: int,
                     target_amount: int, effective_fee_rate: float = 20.0,
                     long_term_fee_rate: float = 20.0, dust_fee_rate: float = 3.0,
                     knapsack_min_change: int = -1,
                     ) -> Tuple[List['UtxoData'], int, int]:
        if (isinstance(utxo_list, list) is False) or (
                len(utxo_list) == 0):
            raise CfdError(
                error_code=1, message='Error: Invalid utxo_list.')
        util = get_util()
        with util.create_handle() as handle:
            word_handle = util.call_func(
                'CfdInitializeCoinSelection', handle.get_handle(),
                len(utxo_list), 1, '', tx_fee_amount, effective_fee_rate,
                long_term_fee_rate, dust_fee_rate, knapsack_min_change)
            with JobHandle(handle, word_handle,
                           'CfdFreeCoinSelectionHandle') as tx_handle:
                for index, utxo in enumerate(utxo_list):
                    util.call_func(
                        'CfdAddCoinSelectionUtxoTemplate',
                        handle.get_handle(), tx_handle.get_handle(), index,
                        str(utxo.outpoint.txid), utxo.outpoint.vout,
                        utxo.amount, '', str(utxo.descriptor),
                        to_hex_string(utxo.scriptsig_template))
                util.call_func(
                    'CfdAddCoinSelectionAmount',
                    handle.get_handle(), tx_handle.get_handle(), 0,
                    target_amount, '')

                _utxo_fee = util.call_func(
                    'CfdFinalizeCoinSelection',
                    handle.get_handle(), tx_handle.get_handle())

                selected_utxo_list = []
                total_amount = 0
                if (target_amount != 0) or (tx_fee_amount != 0):
                    for i in range(len(utxo_list)):
                        _utxo_index = util.call_func(
                            'CfdGetSelectedCoinIndex',
                            handle.get_handle(), tx_handle.get_handle(), i)
                        if _utxo_index < 0:
                            break
                        elif _utxo_index < len(utxo_list):
                            selected_utxo_list.append(utxo_list[_utxo_index])
                    total_amount = util.call_func(
                        'CfdGetSelectedCoinAssetAmount',
                        handle.get_handle(), tx_handle.get_handle(), 0)
                return selected_utxo_list, _utxo_fee, total_amount

    ##
    # @brief estimate fee.
    # @param[in] utxo_list  txin utxo list
    # @param[in] fee_rate   fee rate
    # @retval [0]      total tx fee. (txout fee + utxo fee)
    # @retval [1]      txout fee.
    # @retval [2]      utxo fee.
    def estimate_fee(self, utxo_list: List['UtxoData'], fee_rate: float = 20.0,
                     ) -> Tuple[int, int, int]:
        if (isinstance(utxo_list, list) is False) or (
                len(utxo_list) == 0):
            raise CfdError(
                error_code=1, message='Error: Invalid utxo_list.')
        util = get_util()
        with util.create_handle() as handle:
            work_handle = ctypes.c_void_p()
            util.call_func(
                'CfdInitializeEstimateFee', handle.get_handle(),
                ctypes.byref(work_handle), False)
            with JobHandle(handle, work_handle.value,
                           'CfdFreeEstimateFeeHandle') as tx_handle:
                for utxo in utxo_list:
                    util.call_func(
                        'CfdAddTxInTemplateForEstimateFee',
                        handle.get_handle(), tx_handle.get_handle(),
                        str(utxo.outpoint.txid), utxo.outpoint.vout,
                        str(utxo.descriptor), '', False, False, False,
                        0, '', to_hex_string(utxo.scriptsig_template))

                _txout_fee = ctypes.c_int64()
                _utxo_fee = ctypes.c_int64()
                util.call_func(
                    'CfdFinalizeEstimateFee',
                    handle.get_handle(), tx_handle.get_handle(),
                    self.hex, '', ctypes.byref(_txout_fee),
                    ctypes.byref(_utxo_fee), False, float(fee_rate))
                txout_fee, utxo_fee = _txout_fee.value, _utxo_fee.value
                return (txout_fee + utxo_fee), txout_fee, utxo_fee

    ##
    # @brief fund transaction.
    # @param[in] txin_utxo_list         txin list
    # @param[in] utxo_list              utxo list
    # @param[in] reserved_address       sending reserved address
    # @param[in] target_amount          collect target amount
    # @param[in] effective_fee_rate     effective fee rate
    # @param[in] long_term_fee_rate     long term fee rate
    # @param[in] dust_fee_rate          dust fee rate
    # @param[in] knapsack_min_change    minimum change threshold for knapsack
    # @retval [0]      total tx fee.
    # @retval [1]      used reserved address. (None or reserved_address)
    def fund_raw_transaction(
            self, txin_utxo_list: List['UtxoData'], utxo_list: List['UtxoData'],
            reserved_address, target_amount: int = 0,
            effective_fee_rate: float = 20.0,
            long_term_fee_rate: float = 20.0, dust_fee_rate: float = -1.0,
            knapsack_min_change: int = -1) -> Tuple[int, str]:
        util = get_util()

        def set_opt(handle, tx_handle, key, i_val=0, f_val=0, b_val=False):
            util.call_func(
                'CfdSetOptionFundRawTx', handle.get_handle(),
                tx_handle.get_handle(), int(key.value),
                int(i_val), float(f_val), b_val)

        network = self.NETWORK
        if len(str(reserved_address)) > 0:
            if isinstance(reserved_address, Address):
                check_addr = reserved_address
            else:
                check_addr = AddressUtil.parse(reserved_address)
            temp_network = Network.get(check_addr.network)
            if temp_network in [Network.MAINNET,
                                Network.TESTNET, Network.REGTEST]:
                network = temp_network.value

        with util.create_handle() as handle:
            word_handle = util.call_func(
                'CfdInitializeFundRawTx', handle.get_handle(),
                network, 1, '')
            with JobHandle(handle, word_handle,
                           'CfdFreeFundRawTxHandle') as tx_handle:
                for utxo in txin_utxo_list:
                    util.call_func(
                        'CfdAddTxInTemplateForFundRawTx',
                        handle.get_handle(), tx_handle.get_handle(),
                        str(utxo.outpoint.txid), utxo.outpoint.vout,
                        utxo.amount, str(utxo.descriptor),
                        '', False, False, False, 0, '',
                        to_hex_string(utxo.scriptsig_template))
                for utxo in utxo_list:
                    util.call_func(
                        'CfdAddUtxoTemplateForFundRawTx',
                        handle.get_handle(), tx_handle.get_handle(),
                        str(utxo.outpoint.txid), utxo.outpoint.vout,
                        utxo.amount, str(utxo.descriptor), '',
                        to_hex_string(utxo.scriptsig_template))

                util.call_func(
                    'CfdAddTargetAmountForFundRawTx',
                    handle.get_handle(), tx_handle.get_handle(),
                    0, target_amount, '', str(reserved_address))

                set_opt(handle, tx_handle, _FundTxOpt.DUST_FEE_RATE,
                        f_val=dust_fee_rate)
                set_opt(handle, tx_handle, _FundTxOpt.LONG_TERM_FEE_RATE,
                        f_val=long_term_fee_rate)
                set_opt(handle, tx_handle, _FundTxOpt.KNAPSACK_MIN_CHANGE,
                        i_val=knapsack_min_change)

                _tx_fee, _append_txout_count, _new_hex = util.call_func(
                    'CfdFinalizeFundRawTx',
                    handle.get_handle(), tx_handle.get_handle(),
                    self.hex, effective_fee_rate)

                _used_addr = ''
                if _append_txout_count > 0:
                    _used_addr = util.call_func(
                        'CfdGetAppendTxOutFundRawTx',
                        handle.get_handle(), tx_handle.get_handle(), 0)
                used_addr = None
                if _used_addr == reserved_address:
                    used_addr = str(reserved_address)

                self.hex = _new_hex
                self._update_tx_all()
                return _tx_fee, used_addr


##
# @class _FundTxOpt
# @brief FundTransaction option class.
class _FundTxOpt(Enum):
    ##
    # use blind (for elements)
    USE_BLIND = 1
    ##
    # dust fee rate
    DUST_FEE_RATE = 2
    ##
    # long term fee rate
    LONG_TERM_FEE_RATE = 3
    ##
    # minimum change threshold for knapsack
    KNAPSACK_MIN_CHANGE = 4
    ##
    # blind exponent (for elements)
    EXPONENT = 5
    ##
    # blind minimum bits (for elements)
    MINIMUM_BITS = 6


##
# All import target.
__all__ = [
    'Txid',
    'OutPoint',
    'UtxoData',
    'TxIn',
    'TxOut',
    '_TransactionBase',
    'Transaction'
]
