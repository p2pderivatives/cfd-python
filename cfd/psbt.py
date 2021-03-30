# -*- coding: utf-8 -*-
##
# @file psbt.py
# @brief Partially Signed Bitcoin Transaction function implements file.
# @note Copyright 2021 CryptoGarage
from typing import Any, List, Optional, Tuple, Union
import typing
from .address import Address, AddressUtil
from .descriptor import Descriptor, parse_descriptor
from .hdwallet import KeyData, ExtPubkey
from .key import Network, Pubkey, Privkey, SignParameter, SigHashType
from .script import Script
from .transaction import Transaction, OutPoint, TxIn, TxOut, UtxoData
from .util import ByteData, get_util, CfdError,\
    to_hex_string, CfdErrorCode, JobHandle
from enum import Enum


##
# signature error message
NOT_PERMIT_SIG_ERR_MSG = \
    'Error: tx inputs must not have scriptSigs and witness stacks.'


##
# @class PsbtDefinition
# @brief Psbt definition class.
class PsbtDefinition(Enum):
    ##
    # PSBT_GLOBAL_UNSIGNED_TX
    PSBT_GLOBAL_UNSIGNED_TX = '00'
    ##
    # PSBT_GLOBAL_XPUB
    PSBT_GLOBAL_XPUB = '01'
    ##
    # PSBT_GLOBAL_VERSION
    PSBT_GLOBAL_VERSION = 'fb'
    ##
    # PSBT_GLOBAL_PROPRIETARY
    PSBT_GLOBAL_PROPRIETARY = 'fc'
    ##
    # PSBT_IN_NON_WITNESS_UTXO
    PSBT_IN_NON_WITNESS_UTXO = '00'
    ##
    # PSBT_IN_WITNESS_UTXO
    PSBT_IN_WITNESS_UTXO = '01'
    ##
    # PSBT_IN_PARTIAL_SIG
    PSBT_IN_PARTIAL_SIG = '02'
    ##
    # PSBT_IN_SIGHASH_TYPE
    PSBT_IN_SIGHASH_TYPE = '03'
    ##
    # PSBT_IN_REDEEM_SCRIPT
    PSBT_IN_REDEEM_SCRIPT = '04'
    ##
    # PSBT_IN_WITNESS_SCRIPT
    PSBT_IN_WITNESS_SCRIPT = '05'
    ##
    # PSBT_IN_BIP32_DERIVATION
    PSBT_IN_BIP32_DERIVATION = '06'
    ##
    # PSBT_IN_FINAL_SCRIPTSIG
    PSBT_IN_FINAL_SCRIPTSIG = '07'
    ##
    # PSBT_IN_FINAL_SCRIPTWITNESS
    PSBT_IN_FINAL_SCRIPTWITNESS = '08'
    ##
    # PSBT_IN_POR_COMMITMENT
    PSBT_IN_POR_COMMITMENT = '09'
    ##
    # PSBT_IN_RIPEMD160
    PSBT_IN_RIPEMD160 = '0a'
    ##
    # PSBT_IN_SHA256
    PSBT_IN_SHA256 = '0b'
    ##
    # PSBT_IN_HASH160
    PSBT_IN_HASH160 = '0c'
    ##
    # PSBT_IN_HASH256
    PSBT_IN_HASH256 = '0d'
    ##
    # PSBT_IN_PROPRIETARY
    PSBT_IN_PROPRIETARY = 'fc'
    ##
    # PSBT_OUT_REDEEM_SCRIPT
    PSBT_OUT_REDEEM_SCRIPT = '00'
    ##
    # PSBT_OUT_WITNESS_SCRIPT
    PSBT_OUT_WITNESS_SCRIPT = '01'
    ##
    # PSBT_OUT_BIP32_DERIVATION
    PSBT_OUT_BIP32_DERIVATION = '02'
    ##
    # PSBT_OUT_PROPRIETARY
    PSBT_OUT_PROPRIETARY = 'fc'


##
# @class PsbtAppendInputData
# @brief Psbt append input data class.
class PsbtAppendInputData:
    ##
    # @var txin
    # transaction input
    txin: TxIn
    ##
    # @var utxo_amount
    # witness utxo amount
    utxo_amount: int
    ##
    # @var utxo_locking_script
    # witness utxo locking script
    utxo_locking_script: str
    ##
    # @var utxo_tx
    # transaction hex
    utxo_tx: str
    ##
    # @var descriptor
    # descriptor
    descriptor: str
    ##
    # @var redeem_script
    # redeem script
    redeem_script: str
    ##
    # @var is_scripthash
    # is scripthash
    is_scripthash: bool

    ##
    # @brief constructor.
    # @param[in] outpoint       outpoint
    # @param[in] utxo           utxo
    # @param[in] descriptor     descriptor
    # @param[in] redeem_script  redeem script
    # @param[in] utxo_tx        utxo tx
    # @param[in] sequence       sequence
    # @param[in] network        network type
    def __init__(self, outpoint: 'OutPoint', utxo: 'TxOut',
                 descriptor: Union['Descriptor', str] = '',
                 redeem_script: Union['Script', str] = '',
                 utxo_tx: Union['Transaction', str] = '',
                 sequence: int = TxIn.SEQUENCE_DISABLE,
                 network=Network.MAINNET):
        _network = Network.get(network)
        _locking_script: Union['Script', str] = utxo.locking_script
        if utxo.address:
            if isinstance(utxo.address, Address):
                _locking_script = utxo.address.locking_script
            else:
                _locking_script = AddressUtil.parse(
                    utxo.address).locking_script
        self.utxo_tx = to_hex_string(utxo_tx)
        _script = to_hex_string(redeem_script)
        _desc = str(descriptor)
        is_scripthash = True if _script else False
        if (not is_scripthash) and _desc:
            desc_obj = descriptor if isinstance(
                descriptor, Descriptor) else parse_descriptor(_desc, _network)
            is_scripthash = True if desc_obj.data.redeem_script else False
        self.txin = TxIn(outpoint, sequence=sequence)
        self.descriptor = _desc
        self.utxo_amount = utxo.amount
        self.utxo_locking_script = to_hex_string(_locking_script)
        self.redeem_script = _script
        self.is_scripthash = is_scripthash


##
# @class PsbtAppendOutputData
# @brief Psbt append output data class.
class PsbtAppendOutputData:
    ##
    # @var amount
    # witness amount
    amount: int
    ##
    # @var locking_script
    # witness locking script
    locking_script: str
    ##
    # @var descriptor
    # descriptor
    descriptor: str
    ##
    # @var redeem_script
    # redeem script
    redeem_script: str
    ##
    # @var is_scripthash
    # is scripthash
    is_scripthash: bool

    ##
    # @brief constructor.
    # @param[in] amount             amount
    # @param[in] locking_script     locking script
    # @param[in] address            address
    # @param[in] descriptor         descriptor
    # @param[in] redeem_script      redeem script
    # @param[in] network            network type
    def __init__(self, amount: int,
                 locking_script: Union['Script', str] = '',
                 address: Union['Address', str] = '',
                 descriptor: Union['Descriptor', str] = '',
                 redeem_script: Union['Script', str] = '',
                 network=Network.MAINNET):
        _network = Network.get(network)
        _locking_script = locking_script
        if address:
            if isinstance(address, Address):
                _locking_script = address.locking_script
            else:
                _locking_script = AddressUtil.parse(address).locking_script
        _script = to_hex_string(redeem_script)
        _desc = str(descriptor)
        is_scripthash = True if _script else False
        if (not is_scripthash) and _desc:
            desc_obj = descriptor if isinstance(
                descriptor, Descriptor) else parse_descriptor(_desc, _network)
            is_scripthash = True if desc_obj.data.redeem_script else False
        self.descriptor = _desc
        self.amount = amount
        self.locking_script = to_hex_string(_locking_script)
        self.redeem_script = _script
        self.is_scripthash = is_scripthash


##
# @class Psbt
# @brief Psbt class.
class Psbt:
    ##
    # @var base64
    # base64 string
    base64: str
    ##
    # @var network
    # network type.
    network: 'Network'

    ##
    # @brief create psbt.
    # @param[in] tx_version     transaction version
    # @param[in] locktime       locktime
    # @param[in] network        network type
    # @return psbt object
    @classmethod
    def create(cls, tx_version: int = Transaction.DEFAULT_VERSION,
               locktime: int = 0,
               network=Network.MAINNET) -> 'Psbt':
        _network = Network.get(network)
        util = get_util()
        with util.create_handle() as handle:
            work_handle = util.call_func(
                'CfdCreatePsbtHandle', handle.get_handle(),
                _network.value, '', '', tx_version, locktime)
            with JobHandle(handle, work_handle,
                           'CfdFreePsbtHandle') as tx_handle:
                base64, _ = util.call_func(
                    'CfdGetPsbtData', handle.get_handle(),
                    tx_handle.get_handle())
                obj = Psbt('', _network)
                obj.base64 = base64
                return obj

    ##
    # @brief convert transaction.
    # @param[in] transaction        bitcoin transaction
    # @param[in] permit_sig_data    permit signature data
    # @param[in] network            network type
    # @return psbt object
    @classmethod
    def from_transaction(
            cls, transaction: 'Transaction',
            permit_sig_data: bool = False,
            network=Network.MAINNET) -> 'Psbt':
        tx = transaction if isinstance(
            transaction, Transaction) else Transaction(
            to_hex_string(transaction))
        _network = Network.get(network)
        util = get_util()
        with util.create_handle() as handle:
            if permit_sig_data:
                tx.clear_sign_data()
            else:

                for txin in tx.txin_list:
                    if str(txin.script_sig) or txin.witness_stack:
                        raise CfdError(error_code=1,
                                       message=NOT_PERMIT_SIG_ERR_MSG)

            work_handle = util.call_func(
                'CfdCreatePsbtHandle', handle.get_handle(),
                _network.value, '', tx.hex, 0, 0)
            with JobHandle(handle, work_handle,
                           'CfdFreePsbtHandle') as tx_handle:
                base64, _ = util.call_func(
                    'CfdGetPsbtData', handle.get_handle(),
                    tx_handle.get_handle())
            obj = Psbt('', _network)
            obj.base64 = base64
            return obj

    ##
    # @brief join psbts.
    # @param[in] psbts          psbt (object or list)
    # @param[in] network        network type
    # @return psbt object
    @classmethod
    def join_psbts(
            cls, psbts: List[Any],
            network=Network.MAINNET) -> 'Psbt':
        if len(psbts) < 0:
            raise CfdError(error_code=1, message='Error: list is empty.')

        psbt = Psbt(psbts[0], network)
        if len(psbts) == 1:
            return psbt

        psbt.join(psbts[1:])
        return psbt

    ##
    # @brief combine psbts.
    # @param[in] psbts          psbt (object or list)
    # @param[in] network        network type
    # @return psbt object
    @classmethod
    def combine_psbts(
            cls, psbts: List[Any],
            network=Network.MAINNET) -> 'Psbt':
        if len(psbts) < 0:
            raise CfdError(error_code=1, message='Error: list is empty.')

        psbt = Psbt(psbts[0], network)
        if len(psbts) == 1:
            return psbt

        psbt.combine(psbts[1:])
        return psbt

    ##
    # @brief decode psbt.
    # @param[in] psbt           psbt
    # @param[in] network        network type
    # @param[in] has_detail     detail output flag
    # @param[in] has_simple     simple output flag
    # @return json string
    @classmethod
    def parse_to_json(
            cls, psbt, network=Network.MAINNET,
            has_detail: bool = False, has_simple: bool = False) -> str:
        _network = Network.get(network)
        network_str = 'mainnet'
        if _network == Network.TESTNET:
            network_str = 'testnet'
        elif _network == Network.REGTEST:
            network_str = 'regtest'
        has_detail_str = 'true' if has_detail else 'false'
        has_simple_str = 'true' if has_simple else 'false'
        request_json = \
            f'{{"psbt":"{str(psbt)}","network":"{network_str}",' + \
            f'"hasDetail":{has_detail_str},"hasSimple":{has_simple_str}}}'
        util = get_util()
        with util.create_handle() as handle:
            return util.call_func(
                'CfdRequestExecuteJson', handle.get_handle(),
                'DecodePsbt', request_json)

    ##
    # @brief constructor.
    # @param[in] psbt           psbt string (base64 or bytes)
    # @param[in] network        network
    def __init__(self, psbt, network=Network.MAINNET):
        self.base64 = ''
        self.network = Network.get(network)
        if isinstance(psbt, str):
            _psbt = psbt
        elif isinstance(psbt, Psbt):
            _psbt = psbt.base64
        else:
            _psbt = to_hex_string(psbt)
        if len(_psbt) > 0:
            util = get_util()
            with util.create_handle() as handle:
                work_handle = util.call_func(
                    'CfdCreatePsbtHandle', handle.get_handle(),
                    self.network.value, _psbt, '', 0, 0)
                with JobHandle(handle, work_handle,
                               'CfdFreePsbtHandle') as tx_handle:
                    self.base64, _ = util.call_func(
                        'CfdGetPsbtData', handle.get_handle(),
                        tx_handle.get_handle())

    ##
    # @brief get string.
    # @return base64.
    def __str__(self) -> str:
        return self.base64

    ##
    # @brief get byte data.
    # @return byte data
    def get_bytes(self) -> 'ByteData':
        util = get_util()
        with util.create_handle() as handle:
            _hex = util.call_func(
                'CfdDecodeBase64', handle.get_handle(), self.base64)
            return ByteData(_hex)

    ##
    # @brief get global data.
    # @retval [0]   transaction
    # @retval [1]   psbt version
    # @retval [2]   transaction input count
    # @retval [3]   transaction output count
    def get_global_data(self) -> typing.Tuple['Transaction', int, int, int]:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            _version, _tx, _in_count, _out_count = util.call_func(
                'CfdGetPsbtGlobalData', handle.get_handle(),
                tx_handle.get_handle())
            return Transaction(_tx), _version, _in_count, _out_count

    ##
    # @brief get transaction.
    # @return transaction
    def get_tx(self) -> 'Transaction':
        _ret = self.get_global_data()
        return _ret[0]

    ##
    # @brief get transaction input/output count.
    # @retval [0] txin count
    # @retval [1] txout count
    def get_tx_count(self) -> Tuple[int, int]:
        tx = self.get_tx()
        return len(tx.txin_list), len(tx.txout_list)

    ##
    # @brief get psbt version.
    # @return psbt version
    def get_version(self) -> int:
        _ret = self.get_global_data()
        return _ret[1]

    ##
    # @brief join.
    # @param[in] psbts     psbt (object or list)
    # @return void
    def join(self, psbts) -> None:
        util = get_util()

        def join_func(handle, psbt_handle, psbt):
            if isinstance(psbt, Psbt):
                _psbt = psbt.base64
            else:
                _psbt = str(psbt)
            util.call_func('CfdJoinPsbt', handle.get_handle(),
                           psbt_handle.get_handle(), _psbt)

        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            if isinstance(psbts, list):
                for psbt in psbts:
                    join_func(handle, tx_handle, psbt)
            else:
                join_func(handle, tx_handle, psbts)
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief sign.
    # @param[in] privkey        privkey
    # @param[in] has_grind_r    grind-r flag
    # @return void
    def sign(self, privkey, has_grind_r: bool = True) -> None:
        util = get_util()
        if isinstance(privkey, Privkey):
            _privkey = privkey
        elif isinstance(privkey, str) and (len(privkey) != 64):
            _privkey = Privkey(wif=privkey)
        else:
            _privkey = Privkey(hex=privkey)
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            util.call_func(
                'CfdSignPsbt', handle.get_handle(),
                tx_handle.get_handle(), str(_privkey), has_grind_r)
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief combine.
    # @param[in] psbts     psbt (object or list)
    # @return void
    def combine(self, psbts) -> None:
        util = get_util()

        def combine_func(handle, psbt_handle, psbt):
            if isinstance(psbt, Psbt):
                _psbt = psbt.base64
            else:
                _psbt = str(psbt)
            util.call_func(
                'CfdCombinePsbt', handle.get_handle(),
                psbt_handle.get_handle(), _psbt)

        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            if isinstance(psbts, list):
                for psbt in psbts:
                    combine_func(handle, tx_handle, psbt)
            else:
                combine_func(handle, tx_handle, psbts)
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief finalize.
    # @return void
    def finalize(self) -> None:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            util.call_func(
                'CfdFinalizePsbt', handle.get_handle(),
                tx_handle.get_handle())
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief extract.
    # @param[in] exec_finalize     execute finalize (if finalized is false)
    # @return Transaction
    def extract(self, exec_finalize: bool = True) -> 'Transaction':
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            is_finalized = False
            try:
                util.call_func('CfdIsFinalizedPsbt', handle.get_handle(),
                               tx_handle.get_handle())
                is_finalized = True
            except CfdError as err:
                if err.error_code != CfdErrorCode.SIGN_VERIFICATION.value:
                    raise err
            if exec_finalize and (not is_finalized):
                util.call_func('CfdFinalizePsbt', handle.get_handle(),
                               tx_handle.get_handle())
                self._update_base64(util, handle, tx_handle)
            _tx = util.call_func(
                'CfdExtractPsbtTransaction', handle.get_handle(),
                tx_handle.get_handle())
            return Transaction(_tx)

    ##
    # @brief check finalized.
    # @retval True   finalized
    # @retval False  not finalized
    def is_finalized(self) -> bool:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            try:
                util.call_func('CfdIsFinalizedPsbt', handle.get_handle(),
                               tx_handle.get_handle())
                return True
            except CfdError as err:
                if err.error_code != CfdErrorCode.SIGN_VERIFICATION.value:
                    raise err
            return False

    ##
    # @brief check finalized.
    # @param[in] outpoint     outpoint
    # @retval True   finalized
    # @retval False  not finalized
    def is_finalized_input(self, outpoint: 'OutPoint') -> bool:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            try:
                util.call_func('CfdIsFinalizedPsbtInput', handle.get_handle(),
                               tx_handle.get_handle(), str(outpoint.txid),
                               outpoint.vout)
                return True
            except CfdError as err:
                if err.error_code != CfdErrorCode.SIGN_VERIFICATION.value:
                    raise err
            return False

    ##
    # @brief add input.
    # @param[in] outpoint       outpoint
    # @param[in] utxo           utxo
    # @param[in] descriptor     descriptor
    # @param[in] redeem_script  redeem script
    # @param[in] utxo_tx        utxo tx
    # @param[in] sequence       sequence
    # @return void
    def add_input(self, outpoint: 'OutPoint', utxo: 'TxOut' = TxOut(0),
                  descriptor: Union['Descriptor', str] = '',
                  redeem_script: Union['Script', str] = '',
                  utxo_tx: Union['Transaction', str] = '',
                  sequence: int = TxIn.SEQUENCE_DISABLE) -> None:
        input = PsbtAppendInputData(outpoint, utxo, descriptor, redeem_script,
                                    utxo_tx, sequence, self.network)
        self.add(inputs=[input])

    ##
    # @brief add output.
    # @param[in] amount             amount
    # @param[in] locking_script     locking script
    # @param[in] address            address
    # @param[in] descriptor         descriptor
    # @param[in] redeem_script      redeem script
    # @return void
    def add_output(self, amount: int,
                   locking_script: Union['Script', str] = '',
                   address: Union['Address', str] = '',
                   descriptor: Union['Descriptor', str] = '',
                   redeem_script: Union['Script', str] = '') -> None:
        output = PsbtAppendOutputData(amount, locking_script, address,
                                      descriptor, redeem_script, self.network)
        self.add(outputs=[output])

    ##
    # @brief add input/output list.
    # @param[in] inputs     input list.
    # @param[in] outputs    output list.
    # @return void
    def add(self, inputs: List['PsbtAppendInputData'] = [],
            outputs: List['PsbtAppendOutputData'] = []) -> None:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            for input in inputs:
                if input.is_scripthash:
                    util.call_func(
                        'CfdAddPsbtTxInWithScript', handle.get_handle(),
                        tx_handle.get_handle(), str(input.txin.outpoint.txid),
                        input.txin.outpoint.vout,
                        input.txin.sequence, input.utxo_amount,
                        input.utxo_locking_script,
                        input.redeem_script, input.descriptor, input.utxo_tx)
                else:
                    util.call_func(
                        'CfdAddPsbtTxInWithPubkey', handle.get_handle(),
                        tx_handle.get_handle(), str(input.txin.outpoint.txid),
                        input.txin.outpoint.vout,
                        input.txin.sequence, input.utxo_amount,
                        input.utxo_locking_script,
                        input.descriptor, input.utxo_tx)
            for output in outputs:
                if output.is_scripthash:
                    _ = util.call_func(
                        'CfdAddPsbtTxOutWithScript',
                        handle.get_handle(),
                        tx_handle.get_handle(),
                        output.amount,
                        output.locking_script,
                        output.redeem_script,
                        output.descriptor)
                else:
                    _ = util.call_func(
                        'CfdAddPsbtTxOutWithPubkey',
                        handle.get_handle(),
                        tx_handle.get_handle(),
                        output.amount,
                        output.locking_script,
                        output.descriptor)
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief verify sign.
    # @param[in] outpoint       outpoint
    # @return void
    def verify(self, outpoint: Optional['OutPoint'] = None) -> None:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            if isinstance(outpoint, OutPoint):
                util.call_func(
                    'CfdVerifyPsbtTxIn', handle.get_handle(),
                    tx_handle.get_handle(), str(
                        outpoint.txid), outpoint.vout)
                return
            # all check
            _, _tx, _, _ = util.call_func(
                'CfdGetPsbtGlobalData', handle.get_handle(),
                tx_handle.get_handle())
            tx = Transaction(_tx)
            for txin in tx.txin_list:
                util.call_func('CfdVerifyPsbtTxIn', handle.get_handle(),
                               tx_handle.get_handle(), str(txin.outpoint.txid),
                               txin.outpoint.vout)

    ##
    # @brief fund psbt.
    # @param[in] utxo_list              utxo list
    # @param[in] reserved_address_descriptor  \
    #                sending reserved address descriptor
    # @param[in] effective_fee_rate     effective fee rate
    # @param[in] long_term_fee_rate     long term fee rate
    # @param[in] dust_fee_rate          dust fee rate
    # @param[in] knapsack_min_change    minimum change threshold for knapsack
    # @return fee amount
    def fund(self, utxo_list: List['UtxoData'],
             reserved_address_descriptor: Union['Descriptor', str],
             effective_fee_rate: float = 20.0,
             long_term_fee_rate: float = 20.0,
             dust_fee_rate: float = -1.0,
             knapsack_min_change: int = -1) -> int:
        util = get_util()

        def set_opt(handle, tx_handle, key, i_val=0, f_val=0, b_val=False):
            util.call_func(
                'CfdSetOptionFundPsbt', handle.get_handle(),
                tx_handle.get_handle(), int(key.value),
                int(i_val), float(f_val), b_val)

        with util.create_handle() as handle, self._get_handle(
            util, handle) as tx_handle,\
                JobHandle(handle, util.call_func(
                    'CfdInitializeFundPsbt', handle.get_handle()),
                    'CfdFreeFundPsbt') as fund_handle:
            for utxo in utxo_list:
                util.call_func(
                    'CfdFundPsbtAddToUtxoList',
                    handle.get_handle(), fund_handle.get_handle(),
                    str(utxo.outpoint.txid), utxo.outpoint.vout,
                    utxo.amount, '', str(utxo.descriptor),
                    to_hex_string(utxo.scriptsig_template), '')

            set_opt(handle, fund_handle, _FundPsbtOpt.EFFECTIVE_FEE_RATE,
                    f_val=effective_fee_rate)
            set_opt(handle, fund_handle, _FundPsbtOpt.DUST_FEE_RATE,
                    f_val=dust_fee_rate)
            set_opt(handle, fund_handle, _FundPsbtOpt.LONG_TERM_FEE_RATE,
                    f_val=long_term_fee_rate)
            set_opt(handle, fund_handle, _FundPsbtOpt.KNAPSACK_MIN_CHANGE,
                    i_val=knapsack_min_change)

            fee, _ = util.call_func(
                'CfdFinalizeFundPsbt', handle.get_handle(),
                tx_handle.get_handle(),
                fund_handle.get_handle(), str(reserved_address_descriptor))
            self._update_base64(util, handle, tx_handle)
            return fee

    ##
    # @brief get input index.
    # @param[in] outpoint       outpoint
    # @return input index
    def get_input_index(self, outpoint: 'OutPoint') -> int:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            return util.call_func(
                'CfdGetPsbtTxInIndex', handle.get_handle(),
                tx_handle.get_handle(), str(
                    outpoint.txid), outpoint.vout)

    ##
    # @brief get input outpoint.
    # @param[in] index      input index
    # @return input outpoint
    def get_input_outpoint(self, index: int) -> 'OutPoint':
        tx = self.get_tx()
        if index >= len(tx.txin_list):
            raise CfdError(error_code=3, message='Error: out of range.')
        return tx.txin_list[index].outpoint

    ##
    # @brief set input utxo.
    # @param[in] outpoint       outpoint
    # @param[in] utxo           utxo
    # @param[in] utxo_tx        utxo full tx
    # @return void
    def set_input_utxo(self, outpoint: 'OutPoint', utxo: 'TxOut' = TxOut(0),
                       utxo_tx: Union['Transaction', str] = '') -> None:
        _locking_script: Union['Script', str] = utxo.locking_script
        if utxo.address:
            if isinstance(utxo.address, Address):
                _locking_script = utxo.address.locking_script
            else:
                _locking_script = AddressUtil.parse(
                    utxo.address).locking_script
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            util.call_func(
                'CfdSetPsbtTxInUtxo', handle.get_handle(),
                tx_handle.get_handle(),
                str(outpoint.txid), outpoint.vout, utxo.amount,
                to_hex_string(_locking_script), to_hex_string(utxo_tx))
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief set input bip32 key.
    # @param[in] outpoint       outpoint
    # @param[in] pubkey         pubkey or descriptorPubkey
    # @param[in] fingerprint    fingerprint
    # @param[in] bip32_path     bip32 path
    # @param[in] key_data       keyData object
    # @return void
    def set_input_bip32_key(
            self,
            outpoint: 'OutPoint',
            pubkey=None,
            fingerprint='00000000',
            bip32_path: str = '',
            key_data: Optional['KeyData'] = None) -> None:
        if isinstance(key_data, KeyData):
            pk = to_hex_string(key_data.pubkey)
            fp = key_data.fingerprint if key_data.fingerprint else ''
            path = key_data.bip32_path
        elif pubkey is None:
            raise CfdError(error_code=1, message='Error: pubkey is None.')
        else:
            pk = pubkey if isinstance(pubkey, str) else to_hex_string(pubkey)
            fp = fingerprint if fingerprint else ''
            path = bip32_path
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            util.call_func(
                'CfdSetPsbtTxInBip32Pubkey', handle.get_handle(),
                tx_handle.get_handle(), str(
                    outpoint.txid), outpoint.vout, pk,
                to_hex_string(fp), str(path))
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief set input signature.
    # @param[in] outpoint       outpoint
    # @param[in] pubkey         pubkey or descriptorPubkey
    # @param[in] signature      signature
    # @param[in] sign_data      sign parameter object
    # @return void
    def set_input_signature(
            self,
            outpoint: 'OutPoint',
            pubkey=None,
            signature=None,
            sign_data: Optional['SignParameter'] = None) -> None:
        if isinstance(sign_data, SignParameter):
            pk = sign_data.related_pubkey
            sig = sign_data.hex
        elif pubkey is None:
            raise CfdError(error_code=1, message='Error: pubkey is None.')
        elif signature is None:
            raise CfdError(
                error_code=1, message='Error: signature is None.')
        else:
            pk = pubkey
            sig = signature
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            util.call_func('CfdSetPsbtSignature',
                           handle.get_handle(),
                           tx_handle.get_handle(),
                           str(outpoint.txid),
                           outpoint.vout,
                           to_hex_string(pk),
                           to_hex_string(sig))
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief set input sighash type.
    # @param[in] outpoint       outpoint
    # @param[in] sighash_type   sighash type
    # @return void
    def set_input_sighash_type(self, outpoint: 'OutPoint',
                               sighash_type: 'SigHashType') -> None:
        sighash = SigHashType.get(sighash_type)
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            util.call_func(
                'CfdSetPsbtSighashType', handle.get_handle(),
                tx_handle.get_handle(), str(
                    outpoint.txid), outpoint.vout, sighash.get_type())
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief set input finalize script.
    # @param[in] outpoint       outpoint
    # @param[in] data           finalize script
    # @return void
    def set_input_finalize(self, outpoint: 'OutPoint',
                           data: Union[List['Script'], Script]) -> None:
        _script: Union['Script', str] = ''
        if isinstance(data, list):
            script_list = []
            for script in data:
                if not isinstance(script, Script):
                    pass
                elif ' ' in script.asm:
                    script_list.append(script.hex)
                else:  # single data
                    script_list.append(script.asm)
            _script = Script.from_asm(script_list)
        elif isinstance(data, Script):
            _script = data

        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            util.call_func(
                'CfdSetPsbtFinalizeScript', handle.get_handle(),
                tx_handle.get_handle(), str(
                    outpoint.txid), outpoint.vout, to_hex_string(_script))
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief set input finalize script.
    # @param[in] outpoint       outpoint
    # @param[in] redeem_script  redeem script
    # @param[in] index          input index
    # @return void
    def set_input_script(self, outpoint: Optional['OutPoint'],
                         redeem_script, index: int = 0) -> None:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            if isinstance(outpoint, OutPoint):
                index = util.call_func(
                    'CfdGetPsbtTxInIndex', handle.get_handle(),
                    tx_handle.get_handle(), str(
                        outpoint.txid), outpoint.vout)
            self._set_redeem_script(
                util,
                handle,
                tx_handle,
                _PsbtRecordType.INPUT,
                index,
                redeem_script)
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief set input record.
    # @param[in] outpoint       outpoint
    # @param[in] key            record key
    # @param[in] value          record value
    # @param[in] index          input index
    # @return void
    def set_input_record(self, outpoint: Optional['OutPoint'],
                         key, value, index: int = 0) -> None:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            if isinstance(outpoint, OutPoint):
                index = util.call_func(
                    'CfdGetPsbtTxInIndex', handle.get_handle(),
                    tx_handle.get_handle(), str(
                        outpoint.txid), outpoint.vout)
            self._set_record(util, handle, tx_handle,
                             _PsbtRecordType.INPUT, index, key, value)
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief set input non witness utxo.
    # @param[in] outpoint       outpoint
    # @param[in] transaction    non witness utxo.
    # @param[in] index          input index
    # @return void
    def set_input_non_witness_utxo(
            self,
            outpoint: 'OutPoint',
            transaction: 'Transaction',
            index: int = 0) -> None:
        self.set_input_record(
            outpoint,
            PsbtDefinition.PSBT_IN_NON_WITNESS_UTXO,
            transaction,
            index)

    ##
    # @brief set input redeem script.
    # @param[in] outpoint       outpoint
    # @param[in] redeem_script  redeem script
    # @param[in] index          input index
    # @return void
    def set_input_redeem_script(
            self,
            outpoint: 'OutPoint',
            redeem_script,
            index: int = 0) -> None:
        self.set_input_record(
            outpoint,
            PsbtDefinition.PSBT_IN_REDEEM_SCRIPT,
            redeem_script,
            index)

    ##
    # @brief set input witness script.
    # @param[in] outpoint           outpoint
    # @param[in] witness_script     witness script
    # @param[in] index              input index
    # @return void
    def set_input_witness_script(
            self,
            outpoint: 'OutPoint',
            witness_script,
            index: int = 0) -> None:
        self.set_input_record(
            outpoint,
            PsbtDefinition.PSBT_IN_WITNESS_SCRIPT,
            witness_script,
            index)

    ##
    # @brief set input final scriptsig.
    # @param[in] outpoint       outpoint
    # @param[in] scriptsig      scriptsig
    # @param[in] index          input index
    # @return void
    def set_input_final_scriptsig(
            self,
            outpoint: 'OutPoint',
            scriptsig,
            index: int = 0) -> None:
        self.set_input_record(
            outpoint, PsbtDefinition.PSBT_IN_FINAL_SCRIPTSIG, scriptsig, index)

    ##
    # @brief get input sighash type.
    # @param[in] outpoint       outpoint
    # @return sighash type
    def get_input_sighash_type(self, outpoint: 'OutPoint') -> 'SigHashType':
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            sighashtype = util.call_func(
                'CfdGetPsbtSighashType', handle.get_handle(),
                tx_handle.get_handle(), str(
                    outpoint.txid), outpoint.vout)
            if sighashtype == 0:
                raise CfdError(error_code=8, message='Error: not found.')
            return SigHashType.get(sighashtype)

    ##
    # @brief get input signature.
    # @param[in] outpoint       outpoint
    # @param[in] pubkey         pubkey
    # @return signature
    def get_input_signature(
            self,
            outpoint: 'OutPoint',
            pubkey) -> 'SignParameter':
        pk = pubkey if isinstance(
            pubkey, Pubkey) else Pubkey(to_hex_string(pubkey))
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            index = util.call_func(
                'CfdGetPsbtTxInIndex', handle.get_handle(),
                tx_handle.get_handle(), str(
                    outpoint.txid), outpoint.vout)
            value = self._get_pubkey_record(
                util,
                handle,
                tx_handle,
                _PsbtRecordKind.INPUT_SIGNATURE,
                index,
                pubkey)
            return SignParameter(value, related_pubkey=pk)

    ##
    # @brief find input signature.
    # @param[in] outpoint       outpoint
    # @param[in] pubkey         pubkey
    # @retval true      find
    # @retval false     not found
    def is_find_input_signature(self, outpoint: 'OutPoint', pubkey) -> bool:
        pk = pubkey if isinstance(
            pubkey, Pubkey) else Pubkey(to_hex_string(pubkey))
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            index = util.call_func(
                'CfdGetPsbtTxInIndex', handle.get_handle(),
                tx_handle.get_handle(), str(
                    outpoint.txid), outpoint.vout)
            return self._is_find_pubkey(
                util,
                handle,
                tx_handle,
                _PsbtRecordKind.INPUT_SIGNATURE,
                index,
                pk)

    ##
    # @brief get input signatures.
    # @param[in] outpoint       outpoint
    # @return signature list
    def get_input_signature_list(
            self, outpoint: 'OutPoint') -> List['SignParameter']:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            index = util.call_func(
                'CfdGetPsbtTxInIndex', handle.get_handle(),
                tx_handle.get_handle(), str(
                    outpoint.txid), outpoint.vout)
            pk_list, _ = self._get_pubkey_list(
                util, handle, tx_handle,
                _PsbtRecordKind.INPUT_SIGNATURE, index)
            sig_list = []
            for key in pk_list:
                value = self._get_pubkey_record(
                    util, handle, tx_handle, _PsbtRecordKind.INPUT_SIGNATURE,
                    index, key)
                sig_list.append(SignParameter(
                    value, related_pubkey=Pubkey(key)))
            return sig_list

    ##
    # @brief get input bip32 key.
    # @param[in] outpoint       outpoint
    # @param[in] pubkey         pubkey
    # @return bip32 key
    def get_input_bip32_data(self, outpoint: 'OutPoint', pubkey) -> 'KeyData':
        pk = pubkey if isinstance(
            pubkey, Pubkey) else Pubkey(to_hex_string(pubkey))
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            index = util.call_func(
                'CfdGetPsbtTxInIndex', handle.get_handle(),
                tx_handle.get_handle(), str(
                    outpoint.txid), outpoint.vout)
            fp, path = self._get_pubkey_bip32_data(
                util, handle, tx_handle, _PsbtRecordKind.INPUT_BIP32,
                index, pubkey)
            return KeyData(pk, fp, path)

    ##
    # @brief find input bip32 key.
    # @param[in] outpoint       outpoint
    # @param[in] pubkey         pubkey
    # @retval true      find
    # @retval false     not found
    def is_find_input_bip32_data(self, outpoint: 'OutPoint', pubkey) -> bool:
        pk = pubkey if isinstance(
            pubkey, Pubkey) else Pubkey(to_hex_string(pubkey))
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            index = util.call_func(
                'CfdGetPsbtTxInIndex', handle.get_handle(),
                tx_handle.get_handle(), str(
                    outpoint.txid), outpoint.vout)
            return self._is_find_pubkey(
                util,
                handle,
                tx_handle,
                _PsbtRecordKind.INPUT_BIP32,
                index,
                pk)

    ##
    # @brief get input bip32 keys.
    # @param[in] outpoint       outpoint
    # @return bip32 list
    def get_input_bip32_list(self, outpoint: 'OutPoint') -> List['KeyData']:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            index = util.call_func(
                'CfdGetPsbtTxInIndex', handle.get_handle(),
                tx_handle.get_handle(), str(
                    outpoint.txid), outpoint.vout)
            return self._get_bip32_pubkey_list(
                util, handle, tx_handle, _PsbtRecordKind.INPUT_BIP32, index)

    ##
    # @brief get input utxo data.
    # @param[in] outpoint       outpoint
    # @retval [0]  utxo data
    # @retval [1]  locking script (or None)
    # @retval [2]  redeem script (or None)
    # @retval [3]  utxo transaction  (or None)
    def get_input_utxo_data(
        self,
        outpoint: 'OutPoint') -> Tuple['UtxoData', Optional['Script'],
                                       Optional['Script'],
                                       Optional['Transaction']]:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            amount, locking_script, redeem_script, descriptor, \
                full_tx = util.call_func(
                    'CfdGetPsbtUtxoData', handle.get_handle(),
                    tx_handle.get_handle(),
                    str(outpoint.txid), outpoint.vout)
            tx = Transaction(full_tx) if full_tx else None
            script = Script(redeem_script) if redeem_script else None
            scriptpubkey = Script(locking_script) if locking_script else None
            utxo = UtxoData(outpoint,
                            amount=amount, descriptor=descriptor)
            return utxo, scriptpubkey, script, tx

    ##
    # @brief get input data by index.
    # @param[in] index      input index
    # @retval [0]   outpoint
    # @retval [1]   utxo amount
    # @retval [2]   utxo locking script (or None)
    # @retval [3]   redeem script (or None)
    # @retval [4]   descriptor
    # @retval [5]   utxo full transaction (or None)
    def get_input_data_by_index(
        self, index: int) -> Tuple[
            'OutPoint', int, Optional['Script'],
            Optional['Script'], str, Optional['Transaction']]:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            txid, vout, amount, locking_script, redeem_script,\
                descriptor, full_tx = util.call_func(
                    'CfdGetPsbtUtxoDataByIndex', handle.get_handle(),
                    tx_handle.get_handle(), index)
            tx = Transaction(full_tx) if full_tx else None
            script = Script(redeem_script) if redeem_script else None
            scriptpubkey = Script(locking_script) if locking_script else None
            outpoint = OutPoint(txid, vout)
            return outpoint, amount, scriptpubkey, script, descriptor, tx

    ##
    # @brief get input final script witness.
    # @param[in] outpoint       outpoint
    # @return script witness
    def get_input_final_witness(
            self, outpoint: 'OutPoint') -> List['ByteData']:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            index = util.call_func(
                'CfdGetPsbtTxInIndex', handle.get_handle(),
                tx_handle.get_handle(), str(
                    outpoint.txid), outpoint.vout)
            return self._get_bytedata_list(
                util, handle, tx_handle,
                _PsbtRecordKind.INPUT_FINAL_WITNESS, index)

    ##
    # @brief get input unknown key list.
    # @param[in] outpoint       outpoint
    # @return unknown key list
    def get_input_unknown_keys(self, outpoint: 'OutPoint') -> List['ByteData']:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            index = util.call_func(
                'CfdGetPsbtTxInIndex', handle.get_handle(),
                tx_handle.get_handle(), str(
                    outpoint.txid), outpoint.vout)
            return self._get_bytedata_list(
                util, handle, tx_handle,
                _PsbtRecordKind.INPUT_UNKNOWN_KEYS, index)

    ##
    # @brief get input record.
    # @param[in] outpoint       outpoint
    # @param[in] key            record key
    # @return unknown key list
    def get_input_record(self, outpoint: 'OutPoint', key) -> 'ByteData':
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            index = util.call_func(
                'CfdGetPsbtTxInIndex', handle.get_handle(),
                tx_handle.get_handle(), str(
                    outpoint.txid), outpoint.vout)
            return self._get_record(util, handle, tx_handle,
                                    _PsbtRecordType.INPUT, index, key)

    ##
    # @brief find input record.
    # @param[in] outpoint       outpoint
    # @param[in] key            record key
    # @retval true      find
    # @retval false     not found
    def is_find_input_record(self, outpoint: 'OutPoint', key) -> bool:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            index = util.call_func(
                'CfdGetPsbtTxInIndex', handle.get_handle(),
                tx_handle.get_handle(), str(
                    outpoint.txid), outpoint.vout)
            return self._is_find_record(util, handle, tx_handle,
                                        _PsbtRecordType.INPUT, index, key)

    ##
    # @brief get input redeem script.
    # @param[in] outpoint       outpoint
    # @return redeem script
    def get_input_redeem_script(self, outpoint: 'OutPoint') -> 'Script':
        value = self.get_input_record(
            outpoint, PsbtDefinition.PSBT_IN_REDEEM_SCRIPT)
        return Script(value)

    ##
    # @brief get input witness script.
    # @param[in] outpoint       outpoint
    # @return witness script
    def get_input_witness_script(self, outpoint: 'OutPoint') -> 'Script':
        value = self.get_input_record(
            outpoint, PsbtDefinition.PSBT_IN_WITNESS_SCRIPT)
        return Script(value)

    ##
    # @brief get input final scriptsig.
    # @param[in] outpoint       outpoint
    # @return final scriptsig
    def get_input_final_scriptsig(self, outpoint: 'OutPoint') -> 'Script':
        value = self.get_input_record(
            outpoint, PsbtDefinition.PSBT_IN_FINAL_SCRIPTSIG)
        return Script(value)

    ##
    # @brief clear input sign data.
    # @param[in] outpoint       outpoint
    # @return void
    def clear_input_sign_data(self, outpoint: 'OutPoint') -> None:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            util.call_func(
                'CfdClearPsbtSignData', handle.get_handle(),
                tx_handle.get_handle(), str(
                    outpoint.txid), outpoint.vout)
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief set output bip32 key data.
    # @param[in] index          output index
    # @param[in] pubkey         pubkey or descriptorPubkey
    # @param[in] fingerprint    fingerprint
    # @param[in] bip32_path     bip32 path
    # @param[in] key_data       keyData object
    # @return void
    def set_output_bip32_key(
            self,
            index: int,
            pubkey=None,
            fingerprint=None,
            bip32_path: str = '',
            key_data: Optional['KeyData'] = None) -> None:
        if isinstance(key_data, KeyData):
            pk = to_hex_string(key_data.pubkey)
            fp = key_data.fingerprint if key_data.fingerprint else ''
            path = key_data.bip32_path
        elif pubkey is None:
            raise CfdError(error_code=1, message='Error: pubkey is None.')
        else:
            pk = pubkey if isinstance(pubkey, str) else to_hex_string(pubkey)
            fp = fingerprint if fingerprint else ''
            path = bip32_path
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            util.call_func(
                'CfdSetPsbtTxOutBip32Pubkey',
                handle.get_handle(),
                tx_handle.get_handle(),
                index,
                pk,
                to_hex_string(fp),
                path)
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief set output redeem script (or witness script).
    # @param[in] index          output index
    # @param[in] redeem_script  redeem script
    # @return void
    def set_output_script(self, index: int, redeem_script) -> None:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            self._set_redeem_script(
                util,
                handle,
                tx_handle,
                _PsbtRecordType.OUTPUT,
                index,
                redeem_script)
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief set output record.
    # @param[in] index          output index
    # @param[in] key            record key
    # @param[in] value          record value
    # @return void
    def set_output_record(self, index: int, key, value) -> None:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            self._set_record(util, handle, tx_handle,
                             _PsbtRecordType.OUTPUT, index, key, value)
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief set output redeem script.
    # @param[in] index          output index
    # @param[in] redeem_script  redeem script
    # @return void
    def set_output_redeem_script(self, index: int, redeem_script) -> None:
        self.set_output_record(
            index, PsbtDefinition.PSBT_OUT_REDEEM_SCRIPT, redeem_script)

    ##
    # @brief set output witness script.
    # @param[in] index              output index
    # @param[in] witness_script     witness script
    # @return void
    def set_output_witness_script(self, index: int, witness_script) -> None:
        self.set_output_record(
            index, PsbtDefinition.PSBT_OUT_WITNESS_SCRIPT, witness_script)

    ##
    # @brief get output bip32 key data.
    # @param[in] index          output index
    # @param[in] pubkey         pubkey
    # @return keyData object
    def get_output_bip32_data(self, index: int, pubkey) -> 'KeyData':
        pk = pubkey if isinstance(
            pubkey, Pubkey) else Pubkey(to_hex_string(pubkey))
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            fp, path = self._get_pubkey_bip32_data(
                util, handle, tx_handle,
                _PsbtRecordKind.OUTPUT_BIP32, index, pubkey)
            return KeyData(pk, fp, path)

    ##
    # @brief find output bip32 key data.
    # @param[in] index          output index
    # @param[in] pubkey         pubkey
    # @retval true      find
    # @retval false     not found
    def is_find_output_bip32_data(self, index: int, pubkey) -> bool:
        pk = pubkey if isinstance(
            pubkey, Pubkey) else Pubkey(to_hex_string(pubkey))
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            return self._is_find_pubkey(
                util,
                handle,
                tx_handle,
                _PsbtRecordKind.OUTPUT_BIP32,
                index,
                pk)

    ##
    # @brief get output bip32 key list.
    # @param[in] index          output index
    # @return keyData object list
    def get_output_bip32_list(self, index: int) -> List['KeyData']:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            return self._get_bip32_pubkey_list(
                util, handle, tx_handle, _PsbtRecordKind.OUTPUT_BIP32, index)

    ##
    # @brief get output unknown key list.
    # @param[in] index          output index
    # @return keyData object list
    def get_output_unknown_keys(self, index: int) -> List['ByteData']:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            return self._get_bytedata_list(
                util, handle, tx_handle,
                _PsbtRecordKind.OUTPUT_UNKNOWN_KEYS, index)

    ##
    # @brief get output record.
    # @param[in] index      output index
    # @param[in] key        record key
    # @return record value
    def get_output_record(self, index: int, key) -> 'ByteData':
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            return self._get_record(util, handle, tx_handle,
                                    _PsbtRecordType.OUTPUT, index, key)

    ##
    # @brief find output record.
    # @param[in] index      output index
    # @param[in] key        record key
    # @retval true      find
    # @retval false     not found
    def is_find_output_record(self, index: int, key) -> bool:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            return self._is_find_record(util, handle, tx_handle,
                                        _PsbtRecordType.OUTPUT, index, key)

    ##
    # @brief get output redeem script.
    # @param[in] index      output index
    # @return redeem script
    def get_output_redeem_script(self, index: int) -> 'Script':
        value = self.get_output_record(
            index, PsbtDefinition.PSBT_OUT_REDEEM_SCRIPT)
        return Script(value)

    ##
    # @brief get output witness script.
    # @param[in] index      output index
    # @return witness script
    def get_output_witness_script(self, index: int) -> 'Script':
        value = self.get_output_record(
            index, PsbtDefinition.PSBT_OUT_WITNESS_SCRIPT)
        return Script(value)

    ##
    # @brief set global xpub.
    # @param[in] ext_pubkey     ext pubkey or descriptorExtPubkey
    # @param[in] fingerprint    fingerprint
    # @param[in] bip32_path     bip32 path
    # @param[in] key_data       keyData object
    # @return void
    def set_global_xpub(
            self,
            ext_pubkey=None,
            fingerprint=None,
            bip32_path: str = '',
            key_data: Optional['KeyData'] = None) -> None:
        if isinstance(key_data, KeyData):
            if key_data.ext_pubkey is None:
                raise CfdError(
                    error_code=1, message='Error: ext_pubkey is None.')
            pk = key_data.ext_pubkey
            fp = key_data.fingerprint if key_data.fingerprint else ''
            path = key_data.bip32_path
        elif ext_pubkey is None:
            raise CfdError(error_code=1,
                           message='Error: ext_pubkey is None.')
        else:
            pk = ext_pubkey
            fp = fingerprint if fingerprint else ''
            path = bip32_path
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            util.call_func(
                'CfdAddPsbtGlobalXpubkey',
                handle.get_handle(),
                tx_handle.get_handle(),
                str(pk),
                to_hex_string(fp),
                path)
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief set global record.
    # @param[in] key            record key
    # @param[in] value          record value
    # @return void
    def set_global_record(self, key, value) -> None:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            self._set_record(util, handle, tx_handle,
                             _PsbtRecordType.GLOBAL, 0, key, value)
            self._update_base64(util, handle, tx_handle)

    ##
    # @brief get global xpub.
    # @param[in] xpub           ext pubkey
    # @return keyData object
    def get_global_xpub(self, xpub) -> 'KeyData':
        pk = xpub if isinstance(xpub, ExtPubkey) else ExtPubkey(xpub)
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            fp, path = self._get_pubkey_bip32_data(
                util, handle, tx_handle, _PsbtRecordKind.GLOBAL_XPUB, 0, pk)
            return KeyData(pk, fp, path)

    ##
    # @brief find global xpub.
    # @param[in] xpub           ext pubkey
    # @retval true      find
    # @retval false     not found
    def is_find_global_xpub(self, xpub) -> bool:
        pk = xpub if isinstance(xpub, ExtPubkey) else ExtPubkey(xpub)
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            return self._is_find_pubkey(
                util, handle, tx_handle, _PsbtRecordKind.GLOBAL_XPUB, 0, pk)

    ##
    # @brief get global xpub list.
    # @return keyData object list
    def get_global_xpub_list(self) -> List['KeyData']:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            return self._get_bip32_pubkey_list(
                util, handle, tx_handle, _PsbtRecordKind.GLOBAL_XPUB, 0)

    ##
    # @brief get global unknown list.
    # @return unknown key list (contains global xpub keys)
    def get_global_unknown_keys(self) -> List['ByteData']:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            return self._get_bytedata_list(
                util, handle, tx_handle,
                _PsbtRecordKind.GLOBAL_UNKNOWN_KEYS, 0)

    ##
    # @brief get global record.
    # @param[in] key        record key
    # @return record value
    def get_global_record(self, key) -> 'ByteData':
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            return self._get_record(util, handle, tx_handle,
                                    _PsbtRecordType.GLOBAL, 0, key)

    ##
    # @brief find global record.
    # @param[in] key        record key
    # @retval true      find
    # @retval false     not found
    def is_find_global_record(self, key) -> bool:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tx_handle:
            return self._is_find_record(util, handle, tx_handle,
                                        _PsbtRecordType.GLOBAL, 0, key)

    '''
    -------------------------------------------------------
    internal functions
    -------------------------------------------------------
    '''

    ##
    # @brief get pubkey record.
    # @param[in] util           cfd util object
    # @param[in] handle         cfd handle
    # @param[in] psbt_handle    psbt handle
    # @param[in] kind           record kind
    # @param[in] index          index
    # @param[in] pubkey         pubkey
    # @return value
    def _get_pubkey_record(
            self, util, handle, psbt_handle, kind: '_PsbtRecordKind',
            index: int, pubkey) -> str:
        key = str(pubkey) if isinstance(
            pubkey, ExtPubkey) else to_hex_string(pubkey)
        return util.call_func(
            'CfdGetPsbtPubkeyRecord', handle.get_handle(),
            psbt_handle.get_handle(), kind.value, index, key)

    ##
    # @brief get pubkey bip32 data.
    # @param[in] util           cfd util object
    # @param[in] handle         cfd handle
    # @param[in] psbt_handle    psbt handle
    # @param[in] kind           record kind
    # @param[in] index          index
    # @param[in] pubkey         pubkey or extpubkey
    # @retval [0] fingerprint
    # @retval [1] bip32 path
    def _get_pubkey_bip32_data(
            self, util, handle, psbt_handle, kind: '_PsbtRecordKind',
            index: int, pubkey) -> Tuple['ByteData', str]:
        key = str(pubkey) if isinstance(
            pubkey, ExtPubkey) else to_hex_string(pubkey)
        fp, path = util.call_func(
            'CfdGetPsbtBip32Data', handle.get_handle(),
            psbt_handle.get_handle(), kind.value, index, key)
        return ByteData(fp), path

    ##
    # @brief find pubkey record.
    # @param[in] util           cfd util object
    # @param[in] handle         cfd handle
    # @param[in] psbt_handle    psbt handle
    # @param[in] kind           record kind
    # @param[in] index          index
    # @param[in] pubkey         pubkey or extpubkey
    # @retval true      find
    # @retval false     not found
    def _is_find_pubkey(
            self, util, handle, psbt_handle, kind: '_PsbtRecordKind',
            index: int, pubkey) -> bool:
        key = str(pubkey) if isinstance(
            pubkey, ExtPubkey) else to_hex_string(pubkey)
        return util.call_func(
            'CfdIsFindPsbtPubkeyRecord', handle.get_handle(),
            psbt_handle.get_handle(), kind.value, index, key)

    ##
    # @brief get pubkey bip32 list.
    # @param[in] util           cfd util object
    # @param[in] handle         cfd handle
    # @param[in] psbt_handle    psbt handle
    # @param[in] kind           record kind
    # @param[in] index          index
    # @return keyData list
    def _get_bip32_pubkey_list(
            self, util, handle, psbt_handle, kind: '_PsbtRecordKind',
            index: int) -> List['KeyData']:
        num, work_handle = util.call_func(
            'CfdGetPsbtPubkeyList', handle.get_handle(),
            psbt_handle.get_handle(), kind.value, index)
        with JobHandle(handle, work_handle,
                       'CfdFreePsbtPubkeyList') as list_handle:
            pubkeys = []
            for list_index in range(num):
                pubkey, fingerprint, bip32_path = util.call_func(
                    'CfdGetPsbtPubkeyListBip32Data', handle.get_handle(),
                    list_handle.get_handle(), list_index)
                if len(pubkey) in [66, 130]:
                    pubkeys.append(
                        KeyData(
                            Pubkey(pubkey),
                            ByteData(fingerprint),
                            bip32_path))
                else:
                    pubkeys.append(KeyData(ExtPubkey(pubkey),
                                           ByteData(fingerprint), bip32_path))
            return pubkeys

    ##
    # @brief get pubkey list.
    # @param[in] util           cfd util object
    # @param[in] handle         cfd handle
    # @param[in] psbt_handle    psbt handle
    # @param[in] kind           record kind
    # @param[in] index          index
    # @retval [0]   pubkey or extpubkey list
    # @retval [1]   hex list
    def _get_pubkey_list(
            self, util, handle, psbt_handle, kind: '_PsbtRecordKind',
            index: int) -> Tuple[List[str], List['ByteData']]:
        num, work_handle = util.call_func(
            'CfdGetPsbtPubkeyList', handle.get_handle(),
            psbt_handle.get_handle(), kind.value, index)
        with JobHandle(handle, work_handle,
                       'CfdFreePsbtPubkeyList') as list_handle:
            pubkeys = []
            hex_pubkeys = []
            for list_index in range(num):
                pubkey, pubkey_hex = util.call_func(
                    'CfdGetPsbtPubkeyListData', handle.get_handle(),
                    list_handle.get_handle(), list_index)
                pubkeys.append(pubkey)
                hex_pubkeys.append(ByteData(pubkey_hex))
            return pubkeys, hex_pubkeys

    ##
    # @brief get data list.
    # @param[in] util           cfd util object
    # @param[in] handle         cfd handle
    # @param[in] psbt_handle    psbt handle
    # @param[in] kind           record kind
    # @param[in] index          index
    # @return data list
    def _get_bytedata_list(
            self, util, handle, psbt_handle, kind: '_PsbtRecordKind',
            index: int) -> List['ByteData']:
        num, work_handle = util.call_func(
            'CfdGetPsbtByteDataList', handle.get_handle(),
            psbt_handle.get_handle(), kind.value, index)
        with JobHandle(handle, work_handle,
                       'CfdFreePsbtByteDataList') as list_handle:
            data_list = []
            for list_index in range(num):
                data = util.call_func(
                    'CfdGetPsbtByteDataItem', handle.get_handle(),
                    list_handle.get_handle(), list_index)
                data_list.append(ByteData(data))
            return data_list

    ##
    # @brief set redeem script.
    # @param[in] util           cfd util object
    # @param[in] handle         cfd handle
    # @param[in] psbt_handle    psbt handle
    # @param[in] type           record type
    # @param[in] index          index
    # @param[in] redeem_script  redeem script
    # @return void
    def _set_redeem_script(
            self, util, handle, psbt_handle, type: '_PsbtRecordType',
            index: int, redeem_script) -> None:
        util.call_func(
            'CfdSetPsbtRedeemScript', handle.get_handle(),
            psbt_handle.get_handle(), type.value, index,
            to_hex_string(redeem_script))

    ##
    # @brief set record.
    # @param[in] util           cfd util object
    # @param[in] handle         cfd handle
    # @param[in] psbt_handle    psbt handle
    # @param[in] type           record type
    # @param[in] index          index
    # @param[in] key            record key
    # @param[in] value          record value
    # @return void
    def _set_record(
            self, util, handle, psbt_handle, type: '_PsbtRecordType',
            index: int, key, value) -> None:
        _key = key.value if isinstance(key, PsbtDefinition) else key
        util.call_func(
            'CfdAddPsbtRecord', handle.get_handle(), psbt_handle.get_handle(),
            type.value, index, to_hex_string(_key), to_hex_string(value))

    ##
    # @brief get record.
    # @param[in] util           cfd util object
    # @param[in] handle         cfd handle
    # @param[in] psbt_handle    psbt handle
    # @param[in] type           record type
    # @param[in] index          index
    # @param[in] key            record key
    # @return record value
    def _get_record(self, util, handle, psbt_handle, type: '_PsbtRecordType',
                    index: int, key) -> 'ByteData':
        _key = key.value if isinstance(key, PsbtDefinition) else key
        value = util.call_func(
            'CfdGetPsbtRecord', handle.get_handle(), psbt_handle.get_handle(),
            type.value, index, to_hex_string(_key))
        return ByteData(value)

    ##
    # @brief find record.
    # @param[in] util           cfd util object
    # @param[in] handle         cfd handle
    # @param[in] psbt_handle    psbt handle
    # @param[in] type           record type
    # @param[in] index          index
    # @param[in] key            record key
    # @retval true      find
    # @retval false     not found
    def _is_find_record(
            self, util, handle, psbt_handle, type: '_PsbtRecordType',
            index: int, key) -> bool:
        _key = key.value if isinstance(key, PsbtDefinition) else key
        return util.call_func(
            'CfdIsFindPsbtRecord', handle.get_handle(),
            psbt_handle.get_handle(), type.value, index,
            to_hex_string(_key))

    ##
    # @brief get psbt handle.
    # @param[in] util       cfd util object
    # @param[in] handle     cfd handle
    # @param[in] network    network type
    # @return psbt job handle
    def _get_handle(
            self, util, handle,
            network: Optional['Network'] = None) -> 'JobHandle':
        _network = Network.get(self.network) if not network else network
        work_handle = util.call_func(
            'CfdCreatePsbtHandle', handle.get_handle(),
            _network.value, self.base64, '', 0, 0)
        return JobHandle(handle, work_handle, 'CfdFreePsbtHandle')

    ##
    # @brief update psbt data.
    # @param[in] util           cfd util object
    # @param[in] handle         cfd handle
    # @param[in] psbt_handle    psbt handle
    # @return void
    def _update_base64(self, util, handle, psbt_handle) -> None:
        self.base64, _ = util.call_func(
            'CfdGetPsbtData', handle.get_handle(), psbt_handle.get_handle())


##
# @class _FundPsbtOpt
# @brief FundPsbt option class.
class _FundPsbtOpt(Enum):
    ##
    # effective fee rate
    EFFECTIVE_FEE_RATE = 1
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
# @class _PsbtRecordType
# @brief PSBT record type class.
class _PsbtRecordType(Enum):
    ##
    # global
    GLOBAL = 1
    ##
    # input
    INPUT = 2
    ##
    # output
    OUTPUT = 3


##
# @class _PsbtRecordKind
# @brief PSBT record kind class.
class _PsbtRecordKind(Enum):
    ##
    # input signature
    INPUT_SIGNATURE = 1
    ##
    # input bip32
    INPUT_BIP32 = 2
    ##
    # output bip32
    OUTPUT_BIP32 = 3
    ##
    # global xpub
    GLOBAL_XPUB = 4
    ##
    # input final witness stack
    INPUT_FINAL_WITNESS = 5
    ##
    # input unknown key list
    INPUT_UNKNOWN_KEYS = 6
    ##
    # output unknown key list
    OUTPUT_UNKNOWN_KEYS = 7
    ##
    # global unknown key list
    GLOBAL_UNKNOWN_KEYS = 8


##
# All import target.
__all__ = [
    'Psbt',
    'PsbtDefinition',
    'PsbtAppendInputData',
    'PsbtAppendOutputData',
]
