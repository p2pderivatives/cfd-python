# -*- coding: utf-8 -*-
##
# @file block.py
# @brief bitcoin block function implements file.
# @note Copyright 2021 CryptoGarage
from typing import List, Tuple
from .key import Network
from .transaction import BlockHash, Txid, Transaction
from .util import CfdError, CfdErrorCode, ByteData, \
    to_hex_string, get_util, JobHandle


##
# @class BlockHeader
# @brief Block header data.
class BlockHeader:
    ##
    # @var version
    # block version.
    version: int
    ##
    # @var prev_block_hash
    # previous block hash.
    prev_block_hash: BlockHash
    ##
    # @var merkleroot
    # block merkleroot.
    merkleroot: BlockHash
    ##
    # @var time
    # block time
    time: int
    ##
    # @var bits
    # block flags
    bits: int
    ##
    # @var nonce
    # block nonce
    nonce: int

    ##
    # @brief constructor.
    # @param[in] version            block version
    # @param[in] prev_block_hash    previous block hash
    # @param[in] merkleroot         block merkleroot
    # @param[in] time               block time
    # @param[in] bits               block bits
    # @param[in] nonce              block nonce
    def __init__(self, version: int, prev_block_hash, merkleroot,
                 time: int, bits: int, nonce: int) -> None:
        self.version = version
        self.prev_block_hash = BlockHash(prev_block_hash)
        self.merkleroot = BlockHash(merkleroot)
        self.time = time
        self.bits = bits
        self.nonce = nonce


##
# @class Block
# @brief Block
class Block:
    ##
    # @var hex
    # block hex
    hex: str
    ##
    # @var hash
    # block hash
    hash: BlockHash
    ##
    # @var network
    # network type
    network: Network

    ##
    # @brief constructor.
    # @param[in] data       block data
    # @param[in] network    network type
    def __init__(self, data, network=Network.MAINNET):
        self.network = Network.get(network)
        self.hex = to_hex_string(data)
        self.hash = self._get_blockhash()

    ##
    # @brief get string.
    # @return block hash hex.
    def __str__(self) -> str:
        return str(self.hash)

    ##
    # @brief Get block hash.
    # @return block hash
    def get_blockhash(self) -> 'BlockHash':
        return self.hash

    ##
    # @brief Get block data.
    # @return block data
    def get_data(self) -> 'ByteData':
        return ByteData(self.hex)

    ##
    # @brief Get block header.
    # @return block header
    def get_header(self) -> 'BlockHeader':
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle, self.network, self.hex) as block_handle:
            ret = util.call_func(
                'CfdGetBlockHeaderData', handle.get_handle(),
                block_handle.get_handle())
            return BlockHeader(ret[0], ret[1], ret[2], ret[3], ret[4], ret[5])

    ##
    # @brief Get transaction count in block.
    # @return transaction count
    def get_tx_count(self) -> int:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle, self.network, self.hex) as block_handle:
            tx_count = util.call_func(
                'CfdGetTxCountInBlock', handle.get_handle(),
                block_handle.get_handle())
            return tx_count

    ##
    # @brief Exist transaction in block.
    # @param[in] txid   txid
    # @retval True      exist.
    # @retval False     not exist.
    def exist_txid(self, txid) -> bool:
        _txid = Txid(txid)
        try:
            util = get_util()
            with util.create_handle() as handle, self._get_handle(
                    util, handle, self.network, self.hex) as block_handle:
                util.call_func(
                    'CfdExistTxidInBlock', handle.get_handle(),
                    block_handle.get_handle(), str(_txid))
                return True
        except CfdError as err:
            if err.error_code == CfdErrorCode.NOT_FOUND.value:
                return False
            else:
                raise err

    ##
    # @brief Get txid list.
    # @return txid list
    def get_txid_list(self) -> List['Txid']:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle, self.network, self.hex) as block_handle:
            result = []
            tx_count = util.call_func(
                'CfdGetTxCountInBlock', handle.get_handle(),
                block_handle.get_handle())
            for index in range(tx_count):
                txid = util.call_func(
                    'CfdGetTxidFromBlock', handle.get_handle(),
                    block_handle.get_handle(), index)
                result.append(Txid(txid))
            return result

    ##
    # @brief Get transaction from block.
    # @param[in] txid   txid
    # @return transaction.
    def get_transaction(self, txid) -> 'Transaction':
        _txid = Txid(txid)
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle, self.network, self.hex) as block_handle:
            tx_hex = util.call_func(
                'CfdGetTransactionFromBlock', handle.get_handle(),
                block_handle.get_handle(), str(_txid))
            return Transaction(tx_hex)

    ##
    # @brief Get transaction data from block.
    # @param[in] txid   txid
    # @retval [0]       transaction.
    # @retval [1]       txoutproof.
    def get_tx_data(self, txid) -> Tuple['Transaction', 'ByteData']:
        _txid = Txid(txid)
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle, self.network, self.hex) as block_handle:
            tx_hex = util.call_func(
                'CfdGetTransactionFromBlock', handle.get_handle(),
                block_handle.get_handle(), str(_txid))
            proof = util.call_func(
                'CfdGetTxOutProof', handle.get_handle(),
                block_handle.get_handle(), str(_txid))
            return Transaction(tx_hex), ByteData(proof)

    ##
    # @brief Get block hash.
    # @return block hash
    def _get_blockhash(self) -> 'BlockHash':
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle, self.network, self.hex) as block_handle:
            block_hash = util.call_func(
                'CfdGetBlockHash', handle.get_handle(),
                block_handle.get_handle())
            return BlockHash(block_hash)

    ##
    # @brief get block handle.
    # @param[in] util       cfd util object
    # @param[in] handle     cfd handle
    # @param[in] network    network type
    # @param[in] block      block hex
    # @return block job handle
    @classmethod
    def _get_handle(cls, util, handle, network: 'Network',
                    block: str) -> 'JobHandle':
        work_handle = util.call_func(
            'CfdInitializeBlockHandle', handle.get_handle(),
            network.value, block)
        return JobHandle(handle, work_handle, 'CfdFreeBlockHandle')


##
# All import target.
__all__ = [
    'Block',
    'BlockHeader'
]
