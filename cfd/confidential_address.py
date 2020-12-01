# -*- coding: utf-8 -*-
##
# @file confidential_address.py
# @brief elements confidential address function implements file.
# @note Copyright 2020 CryptoGarage
import typing
from .address import Address, AddressUtil
from .key import Pubkey
from .util import get_util, to_hex_string, CfdError


##
# @class ConfidentialAddress
# @brief Elements confidential address class.
class ConfidentialAddress:
    ##
    # @var confidential_address
    # confidential address string
    confidential_address: str
    ##
    # @var address
    # address
    address: 'Address'
    ##
    # @var confidential_key
    # confidential key
    confidential_key: 'Pubkey'

    ##
    # @brief check confidential address.
    # @param[in] confidential_address   confidential address
    # @retval True      confidential address
    # @retval False     other
    @classmethod
    def valid(cls, confidential_address) -> bool:
        util = get_util()
        try:
            with util.create_handle() as handle:
                _, _, _ = util.call_func(
                    'CfdParseConfidentialAddress', handle.get_handle(),
                    str(confidential_address))
                return True
        except CfdError:
            return False

    ##
    # @brief parse confidential address.
    # @param[in] confidential_address   confidential address
    # @return ConfidentialAddress object
    @classmethod
    def parse(cls, confidential_address) -> 'ConfidentialAddress':
        util = get_util()
        with util.create_handle() as handle:
            _addr, _key, _ = util.call_func(
                'CfdParseConfidentialAddress', handle.get_handle(),
                confidential_address)
            return ConfidentialAddress(_addr, _key)

    ##
    # @brief constructor.
    # @param[in] address            address address
    # @param[in] confidential_key   confidential key
    def __init__(self, address, confidential_key):
        self.address = address if isinstance(
            address, Address) else AddressUtil.parse(address)
        self.confidential_key = confidential_key if isinstance(
            confidential_key, Pubkey) else Pubkey(confidential_key)
        util = get_util()
        with util.create_handle() as handle:
            self.confidential_address = util.call_func(
                'CfdCreateConfidentialAddress', handle.get_handle(),
                str(address), to_hex_string(confidential_key))

    ##
    # @brief get string.
    # @return confidential address.
    def __str__(self) -> str:
        return self.confidential_address


##
# All import target.
__all__ = ['ConfidentialAddress']
