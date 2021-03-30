# -*- coding: utf-8 -*-
##
# @file hdwallet.py
# @brief hdwallet function implements file.
# @note Copyright 2020 CryptoGarage
import typing
from typing import List, Tuple, Union, Optional
from .util import ByteData, CfdUtil, get_util, JobHandle,\
    to_hex_string, CfdError
from .key import Network, Privkey, Pubkey
from enum import Enum
import unicodedata


##
# xpriv mainnet version
XPRIV_MAINNET_VERSION = '0488ade4'
##
# xpriv testnet version
XPRIV_TESTNET_VERSION = '04358394'
##
# xpub mainnet version
XPUB_MAINNET_VERSION = '0488b21e'
##
# xpub testnet version
XPUB_TESTNET_VERSION = '043587cf'


##
# @class ExtKeyType
# @brief ExtKey type.
class ExtKeyType(Enum):
    ##
    # Ext privkey
    EXT_PRIVKEY = 0
    ##
    # Ext pubkey
    EXT_PUBKEY = 1

    ##
    # @brief get string.
    # @return name.
    def __str__(self) -> str:
        return self.name.lower().replace('_', '')

    ##
    # @brief get string.
    # @return name.
    def as_str(self) -> str:
        return self.name.lower().replace('_', '')

    ##
    # @brief get object.
    # @param[in] key_type   key type
    # @return object.
    @classmethod
    def get(cls, key_type) -> 'ExtKeyType':
        if (isinstance(key_type, ExtKeyType)):
            return key_type
        elif (isinstance(key_type, int)):
            _num = int(key_type)
            for _type in ExtKeyType:
                if _num == _type.value:
                    return _type
        else:
            _key_type = str(key_type).lower()
            for _type in ExtKeyType:
                if _key_type == _type.name.lower():
                    return _type
            if _key_type == 'extprivkey':
                return ExtKeyType.EXT_PRIVKEY
            elif _key_type == 'extpubkey':
                return ExtKeyType.EXT_PUBKEY
        raise CfdError(
            error_code=1,
            message='Error: Invalid extkey type.')


##
# @class Extkey
# @brief ExtKey base class.
class Extkey(object):
    ##
    # @var extkey_type
    # extkey type
    extkey_type: 'ExtKeyType'
    ##
    # @var util
    # cfd util
    util: 'CfdUtil'
    ##
    # @var version
    # version
    version: str
    ##
    # @var fingerprint
    # fingerprint
    fingerprint: 'ByteData'
    ##
    # @var chain_code
    # chain code
    chain_code: 'ByteData'
    ##
    # @var depth
    # depth
    depth: int
    ##
    # @var child_number
    # child number
    child_number: int
    ##
    # @var extkey
    # extkey string
    extkey: str
    ##
    # @var network
    # network
    network: 'Network'

    ##
    # @brief constructor.
    # @param[in] extkey_type    extkey type
    def __init__(self, extkey_type):
        self.extkey_type = extkey_type
        self.util = get_util()
        self.version = ''
        self.fingerprint = ByteData('')
        self.chain_code = ByteData('')
        self.depth = 0
        self.child_number = 0
        self.extkey = ''
        self.network = Network.TESTNET

    ##
    # @brief get extkey information.
    # @param[in] extkey    extkey
    # @return void
    def _get_information(self, extkey):
        _extkey = str(extkey)
        with self.util.create_handle() as handle:
            result = self.util.call_func(
                'CfdGetExtkeyInformation', handle.get_handle(), _extkey)
            self.version, _fingerprint, _chain_code, self.depth, \
                self.child_number = result
            self.fingerprint = ByteData(_fingerprint)
            self.chain_code = ByteData(_chain_code)
            self.extkey = _extkey
            if self.extkey_type == ExtKeyType.EXT_PRIVKEY:
                main, test, name = XPRIV_MAINNET_VERSION,\
                    XPRIV_TESTNET_VERSION, 'privkey'
            else:
                main, test, name = XPUB_MAINNET_VERSION,\
                    XPUB_TESTNET_VERSION, 'pubkey'
            if self.version == main:
                self.network = Network.MAINNET
            elif self.version == test:
                self.network = Network.TESTNET
            else:
                raise CfdError(
                    error_code=1,
                    message='Error: Invalid ext {}.'.format(name))

    ##
    # @brief get extkey information.
    # @param[in] path           bip32 path
    # @param[in] number         bip32 number
    # @param[in] number_list    bip32 number list
    # @retval [0]  bip32 path
    # @retval [1]  bip32 number list
    @classmethod
    def _convert_path(cls, path='', number=0, number_list=[]):
        if path != '':
            return path, []
        if isinstance(number_list, list) and (
                len(number_list) > 0) and (isinstance(number_list[0], int)):
            for num in number_list:
                if (num < 0) or (num > 0xffffffff):
                    raise CfdError(
                        error_code=1,
                        message='Error: Invalid number_list item range.')
            return '', number_list
        if (not isinstance(number, int)) or (
                number < 0) or (number > 0xffffffff):
            raise CfdError(
                error_code=1,
                message='Error: Invalid number range.')
        return '', [number]

    ##
    # @brief get extkey path data.
    # @param[in] bip32_path     bip32 path
    # @param[in] key_type       key type
    # @return path data
    def _get_path_data(self, bip32_path, key_type):
        with self.util.create_handle() as handle:
            return self.util.call_func(
                'CfdGetParentExtkeyPathData', handle.get_handle(),
                self.extkey, bip32_path, key_type.value)

    ##
    # @brief create extkey.
    # @param[in] key_type       key type
    # @param[in] network        network
    # @param[in] fingerprint    fingerprint
    # @param[in] key            key
    # @param[in] chain_code     chain_code
    # @param[in] depth          depth
    # @param[in] number         number
    # @param[in] parent_key     parent key
    # @return Extkey string
    @classmethod
    def _create(
            cls, key_type, network, fingerprint, key, chain_code,
            depth, number, parent_key='') -> str:
        _network = Network.get_mainchain(network)
        _fingerprint = ''
        _path, _num_list = cls._convert_path(number=number)
        _number = _num_list[0] if len(_num_list) > 0 else number
        if parent_key == '':
            _fingerprint = str(fingerprint)
        _network = Network.get_mainchain(network)
        util = get_util()
        with util.create_handle() as handle:
            _extkey = util.call_func(
                'CfdCreateExtkey', handle.get_handle(),
                _network.value, key_type.value, str(parent_key),
                _fingerprint, str(key), str(chain_code), depth, _number)
        return _extkey


##
# @class ExtPrivkey
# @brief ExtPrivkey class.
class ExtPrivkey(Extkey):
    ##
    # @var privkey
    # privkey
    privkey: 'Privkey'

    ##
    # @brief create extkey from seed.
    # @param[in] seed       seed
    # @param[in] network    network
    # @return ExtPrivkey
    @classmethod
    def from_seed(cls, seed, network=Network.MAINNET) -> 'ExtPrivkey':
        _seed = to_hex_string(seed)
        _network = Network.get_mainchain(network)
        util = get_util()
        with util.create_handle() as handle:
            _extkey = util.call_func(
                'CfdCreateExtkeyFromSeed', handle.get_handle(),
                _seed, _network.value, ExtKeyType.EXT_PRIVKEY.value)
        return ExtPrivkey(_extkey)

    ##
    # @brief create extkey.
    # @param[in] network        network
    # @param[in] fingerprint    fingerprint
    # @param[in] key            key
    # @param[in] chain_code     chain_code
    # @param[in] depth          depth
    # @param[in] number         number
    # @param[in] parent_key     parent key
    # @return ExtPrivkey
    @classmethod
    def create(
            cls, network, fingerprint, key, chain_code,
            depth: int, number: int, parent_key='') -> 'ExtPrivkey':
        _extkey = cls._create(
            ExtKeyType.EXT_PRIVKEY, network, fingerprint, key,
            chain_code, depth, number, parent_key)
        return ExtPrivkey(_extkey)

    ##
    # @brief constructor.
    # @param[in] extkey        extkey
    def __init__(self, extkey):
        super().__init__(ExtKeyType.EXT_PRIVKEY)
        self._get_information(extkey)
        if isinstance(extkey, ExtPrivkey):
            self.privkey = extkey.privkey
        else:
            with self.util.create_handle() as handle:
                _hex, wif = self.util.call_func(
                    'CfdGetPrivkeyFromExtkey', handle.get_handle(),
                    self.extkey, self.network.value)
                self.privkey = Privkey(wif=wif)

    ##
    # @brief get string.
    # @return extkey.
    def __str__(self) -> str:
        return self.extkey

    ##
    # @brief derive key.
    # @param[in] path           bip32 path
    # @param[in] number         bip32 number
    # @param[in] number_list    bip32 number list
    # @return ExtPrivkey
    def derive(self, path: str = '', number: int = 0,
               number_list: typing.List[int] = []) -> 'ExtPrivkey':
        _path, _list = self._convert_path(path, number, number_list)
        with self.util.create_handle() as handle:
            if _path == '':
                _extkey = self.extkey
                for child in _list:
                    hardened = True if child >= 0x80000000 else False
                    _extkey = self.util.call_func(
                        'CfdCreateExtkeyFromParent',
                        handle.get_handle(), _extkey, child, hardened,
                        self.network.value,
                        ExtKeyType.EXT_PRIVKEY.value)
            else:
                _extkey = self.util.call_func(
                    'CfdCreateExtkeyFromParentPath', handle.get_handle(),
                    self.extkey, _path, self.network.value,
                    ExtKeyType.EXT_PRIVKEY.value)
        return ExtPrivkey(_extkey)

    ##
    # @brief derive pubkey.
    # @param[in] path           bip32 path
    # @param[in] number         bip32 number
    # @param[in] number_list    bip32 number list
    # @return ExtPubkey
    def derive_pubkey(self, path: str = '', number: int = 0,
                      number_list: typing.List[int] = []) -> 'ExtPubkey':
        return self.derive(
            path=path,
            number=number,
            number_list=number_list).get_extpubkey()

    ##
    # @brief get ext pubkey.
    # @return ExtPubkey
    def get_extpubkey(self) -> 'ExtPubkey':
        with self.util.create_handle() as handle:
            ext_pubkey = self.util.call_func(
                'CfdCreateExtPubkey', handle.get_handle(),
                self.extkey, self.network.value)
            return ExtPubkey(ext_pubkey)

    ##
    # @brief get extkey path data.
    # @param[in] bip32_path     bip32 path
    # @param[in] key_type       key type
    # @retval [0] path data
    # @retval [1] object
    def get_path_data(self, bip32_path: str, key_type=ExtKeyType.EXT_PRIVKEY,
                      ) -> Tuple[int, Union['ExtPubkey', 'ExtPrivkey']]:
        path_data, child_key = self._get_path_data(
            bip32_path, key_type)
        _key_type = ExtKeyType.get(key_type)
        if _key_type == ExtKeyType.EXT_PUBKEY:
            return path_data, ExtPubkey(child_key)
        else:
            return path_data, ExtPrivkey(child_key)


##
# @class ExtPubkey
# @brief ExtPubkey class.
class ExtPubkey(Extkey):
    ##
    # @var pubkey
    # pubkey
    pubkey: 'Pubkey'

    ##
    # @brief create extkey.
    # @param[in] network        network
    # @param[in] fingerprint    fingerprint
    # @param[in] key            key
    # @param[in] chain_code     chain_code
    # @param[in] depth          depth
    # @param[in] number         number
    # @param[in] parent_key     parent key
    # @return ExtPubkey
    @classmethod
    def create(
            cls, network, fingerprint, key, chain_code,
            depth: int, number: int, parent_key='') -> 'ExtPubkey':
        _extkey = cls._create(
            ExtKeyType.EXT_PUBKEY, network, fingerprint, key,
            chain_code, depth, number, parent_key)
        return ExtPubkey(_extkey)

    ##
    # @brief constructor.
    # @param[in] extkey        extkey
    def __init__(self, extkey):
        super().__init__(ExtKeyType.EXT_PUBKEY)
        self._get_information(extkey)
        if isinstance(extkey, ExtPubkey):
            self.pubkey = extkey.pubkey
        else:
            with self.util.create_handle() as handle:
                hex = self.util.call_func(
                    'CfdGetPubkeyFromExtkey', handle.get_handle(),
                    self.extkey, self.network.value)
                self.pubkey = Pubkey(hex)

    ##
    # @brief get string.
    # @return extkey.
    def __str__(self) -> str:
        return self.extkey

    ##
    # @brief derive key.
    # @param[in] path           bip32 path
    # @param[in] number         bip32 number
    # @param[in] number_list    bip32 number list
    # @return ExtPubkey
    def derive(self, path: str = '', number: int = 0,
               number_list: List[int] = []) -> 'ExtPubkey':
        _path, _list = self._convert_path(path, number, number_list)
        with self.util.create_handle() as handle:
            if len(_path) == 0:
                _extkey = self.extkey
                for child in _list:
                    hardened = True if child >= 0x80000000 else False
                    _extkey = self.util.call_func(
                        'CfdCreateExtkeyFromParent',
                        handle.get_handle(),
                        _extkey, child, hardened,
                        self.network.value,
                        ExtKeyType.EXT_PUBKEY.value)
            else:
                _extkey = self.util.call_func(
                    'CfdCreateExtkeyFromParentPath', handle.get_handle(),
                    self.extkey, _path, self.network.value,
                    ExtKeyType.EXT_PUBKEY.value)
        return ExtPubkey(_extkey)

    ##
    # @brief get extkey path data.
    # @param[in] bip32_path     bip32 path
    # @retval [0] path data
    # @retval [1] object
    def get_path_data(self, bip32_path: str) -> Tuple[str, 'ExtPubkey']:
        path_data, child_key = self._get_path_data(
            bip32_path, ExtKeyType.EXT_PUBKEY)
        return path_data, ExtPubkey(child_key)


##
# @class MnemonicLanguage
# @brief Mnemonic language class.
class MnemonicLanguage(Enum):
    ##
    # English
    EN = 'en'
    ##
    # Spanish
    ES = 'es'
    ##
    # French
    FR = 'fr'
    ##
    # Italic
    IT = 'it'
    ##
    # Japanese
    JP = 'jp'
    ##
    # Simplified Chinese
    ZH_CN = 'zhs'
    ##
    # Traditional Chinese
    ZH_TW = 'zht'

    ##
    # @brief get object.
    # @param[in] language    language
    # @return object.
    @classmethod
    def get(cls, language) -> 'MnemonicLanguage':
        if (isinstance(language, MnemonicLanguage)):
            return language
        else:
            _type = str(language).lower()
            for lang_data in MnemonicLanguage:
                if _type == lang_data.value:
                    return lang_data
            _type = str(language).upper()
            for lang_data in MnemonicLanguage:
                if _type == lang_data.name:
                    return lang_data
            if _type == 'ZHCN':
                return MnemonicLanguage.ZH_CN
            if _type == 'ZHTW':
                return MnemonicLanguage.ZH_TW
        raise CfdError(
            error_code=1,
            message='Error: Invalid lang.')


##
# @class HDWallet
# @brief HDWallet class.
class HDWallet:
    ##
    # @var seed
    # seed
    seed: 'ByteData'
    ##
    # @var network
    # network
    network: 'Network'
    ##
    # @var ext_privkey
    # ext privkey
    ext_privkey: 'ExtPrivkey'

    ##
    # @brief get mnemonic word list.
    # @param[in] language   language
    # @return word_list     mnemonic word list
    @classmethod
    def get_mnemonic_word_list(cls, language) -> List[str]:
        util = get_util()
        _lang = MnemonicLanguage.get(language).value
        word_list = []
        with util.create_handle() as handle:
            word_handle, max_index = util.call_func(
                'CfdInitializeMnemonicWordList', handle.get_handle(), _lang)
            with JobHandle(
                    handle,
                    word_handle,
                    'CfdFreeMnemonicWordList') as mnemonic_handle:
                for i in range(max_index):
                    word = util.call_func(
                        'CfdGetMnemonicWord',
                        handle.get_handle(), mnemonic_handle.get_handle(), i)
                    word_list.append(word)
        return word_list

    ##
    # @brief get mnemonic.
    # @param[in] entropy    entropy
    # @param[in] language   language
    # @return mnemonic
    @classmethod
    def get_mnemonic(cls, entropy, language) -> str:
        _entropy = to_hex_string(entropy)
        _lang = MnemonicLanguage.get(language).value
        util = get_util()
        with util.create_handle() as handle:
            mnemonic = util.call_func(
                'CfdConvertEntropyToMnemonic',
                handle.get_handle(), _entropy, _lang)
            return mnemonic

    ##
    # @brief get entropy.
    # @param[in] mnemonic       mnemonic
    # @param[in] language       language
    # @param[in] strict_check   strict check
    # @return entropy
    @classmethod
    def get_entropy(cls, mnemonic: Union[str, List[str]], language,
                    strict_check: bool = True) -> 'ByteData':
        _mnemonic = cls._convert_mnemonic(mnemonic)
        _lang = MnemonicLanguage.get(language).value
        _mnemonic = unicodedata.normalize('NFKD', _mnemonic)
        util = get_util()
        with util.create_handle() as handle:
            _, entropy = util.call_func(
                'CfdConvertMnemonicToSeed', handle.get_handle(),
                _mnemonic, '', strict_check, _lang, False)
            return ByteData(entropy)

    ##
    # @brief create extkey from seed.
    # @param[in] seed       seed
    # @param[in] network    network
    # @return HDWallet
    @classmethod
    def from_seed(cls, seed, network=Network.MAINNET) -> 'HDWallet':
        return HDWallet(seed=seed, network=network)

    ##
    # @brief create extkey from mnemonic.
    # @param[in] mnemonic       mnemonic
    # @param[in] language       language
    # @param[in] passphrase     passphrase
    # @param[in] network        network
    # @param[in] strict_check   strict check
    # @return HDWallet
    @classmethod
    def from_mnemonic(cls,
                      mnemonic: Union[str,
                                      List[str]],
                      language='en',
                      passphrase: str = '',
                      network=Network.MAINNET,
                      strict_check: bool = True) -> 'HDWallet':
        return HDWallet(
            mnemonic=mnemonic, language=language,
            passphrase=passphrase, network=network, strict_check=strict_check)

    ##
    # @brief constructor.
    # @param[in] seed           seed
    # @param[in] mnemonic       mnemonic
    # @param[in] language       language
    # @param[in] passphrase     passphrase
    # @param[in] network        network
    # @param[in] strict_check   strict check
    def __init__(
            self, seed='', mnemonic: Union[str, List[str]] = '',
            language='en', passphrase: str = '',
            network=Network.MAINNET, strict_check: bool = True):
        self.seed = ByteData(seed)
        self.network = Network.get_mainchain(network)
        _mnemonic = self._convert_mnemonic(mnemonic)
        _lang = MnemonicLanguage.get(language).value
        _mnemonic = unicodedata.normalize('NFKD', _mnemonic)
        _passphrase = unicodedata.normalize('NFKD', passphrase)
        if _mnemonic != '':
            util = get_util()
            with util.create_handle() as handle:
                _seed, _ = util.call_func(
                    'CfdConvertMnemonicToSeed',
                    handle.get_handle(), _mnemonic, _passphrase,
                    strict_check, _lang, False)
                self.seed = ByteData(_seed)
        self.ext_privkey = ExtPrivkey.from_seed(self.seed, self.network)

    ##
    # @brief get privkey.
    # @param[in] path           bip32 path
    # @param[in] number         bip32 number
    # @param[in] number_list    bip32 number list
    # @return ExtPrivkey
    def get_privkey(self, path: str = '', number: int = 0,
                    number_list: List[int] = []) -> 'ExtPrivkey':
        return self.ext_privkey.derive(path, number, number_list)

    ##
    # @brief get pubkey.
    # @param[in] path           bip32 path
    # @param[in] number         bip32 number
    # @param[in] number_list    bip32 number list
    # @return ExtPubkey
    def get_pubkey(self, path: str = '', number: int = 0,
                   number_list: List[int] = []) -> 'ExtPubkey':
        return self.ext_privkey.derive_pubkey(path, number, number_list)

    ##
    # @brief convert mnemonic.
    # @param[in] mnemonic   mnemonic
    # @return mnemonic
    @classmethod
    def _convert_mnemonic(cls, mnemonic):
        _words = ' '.join(mnemonic) if isinstance(mnemonic, list) else mnemonic
        return _words.replace('　', ' ') if isinstance(_words, str) else _words


##
# @class KeyData
# @brief KeyData class.
class KeyData:
    ##
    # @var pubkey
    # pubkey
    pubkey: 'Pubkey'
    ##
    # @var privkey
    # privkey
    privkey: Optional['Privkey'] = None
    ##
    # @var ext_pubkey
    # ext pubkey
    ext_pubkey: Optional['ExtPubkey'] = None
    ##
    # @var ext_privkey
    # ext privkey
    ext_privkey: Optional['ExtPrivkey'] = None
    ##
    # @var fingerprint
    # fingerprint
    fingerprint: Optional['ByteData'] = None
    ##
    # @var bip32_path
    # bip32 path
    bip32_path: str

    ##
    # @brief constructor.
    # @param[in] key            key.
    # @param[in] fingerprint    fingerprint or parent key.
    # @param[in] bip32_path     bip32 path
    def __init__(self,
                 key: Union['Pubkey',
                            'Privkey',
                            'ExtPubkey',
                            'ExtPrivkey'],
                 fingerprint: Optional[Union['ByteData',
                                             'Pubkey',
                                             'Privkey',
                                             'ExtPubkey',
                                             'ExtPrivkey']],
                 bip32_path: str = ''):
        if isinstance(key, ExtPrivkey):
            self.ext_privkey = key
            self.privkey = self.ext_privkey.privkey
            self.pubkey = self.privkey.pubkey
        elif isinstance(key, ExtPubkey):
            self.ext_pubkey = key
            self.pubkey = self.ext_pubkey.pubkey
        elif isinstance(key, Privkey):
            self.privkey = key
            self.pubkey = self.privkey.pubkey
        elif isinstance(key, Pubkey):
            self.pubkey = key
        else:
            raise CfdError(error_code=1, message='Error: Unsupported key.')

        if isinstance(fingerprint, ByteData):
            if len(fingerprint.hex) < 8:
                raise CfdError(
                    error_code=1, message='Error: fingerprint is low size.')
            self.fingerprint = fingerprint
        elif isinstance(fingerprint, ExtPrivkey):
            self.fingerprint = fingerprint.privkey.pubkey.get_fingerprint()
        elif isinstance(fingerprint, ExtPubkey) or isinstance(
                fingerprint, Privkey):
            self.fingerprint = fingerprint.pubkey.get_fingerprint()
        elif isinstance(fingerprint, Pubkey):
            self.fingerprint = fingerprint.get_fingerprint()
        elif fingerprint is None:
            pass
        else:
            raise CfdError(
                error_code=1, message='Error: Unsupported fingerprint.')
        self.bip32_path = str(bip32_path)

    ##
    # @brief get string.
    # @return pubkey & bip32 data.
    def __str__(self) -> str:
        if (not self.fingerprint) or (not self.bip32_path):
            return str(self.pubkey)
        fp_str = to_hex_string(self.fingerprint)
        if len(fp_str) < 8:
            return str(self.pubkey)
        path = self.bip32_path
        path = path[1:] if path[0] == 'm' else path
        path = path[1:] if path[0] == '/' else path
        return f'[{fp_str}/{path}]{self.pubkey._hex}'


##
# All import target.
__all__ = [
    'ExtKeyType',
    'Extkey',
    'ExtPrivkey',
    'ExtPubkey',
    'MnemonicLanguage',
    'HDWallet',
    'KeyData',
    'XPRIV_MAINNET_VERSION',
    'XPRIV_TESTNET_VERSION',
    'XPUB_MAINNET_VERSION',
    'XPUB_TESTNET_VERSION'
]
