# -*- coding: utf-8 -*-
##
# @file taproot.py
# @brief bitcoin taproot function implements file.
# @note Copyright 2021 CryptoGarage
from typing import List, Optional, Tuple, Union
from .util import CfdError, CfdErrorCode, get_util, JobHandle, ByteData, \
    to_hex_string
from .key import SchnorrPubkey, Privkey
from .script import Script


##
# @brief tapscript leaf version.
TAPSCRIPT_LEAF_VERSION: int = 0xc0


##
# @class TapBranch
# @brief TapBranch
class TapBranch:
    ##
    # @var branches
    # script tree branches.
    branches: List[Union['TapBranch', 'ByteData', 'Script']]
    ##
    # @var hash
    # hash.
    hash: 'ByteData'
    ##
    # @var tapscript
    # tapscript.
    tapscript: Optional['Script']
    ##
    # @var tree_str
    # tree serialize string. (cfd format)
    tree_str: str
    ##
    # @var leaf_version
    # leaf version.
    leaf_version: int
    ##
    # @var taget_node_str
    # target node route string.
    taget_node_str: str

    ##
    # @brief get tapbranch from string.
    # @param[in] tree_str           tree string.
    # @return tapbranch object
    @classmethod
    def from_string(cls, tree_str: str) -> 'TapBranch':
        result = TapBranch()
        util = get_util()
        with util.create_handle() as handle, TapBranch._get_handle(
                util, handle) as tree_handle:
            util.call_func(
                'CfdSetScriptTreeFromString', handle.get_handle(),
                tree_handle.get_handle(), tree_str, '', 0, '')
            result.tree_str = util.call_func(
                'CfdGetTaprootScriptTreeSrting', handle.get_handle(),
                tree_handle.get_handle())
            branch_data = TapBranch._load_tree(handle, tree_handle)
            result.tree_str = branch_data.tree_str
            result.branches = branch_data.branches
            result.hash = branch_data.hash
            result.tapscript = branch_data.tapscript
            result.leaf_version = branch_data.leaf_version
            result.taget_node_str = ''
            for branch in result.branches:
                if isinstance(branch, TapBranch):
                    result.taget_node_str += to_hex_string(
                        branch.get_current_hash())
                else:
                    result.taget_node_str += to_hex_string(branch)
            return result

    ##
    # @brief constructor.
    # @param[in] hash           branch hash only
    # @param[in] tapscript      tapscript
    # @param[in] tree_str       scripttree string
    # @param[in] leaf_version   leaf version
    def __init__(self, hash: Union['ByteData', str] = '',
                 tapscript: Optional['Script'] = None,
                 tree_str: str = '',
                 leaf_version: int = TAPSCRIPT_LEAF_VERSION):
        self.branches = []
        if isinstance(hash, ByteData):
            self.hash = hash
        else:
            self.hash = ByteData(hash)
        if isinstance(tapscript, Script) and tapscript.hex:
            self.tapscript = tapscript
        else:
            self.tapscript = None
        self.taget_node_str = ''
        self.tree_str = ''
        self.leaf_version = leaf_version

        if tree_str:
            temp_tree_str = tree_str
        elif self.tapscript and self.tapscript.hex:
            temp_tree_str = f'tl({self.tapscript.hex})'
        elif self.hash.hex:
            temp_tree_str = self.hash.hex
        else:
            temp_tree_str = ''
        self._load(temp_tree_str)

    ##
    # @brief get string.
    # @return tree or hash string.
    def __str__(self) -> str:
        return str(self.hash) if not self.tree_str else self.tree_str

    ##
    # @brief get branch string.
    # @return tree/branch string.
    def as_str(self) -> str:
        return self.tree_str

    ##
    # @brief add branch.
    # @param[in] branch     branch
    # @return void
    def add_branch(
            self, branch: Union['TapBranch', 'Script', 'ByteData']) -> None:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tree_handle:
            tapscript = self.tapscript.hex if self.tapscript else ''
            util.call_func(
                'CfdSetScriptTreeFromString', handle.get_handle(),
                tree_handle.get_handle(), self.tree_str,
                tapscript, self.leaf_version, self.taget_node_str)
            branch_data = self._add_branch(handle, tree_handle, branch)
            self.tree_str = util.call_func(
                'CfdGetTaprootScriptTreeSrting', handle.get_handle(),
                tree_handle.get_handle())
            self.branches.append(branch_data)
            if isinstance(branch_data, TapBranch):
                self.taget_node_str += to_hex_string(
                    branch_data.get_current_hash())
            else:
                self.taget_node_str += to_hex_string(branch_data)

    ##
    # @brief add branch list.
    # @param[in] branches   branch list
    # @return void
    def add_branches(
            self, branches: List[Union['TapBranch', 'Script', 'ByteData']],
    ) -> None:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tree_handle:
            tapscript = self.tapscript.hex if self.tapscript else ''
            util.call_func(
                'CfdSetScriptTreeFromString', handle.get_handle(),
                tree_handle.get_handle(), self.tree_str,
                tapscript, self.leaf_version, self.taget_node_str)
            for branch in branches:
                branch_data = self._add_branch(handle, tree_handle, branch)
                self.branches.append(branch_data)
                if isinstance(branch_data, TapBranch):
                    self.taget_node_str += to_hex_string(
                        branch_data.get_current_hash())
                else:
                    self.taget_node_str += to_hex_string(branch_data)
            self.tree_str = util.call_func(
                'CfdGetTaprootScriptTreeSrting', handle.get_handle(),
                tree_handle.get_handle())

    ##
    # @brief has tapscript.
    # @return True or False
    def has_tapscript(self) -> bool:
        return True if self.tapscript and self.tapscript.hex else False

    ##
    # @brief get tapscript.
    # @return script.
    def get_tapscript(self) -> 'Script':
        if not self.tapscript:
            raise CfdError(CfdErrorCode.ILLEGAL_STATE, 'tapscript not found.')
        return self.tapscript

    ##
    # @brief get base hash.
    # @return base hash.
    def get_base_hash(self) -> 'ByteData':
        return self.hash

    ##
    # @brief get current branch hash.
    # @return current branch hash.
    def get_current_hash(self) -> 'ByteData':
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tree_handle:
            tapscript = self.tapscript.hex if self.tapscript else ''
            util.call_func(
                'CfdSetScriptTreeFromString', handle.get_handle(),
                tree_handle.get_handle(), self.tree_str,
                tapscript, self.leaf_version, '')
            count = util.call_func(
                'CfdGetTapBranchCount', handle.get_handle(),
                tree_handle.get_handle())
            if count == 0:
                return self.hash

            hash, _, _, _ = util.call_func(
                'CfdGetTapBranchData', handle.get_handle(),
                tree_handle.get_handle(), count - 1, True)
            return ByteData(hash)

    ##
    # @brief get branch hash.
    # @param[in] index      target index from tapleaf.
    # @return branch hash.
    def get_branch_hash(self, index: int) -> 'ByteData':
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tree_handle:
            tapscript = self.tapscript.hex if self.tapscript else ''
            util.call_func(
                'CfdSetScriptTreeFromString', handle.get_handle(),
                tree_handle.get_handle(), self.tree_str,
                tapscript, self.leaf_version, '')
            hash, _, _, _ = util.call_func(
                'CfdGetTapBranchData', handle.get_handle(),
                tree_handle.get_handle(), index, True)
            return ByteData(hash)

    ##
    # @brief get taproot data.
    # @param[in] internal_pubkey    internal pubkey
    # @retval [0]   taproot schnorr pubkey. (for address)
    # @retval [1]   tapleaf hash. (for sighash)
    # @retval [2]   tapscript.
    # @retval [3]   control block. (for witness stack)
    def get_taproot_data(
        self, internal_pubkey: 'SchnorrPubkey',
    ) -> Tuple['SchnorrPubkey', 'ByteData', 'Script', 'ByteData']:
        return self._get_taproot_data(internal_pubkey, self.tapscript)

    ##
    # @brief get taproot data.
    # @param[in] internal_pubkey    internal pubkey
    # @param[in] tapscript          tapscript
    # @retval [0]   taproot schnorr pubkey. (for address)
    # @retval [1]   tapleaf hash. (for sighash)
    # @retval [2]   tapscript.
    # @retval [3]   control block. (for witness stack)
    def _get_taproot_data(
        self, internal_pubkey: 'SchnorrPubkey',
        tapscript: Optional['Script'] = None,
    ) -> Tuple['SchnorrPubkey', 'ByteData', 'Script', 'ByteData']:
        if not internal_pubkey:
            raise CfdError(CfdErrorCode.ILLEGAL_STATE,
                           'internal pubkey not found.')
        _script = tapscript if isinstance(tapscript, Script) else Script('')
        util = get_util()
        with util.create_handle() as handle, TapBranch._get_handle(
                util, handle) as tree_handle:
            util.call_func(
                'CfdSetScriptTreeFromString', handle.get_handle(),
                tree_handle.get_handle(), self.tree_str,
                to_hex_string(_script), self.leaf_version,
                self.taget_node_str)
            hash, tapleaf_hash, control_block = util.call_func(
                'CfdGetTaprootScriptTreeHash', handle.get_handle(),
                tree_handle.get_handle(), to_hex_string(internal_pubkey))
            return SchnorrPubkey(hash), ByteData(tapleaf_hash), \
                _script, ByteData(control_block)

    ##
    # @brief get tweaked privkey.
    # @param[in] internal_privkey   internal privkey
    # @return privkey.
    def get_privkey(self, internal_privkey: 'Privkey') -> 'Privkey':
        util = get_util()
        with util.create_handle() as handle, TapBranch._get_handle(
                util, handle) as tree_handle:
            tapscript = self.tapscript.hex if self.tapscript else ''
            util.call_func(
                'CfdSetScriptTreeFromString', handle.get_handle(),
                tree_handle.get_handle(), self.tree_str,
                tapscript, self.leaf_version, self.taget_node_str)
            tweaked_privkey = util.call_func(
                'CfdGetTaprootTweakedPrivkey', handle.get_handle(),
                tree_handle.get_handle(), to_hex_string(internal_privkey))
            return Privkey(hex=tweaked_privkey)

    ##
    # @brief load tree info.
    # @param[in] tree_str       tree string
    # @return void
    def _load(self, tree_str: str) -> None:
        util = get_util()
        with util.create_handle() as handle, self._get_handle(
                util, handle) as tree_handle:
            if tree_str:
                tapscript = self.tapscript.hex if self.tapscript else ''
                util.call_func(
                    'CfdSetScriptTreeFromString', handle.get_handle(),
                    tree_handle.get_handle(), tree_str,
                    tapscript, self.leaf_version, self.taget_node_str)
            elif self.tapscript:
                util.call_func(
                    'CfdSetInitialTapLeaf', handle.get_handle(),
                    tree_handle.get_handle(),
                    self.tapscript.hex, self.leaf_version)
            elif self.hash.hex:
                util.call_func(
                    'CfdSetInitialTapBranchByHash', handle.get_handle(),
                    tree_handle.get_handle(), self.hash.hex)
            else:
                pass  # empty branch
            self.leaf_version, script, hash = util.call_func(
                'CfdGetBaseTapLeaf', handle.get_handle(),
                tree_handle.get_handle())
            if self.leaf_version != 0:
                self.tapscript = Script(script)
            self.hash = ByteData(hash)
            self.tree_str = util.call_func(
                'CfdGetTaprootScriptTreeSrting', handle.get_handle(),
                tree_handle.get_handle())

    ##
    # @brief load tree info.
    # @param[in] handle         cfd handle
    # @param[in] tree_handle    script tree handle
    # @return loaded tree/branch data.
    @classmethod
    def _load_tree(cls, handle, tree_handle) -> 'TapBranch':
        util = get_util()
        count = util.call_func(
            'CfdGetTapBranchCount', handle.get_handle(),
            tree_handle.get_handle())
        branch = TapBranch()
        for index in range(count):
            _, work_handle = util.call_func(
                'CfdGetTapBranchHandle', handle.get_handle(),
                tree_handle.get_handle(), index)
            with JobHandle(handle, work_handle,
                           'CfdFreeTaprootScriptTreeHandle') as br_hdl:
                child = cls._load_tree(handle, br_hdl)
                branch.branches.append(child)
        branch.leaf_version, tapscript, hash = util.call_func(
            'CfdGetBaseTapLeaf', handle.get_handle(),
            tree_handle.get_handle())
        if branch.leaf_version != 0:
            branch.tapscript = Script(tapscript)
        branch.hash = ByteData(hash)
        branch.tree_str = util.call_func(
            'CfdGetTaprootScriptTreeSrting', handle.get_handle(),
            tree_handle.get_handle())
        return branch

    ##
    # @brief get scripttree handle.
    # @param[in] util       cfd util object
    # @param[in] handle     cfd handle
    # @return scripttree job handle
    @classmethod
    def _get_handle(cls, util, handle) -> 'JobHandle':
        work_handle = util.call_func(
            'CfdInitializeTaprootScriptTree', handle.get_handle())
        return JobHandle(handle, work_handle, 'CfdFreeTaprootScriptTreeHandle')

    ##
    # @brief add branch internal.
    # @param[in] handle         cfd handle
    # @param[in] tree_handle    tree job handle
    # @param[in] branch         branch
    # @return added branch data.
    @classmethod
    def _add_branch(
            cls, handle, tree_handle,
            branch: Union['TapBranch', 'ByteData', 'Script'],
    ) -> Union['TapBranch', 'Script', 'ByteData']:
        util = get_util()
        branch_data = branch
        hash = ''
        if isinstance(branch, TapBranch):
            if branch.tree_str:
                util.call_func(
                    'CfdAddTapBranchByScriptTreeString',
                    handle.get_handle(), tree_handle.get_handle(),
                    branch.tree_str)
            else:
                hash = str(branch.hash)
        elif isinstance(branch, Script):
            branch_data = TapBranch(tapscript=branch)
            util.call_func(
                'CfdAddTapBranchByTapLeaf', handle.get_handle(),
                tree_handle.get_handle(), branch.hex, TAPSCRIPT_LEAF_VERSION)
        else:
            hash = to_hex_string(branch)

        if hash:
            util.call_func(
                'CfdAddTapBranchByHash', handle.get_handle(),
                tree_handle.get_handle(), hash)
            branch_data = ByteData(hash)
        return branch_data


##
# @class TaprootScriptTree
# @brief TaprootScriptTree
class TaprootScriptTree(TapBranch):
    ##
    # @var internal_pubkey
    # leaf internal_pubkey.
    internal_pubkey: Optional['SchnorrPubkey']

    ##
    # @brief get script tree.
    # @param[in] tapscript          tapscript
    # @param[in] branches           append branch list.
    # @param[in] internal_pubkey    internal pubkey
    # @return script tree object
    @classmethod
    def create(
            cls,
            tapscript: 'Script',
            branches: List[Union['TapBranch', 'ByteData', 'Script']] = [],
            internal_pubkey: Optional['SchnorrPubkey'] = None,
    ) -> 'TaprootScriptTree':
        result = TaprootScriptTree(tapscript)
        result.add_branches(branches)
        if isinstance(internal_pubkey, SchnorrPubkey):
            result.internal_pubkey = internal_pubkey
        return result

    ##
    # @brief get script tree from control block.
    # @param[in] control_block      control block.
    # @param[in] tapscript          tapscript
    # @return script tree object
    @classmethod
    def from_control_block(
            cls, control_block, tapscript: 'Script') -> 'TaprootScriptTree':
        result = TaprootScriptTree(Script('51'))  # dummy
        util = get_util()
        with util.create_handle() as handle, TapBranch._get_handle(
                util, handle) as tree_handle:
            _internal_pubkey = util.call_func(
                'CfdSetTapScriptByWitnessStack', handle.get_handle(),
                tree_handle.get_handle(), to_hex_string(control_block),
                tapscript.hex)
            branch_data = TapBranch._load_tree(handle, tree_handle)
            result.tree_str = branch_data.tree_str
            result.branches = branch_data.branches
            result.tapscript = tapscript
            result.internal_pubkey = SchnorrPubkey(_internal_pubkey)
            for branch in result.branches:
                if isinstance(branch, TapBranch):
                    result.taget_node_str += to_hex_string(
                        branch.get_current_hash())
                else:
                    result.taget_node_str += to_hex_string(branch)
            return result

    ##
    # @brief get script tree from string and key.
    # @param[in] tree_str           tree string.
    # @param[in] tapscript          tapscript
    # @param[in] target_nodes       target tapbranch hash list.
    # @param[in] internal_pubkey    internal pubkey
    # @return script tree object
    @classmethod
    def from_string_and_key(
            cls, tree_str: str, tapscript: 'Script',
            target_nodes: List[Union['ByteData', str]] = [],
            internal_pubkey: Optional['SchnorrPubkey'] = None,
    ) -> 'TaprootScriptTree':
        result = TaprootScriptTree(Script('51'))  # dummy
        util = get_util()
        with util.create_handle() as handle, TapBranch._get_handle(
                util, handle) as tree_handle:
            target_nodes_str = ''
            for node in target_nodes:
                target_nodes_str += to_hex_string(node)
            util.call_func(
                'CfdSetScriptTreeFromString', handle.get_handle(),
                tree_handle.get_handle(), tree_str,
                tapscript.hex, result.leaf_version, target_nodes_str)
            result.tree_str = util.call_func(
                'CfdGetTaprootScriptTreeSrting', handle.get_handle(),
                tree_handle.get_handle())
            branch_data = TapBranch._load_tree(handle, tree_handle)
            result.tree_str = branch_data.tree_str
            result.branches = branch_data.branches
            result.hash = branch_data.hash
            result.taget_node_str = target_nodes_str
            if not target_nodes_str:
                for branch in result.branches:
                    if isinstance(branch, TapBranch):
                        result.taget_node_str += to_hex_string(
                            branch.get_current_hash())
                    else:
                        result.taget_node_str += to_hex_string(branch)
            result.tapscript = branch_data.tapscript
            if isinstance(internal_pubkey, SchnorrPubkey):
                result.internal_pubkey = internal_pubkey
            return result

    ##
    # @brief constructor.
    # @param[in] tapscript     tapscript
    def __init__(self, tapscript: 'Script'):
        super().__init__('', tapscript)
        self.internal_pubkey = None

    ##
    # @brief get string.
    # @return tree string.
    def __str__(self) -> str:
        if (not self.tapscript) and (not self.branches) and (
                self.internal_pubkey):
            return 'tr(' + str(self.internal_pubkey) + ')'
        if not self.internal_pubkey:
            return self.tree_str
        return 'tr(' + str(self.internal_pubkey) + ',' + self.tree_str + ')'

    ##
    # @brief get taproot data.
    # @param[in] internal_pubkey    internal pubkey
    # @retval [0]   taproot schnorr pubkey. (for address)
    # @retval [1]   tapleaf hash. (for sighash)
    # @retval [2]   tapscript.
    # @retval [3]   control block. (for witness stack)
    def get_taproot_data(
        self, internal_pubkey: Optional['SchnorrPubkey'] = None,
    ) -> Tuple['SchnorrPubkey', 'ByteData', 'Script', 'ByteData']:
        pk = internal_pubkey if internal_pubkey else self.internal_pubkey
        if not pk:
            raise CfdError(CfdErrorCode.ILLEGAL_STATE,
                           'internal pubkey not found.')
        if not self.tapscript:
            raise CfdError(CfdErrorCode.ILLEGAL_STATE, 'tapscript not found.')
        return super()._get_taproot_data(pk, self.tapscript)


##
# All import target.
__all__ = [
    'TapBranch',
    'TaprootScriptTree'
]
