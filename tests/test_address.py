from unittest import TestCase
from unittest.main import main
from tests.util import load_json_file, exec_test,\
    assert_equal, assert_error, assert_match, assert_message
from cfd.address import AddressUtil
from cfd.key import Network, SchnorrPubkey, Privkey
from cfd.script import HashType, Script
from cfd.taproot import TapBranch, TaprootScriptTree
from cfd.util import CfdError, ByteData


def test_address_func(obj, name, case, req, exp, error):
    try:
        resp = None
        _network = req.get('network', 'mainnet')
        if req.get('isElements', False) and (
                _network.lower() == Network.REGTEST.as_str()):
            _network = Network.ELEMENTS_REGTEST

        if name == 'Address.Create':
            _hash_type = HashType.get(req['hashType'])
            if _hash_type == HashType.P2PKH:
                resp = AddressUtil.p2pkh(
                    req['keyData']['hex'], network=_network)
            elif _hash_type == HashType.P2WPKH:
                resp = AddressUtil.p2wpkh(
                    req['keyData']['hex'], network=_network)
            elif _hash_type == HashType.P2SH_P2WPKH:
                resp = AddressUtil.p2sh_p2wpkh(
                    req['keyData']['hex'], network=_network)
            elif _hash_type == HashType.P2SH:
                resp = AddressUtil.p2sh(
                    req['keyData']['hex'], network=_network)
            elif _hash_type == HashType.P2WSH:
                resp = AddressUtil.p2wsh(
                    req['keyData']['hex'], network=_network)
            elif _hash_type == HashType.P2SH_P2WSH:
                resp = AddressUtil.p2sh_p2wsh(
                    req['keyData']['hex'], network=_network)
            elif _hash_type == HashType.TAPROOT:
                resp = AddressUtil.taproot(
                    req['keyData']['hex'], network=_network)
        elif name == 'Address.GetInfo':
            resp = AddressUtil.parse(req['address'])
        elif name == 'Address.MultisigAddresses':
            resp = AddressUtil.get_multisig_address_list(
                req['redeemScript'], req['hashType'], network=_network)
        elif name == 'Address.CreateMultisig':
            resp = AddressUtil.multisig(
                req['nrequired'],
                req['keys'], req['hashType'], network=_network)

        elif name == 'Address.FromLockingScript':
            resp = AddressUtil.from_locking_script(
                req['lockingScript'], network=_network)

        elif name == 'Address.GetTapScriptTreeInfo':
            resp = {}
            nodes = []
            for node in req['tree'][1:]:
                if 'tapscript' in node:
                    nodes.append(Script(node['tapscript']))
                elif 'treeString' in node:
                    nodes.append(TapBranch(tree_str=node['treeString']))
                else:
                    nodes.append(ByteData(node['branchHash']))
            pk = None if 'internalPubkey' not in req else SchnorrPubkey(
                req['internalPubkey'])
            if 'tapscript' in req['tree'][0]:
                tree = TaprootScriptTree.create(
                    Script(req['tree'][0]['tapscript']), nodes, pk)
                if 'internalPubkey' not in req:
                    tapleaf_hash = tree.get_base_hash()
                    resp = {
                        'tapLeafHash': tapleaf_hash,
                        'tapscript': tree.tapscript,
                    }
                else:
                    tap_data = tree.get_taproot_data()
                    addr = AddressUtil.taproot(tree, network=_network)
                    resp = {
                        'tapLeafHash': tap_data[1],
                        'tapscript': tap_data[2],
                        'tweakedPubkey': tap_data[0],
                        'controlBlock': tap_data[3],
                        'address': addr.address,
                        'lockingScript': addr.locking_script,
                    }
                if 'internalPrivkey' in req:
                    tweak_privkey = tree.get_privkey(
                        Privkey(hex=req['internalPrivkey']))
                    resp['tweakedPrivkey'] = tweak_privkey
                nodes = []
                for node in tree.branches:
                    if isinstance(node, TapBranch):
                        nodes.append(node.get_current_hash())
                    else:
                        nodes.append(str(node))
                resp['nodes'] = nodes
            elif 'treeString' in node:
                tree = TapBranch(tree_str=node['treeString'])
            else:
                tree = TapBranch(ByteData(node['branchHash']))
            resp['topBranchHash'] = tree.get_current_hash()
            resp['treeString'] = tree.as_str()

        elif name == 'Address.GetTapScriptTreeInfoByControlBlock':
            tree = TaprootScriptTree.from_control_block(
                ByteData(req['controlBlock']),
                Script(req['tapscript']))
            tap_data = tree.get_taproot_data()
            addr = AddressUtil.taproot(tree, network=_network)
            resp = {
                'tapLeafHash': tap_data[1],
                'tweakedPubkey': tap_data[0],
                'controlBlock': tap_data[3],
                'tapscript': tap_data[2],
                'address': addr.address,
                'lockingScript': addr.locking_script,
            }
            resp['topBranchHash'] = tree.get_current_hash()
            resp['treeString'] = tree.as_str()
            nodes = []
            for node in tree.branches:
                if isinstance(node, TapBranch):
                    nodes.append(node.get_current_hash())
                else:
                    nodes.append(str(node))
            resp['nodes'] = nodes
            if 'internalPrivkey' in req:
                tweak_privkey = tree.get_privkey(
                    Privkey(hex=req['internalPrivkey']))
                resp['tweakedPrivkey'] = tweak_privkey

        elif name == 'Address.GetTapScriptTreeFromString':
            resp = {}
            if 'tapscript' in req:
                nodes = [ByteData(node) for node in req.get('nodes', [])]
                pk = None if 'internalPubkey' not in req else SchnorrPubkey(
                    req['internalPubkey'])
                tree = TaprootScriptTree.from_string(
                    req['treeString'], Script(req['tapscript']), nodes, pk)
                if pk is not None:
                    tap_data = tree.get_taproot_data()
                    addr = AddressUtil.taproot(tree, network=_network)
                    resp = {
                        'tweakedPubkey': tap_data[0],
                        'controlBlock': tap_data[3],
                        'address': addr.address,
                        'lockingScript': addr.locking_script,
                    }
                if 'internalPrivkey' in req:
                    tweak_privkey = tree.get_privkey(
                        Privkey(hex=req['internalPrivkey']))
                    resp['tweakedPrivkey'] = tweak_privkey
                resp['tapLeafHash'] = tree.get_base_hash()
                resp['tapscript'] = tree.tapscript
                nodes = []
                for node in tree.branches:
                    if isinstance(node, TapBranch):
                        nodes.append(node.get_current_hash())
                    else:
                        nodes.append(str(node))
                resp['nodes'] = nodes
            else:
                tree = TapBranch(tree_str=req['treeString'])
            resp['topBranchHash'] = tree.get_current_hash()
            resp['treeString'] = tree.as_str()

        elif name == 'Address.GetTapBranchInfo':
            resp = {}
            nodes = [ByteData(node) for node in req.get('nodes', [])]
            tree = TaprootScriptTree.from_string(
                req['treeString'], Script(req.get('tapscript', '')), nodes)
            branch = tree.branches[req.get('index', 0)]
            resp['tapLeafHash'] = branch.get_base_hash()
            nodes = []
            for node in branch.branches:
                if isinstance(node, TapBranch):
                    nodes.append(node.get_current_hash())
                else:
                    nodes.append(str(node))
            resp['nodes'] = nodes
            resp['topBranchHash'] = branch.get_current_hash()
            resp['treeString'] = branch.as_str()

        elif name == 'Address.AnalyzeTapScriptTree':
            resp = []

            def collect_branch(branch):
                count = len(branch.branches)
                for index, child in enumerate(branch.branches):
                    collect_branch(child)
                    br = TapBranch(hash=branch.get_branch_hash(
                        count - index - 1))
                    resp.append(br)

                if not branch.branches:
                    resp.append(branch)
                elif branch.has_tapscript():
                    br = TapBranch(tapscript=branch.tapscript)
                    resp.append(br)
                else:
                    br = TapBranch(hash=branch.get_base_hash())
                    resp.append(br)

            tree = TapBranch.from_string(req['treeString'])
            collect_branch(tree)

        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        if name == 'Address.AnalyzeTapScriptTree':
            exp_dict = {}
            for exp_data in exp['branches']:
                exp_dict[exp_data['tapBranchHash']] = exp_data
            assert_match(obj, name, case, len(exp['branches']),
                         len(resp), 'list length')
            ret_dict = {}
            for ret_data in resp:
                hash_val = str(ret_data.get_current_hash())
                exp_data = exp_dict.get(hash_val, None)
                if exp_data is None:
                    assert_message(obj, name, case,
                                   f'hash {hash_val} not found.'
                                   + str(exp_dict))
                elif 'tapscript' in exp_data:
                    assert_equal(obj, name, case, exp_data,
                                 str(ret_data.tapscript), 'tapscript')
                ret_dict[hash_val] = ret_data
            assert_match(obj, name, case, len(exp_dict),
                         len(ret_dict), 'hash list length')

        elif isinstance(resp, dict):
            for key, val in resp.items():
                if isinstance(val, list):
                    assert_match(obj, name, case, len(exp[key]),
                                 len(val), f'{key}:Len')
                    for index, list_val in enumerate(val):
                        assert_match(obj, name, case, str(exp[key][index]),
                                     str(list_val), f'{key}:{index}')
                else:
                    assert_equal(obj, name, case, exp, val, key)
        elif isinstance(resp, list):
            assert_match(obj, name, case, len(exp['addresses']),
                         len(resp), 'addressLen')
            if 'pubkeys' in exp:
                assert_match(obj, name, case, len(exp['pubkeys']),
                             len(resp), 'pubkeyLen')
            for index, addr in enumerate(resp):
                assert_match(obj, name, case, exp['addresses'][index],
                             str(addr), 'address')
                assert_match(obj, name, case, exp['pubkeys'][index],
                             str(addr.pubkey), 'pubkey')
        else:
            assert_equal(obj, name, case, exp, str(resp), 'address')
            if name == 'Address.CreateMultisig':
                if ('redeemScript' in exp) and ('witnessScript' in exp):
                    assert_equal(obj, name, case, exp,
                                 resp.redeem_script, 'witnessScript')
                    assert_equal(obj, name, case, exp,
                                 resp.p2sh_wrapped_script, 'redeemScript')
                elif 'witnessScript' in exp:
                    assert_equal(obj, name, case, exp,
                                 resp.redeem_script, 'witnessScript')
                else:
                    assert_equal(obj, name, case, exp,
                                 resp.redeem_script, 'redeemScript')

            elif name == 'Address.Create':
                assert_equal(obj, name, case, exp,
                             resp.p2sh_wrapped_script, 'redeemScript')

            if resp.network == Network.ELEMENTS_REGTEST:
                assert_match(obj, name, case,
                             Network.ELEMENTS_REGTEST.as_str(),
                             resp.network.as_str(), 'network')
            else:
                assert_equal(obj, name, case, exp,
                             resp.network.as_str(), 'network')

            assert_equal(obj, name, case, exp,
                         resp.locking_script, 'lockingScript')
            assert_equal(obj, name, case, exp,
                         resp.hash_type.as_str(), 'hashType')
            assert_equal(obj, name, case, exp,
                         resp.witness_version, 'witnessVersion')

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


def test_pegin_address_func(obj, name, case, req, exp, error):
    try:
        resp = None

        if name == 'PeginAddress.Create':
            ret = AddressUtil.get_pegin_address(
                req.get('fedpegscript', ''),
                pubkey=req.get('pubkey', ''),
                redeem_script=req.get('redeemScript', ''),
                hash_type=req.get('hashType', 'p2sh-p2wsh'),
                mainchain_network=req.get('network', 'mainnet'))
            resp = {
                'mainchainAddress': ret[0],
                'claimScript': ret[1],
                'tweakFedpegscript': ret[2],
            }

        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        if name == 'PeginAddress.Create':
            assert_equal(obj, name, case, exp,
                         str(resp['mainchainAddress']), 'mainchainAddress')
            assert_equal(obj, name, case, exp,
                         str(resp['claimScript']), 'claimScript')
            assert_equal(obj, name, case, exp,
                         str(resp['tweakFedpegscript']), 'tweakFedpegscript')

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


class TestAddress(TestCase):
    def setUp(self):
        self.test_list = load_json_file('address_test.json')

    def test_address(self):
        exec_test(self, 'Address', test_address_func)

    def test_scripttree(self):
        tree = TaprootScriptTree.create(Script('51'))
        tree.add_branch(Script('51'))
        tree.add_branch(Script('51'))
        pk = '0000000000000000000000000000000000000000000000000000000000000001'
        tweakedPk, _, _, ctrlBlock = tree.get_taproot_data(SchnorrPubkey(pk))
        self.assertEqual(
            'e3f3b67db1123a90fa960119099ae04c18b0f6e1f437157739222cd233b21212',
            tweakedPk.hex)
        self.assertEqual(
            'c10000000000000000000000000000000000000000000000000000000000000001a85b2107f791b26a84e7586c28cec7cb61202ed3d01944d832500f363782d675a85b2107f791b26a84e7586c28cec7cb61202ed3d01944d832500f363782d675',  # noqa: E501
            ctrlBlock.hex)


class TestElementsAddress(TestCase):
    def setUp(self):
        self.test_list = load_json_file('elements_address_test.json')

    def test_pegin_address(self):
        exec_test(self, 'PeginAddress', test_pegin_address_func)
