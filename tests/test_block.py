from unittest import TestCase
from tests.util import load_json_file, exec_test,\
    assert_equal, assert_error, assert_match
from cfd.util import CfdError
from cfd.block import Block


def test_block_func(obj, name, case, req, exp, error):
    try:
        block = ''
        if req.get('isElements', False):
            raise Exception('isElements=True not support. name: ' + name)
        else:
            block = Block(req['block'])

        if name == 'Block.GetBlockInfo':
            hash = block.get_blockhash()
            header = block.get_header()
            txid_list = block.get_txid_list()
            txs = [str(txid) for txid in txid_list]
            resp = {
                'blockHash': str(hash),
                'tx': txs,
                'version': header.version,
                'previousblockhash': str(header.prev_block_hash),
                'merkleroot': str(header.merkleroot),
                'time': header.time,
                'bits': header.bits,
                'nonce': header.nonce,
            }
        elif name == 'Block.GetTxDataFromBlock':
            tx, txoutproof = block.get_tx_data(req['txid'])
            resp = {'tx': str(tx), 'txoutproof': str(txoutproof)}
        elif name == 'Block.ExistTxid':
            exist = block.exist_txid(req['txid'])
            resp = {'exist': exist}
        elif name == 'Block.GetTxCount':
            count = block.get_tx_count()
            resp = {'count': count}
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        if name == 'Block.GetBlockInfo':
            assert_equal(obj, name, case, exp, resp['blockHash'], 'blockHash')
            assert_equal(obj, name, case, exp, resp['version'], 'version')
            assert_equal(obj, name, case, exp,
                         resp['previousblockhash'], 'previousblockhash')
            assert_equal(obj, name, case, exp,
                         resp['merkleroot'], 'merkleroot')
            assert_equal(obj, name, case, exp, resp['time'], 'time')
            assert_equal(obj, name, case, exp, resp['bits'], 'bits')
            assert_equal(obj, name, case, exp, resp['nonce'], 'nonce')
            assert_match(obj, name, case, len(
                exp['tx']), len(resp['tx']), 'tx.len')
            for i in range(len(exp['tx'])):
                assert_match(obj, name, case,
                             exp['tx'][i], resp['tx'][i], f'tx.len.{i}')
        elif ('tx' in resp) and isinstance(resp['tx'], str):
            assert_equal(obj, name, case, exp, resp['tx'], 'tx')

        assert_equal(obj, name, case, exp,
                     resp.get('txoutproof', ''), 'txoutproof')
        assert_equal(obj, name, case, exp, resp.get('exist', False), 'exist')
        assert_equal(obj, name, case, exp, resp.get('count', 0), 'count')

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


class TestBlock(TestCase):
    def setUp(self):
        self.test_list = load_json_file('block_test.json')

    def test_block(self):
        exec_test(self, 'Block', test_block_func)
