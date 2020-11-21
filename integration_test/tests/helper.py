from bitcoinrpc.authproxy import AuthServiceProxy


LISTUNSPENT_MAX = 9999999


class RpcWrapper:
    def __init__(self, host='127.0.0.1', port=8432,
                 rpc_user='', rpc_password=''):
        self.rpc_connection = AuthServiceProxy('http://{}:{}@{}:{}'.format(
            rpc_user, rpc_password, host, port))

    def command(self, command, *args):
        return self.rpc_connection.command(args)

    def get_rpc(self):
        return self.rpc_connection


def get_utxo(conn, address_list=[]):
    return conn.listunspent(0, LISTUNSPENT_MAX, address_list)
