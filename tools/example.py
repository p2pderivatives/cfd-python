from cfd.address import AddressUtil


PUBKEY = '027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af'
SCRIPT_PUBKEY = '76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac'


if __name__ == '__main__':
    addr = AddressUtil.p2pkh(PUBKEY)
    if str(addr) != '1ELuNB5fLNUcrLzb93oJDPmjxjnsVwhNHn':
        print('invalid address: ' + str(addr))
    else:
        print('address: ' + str(addr))
    if str(addr.locking_script) != SCRIPT_PUBKEY:
        print('invalid script: ' + str(addr.locking_script))
    else:
        print('locking script: ' + str(addr.locking_script))
