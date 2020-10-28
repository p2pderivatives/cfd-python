import sys
from os.path import abspath, join, dirname


def check_version(version):
    lib_ver = ''
    path = join(dirname(abspath(__file__)), '..', 'VERSION')
    with open(path, mode='r') as f:
        lib_ver = f.read()

    tmp_ver = version
    if len(version) > 0 and version[0] == 'v':
        tmp_ver = version[1:]
    if lib_ver == tmp_ver:
        print('match version: {}'.format(tmp_ver))
    else:
        err_msg = 'unmatch version: {}, {}'.format(lib_ver, tmp_ver)
        raise Exception(err_msg)


if __name__ == '__main__':
    if (len(sys.argv) > 1) and (type(sys.argv[1]) is str) and (
            len(sys.argv[1]) > 0):
        check_version(sys.argv[1])
        sys.exit(0)
    else:
        print('usage: python version_checker.py <version>')
        sys.exit(1)
