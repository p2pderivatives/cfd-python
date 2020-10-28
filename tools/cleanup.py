import os
import shutil
import sys


def rmdir(path):
    if os.path.exists(path):
        print('remove {}'.format(path))
        shutil.rmtree(path, ignore_errors=True)


if __name__ == '__main__':
    if (len(sys.argv) > 1) and (type(sys.argv[1]) is str) and (
            len(sys.argv[1]) > 0):
        rmdir(sys.argv[1])
    else:
        print('usage: python cleanup.py <remove folder path>')
