import sys
import itertools
import re
from os import listdir
from os.path import abspath, join, splitext


def collect_functions(path):
    collecting = False
    func_list = []
    func_cache = ''
    with open(path, mode='r') as f:
        line = f.readline()
        while line:
            if collecting is False:
                if line.find('CFDC_API') != 0:
                    line = f.readline()
                    continue
            offset = line.find(';')
            if offset == -1:
                collecting = True
                func_cache += line.replace('\n', '').replace('\r', '')
            else:
                collecting = False
                func_cache += line[:offset]
                func_list.append(func_cache)
                func_cache = ''
            line = f.readline()
    return func_list


def parse_parameters(param_str):
    parameters = []
    for text in param_str.split(','):
        text = text.strip()
        text = text[:text.rfind(' ')]
        text = text.replace(' *', '*')
        parameters.append(text.strip())
    return parameters


def parse_func(func_str):
    m = re.fullmatch(
        r'^CFDC_API\s+([A-Za-z]+)\s+([A-Za-z0-9]+)\((([^,\);]+(,|\)))+)$',
        func_str)
    if m is None:
        raise Exception('parse fail. func str: ' + func_str)
    # print(m)
    return m.group(2), m.group(1), parse_parameters(m.group(3))


PYTHON_RESPONSE_LIST = [
    ['int', 'c_int'],
]

PYTHON_PARAM_LIST = [
    ['const char*', 'c_char_p'],
    ['char*', 'c_char_p'],
    ['char**', 'c_char_p_p'],
    ['const void*', 'c_void_p'],
    ['void*', 'c_void_p'],
    ['void**', 'c_void_p_p'],
    ['bool*', 'c_bool_p'],
    ['bool', 'c_bool'],
    ['int', 'c_int'],
    ['int*', 'c_int_p'],
    ['int32_t', 'c_int32'],
    ['int32_t*', 'c_int32_p'],
    ['uint32_t', 'c_uint32'],
    ['uint32_t*', 'c_uint32_p'],
    ['int64_t', 'c_int64'],
    ['int64_t*', 'c_int64_p'],
    ['uint64_t', 'c_uint64'],
    ['uint64_t*', 'c_uint64_p'],
    ['unsigned char', 'c_ubyte'],
    ['uint8_t', 'c_uint8'],
    ['uint8_t*', 'c_uint8_p'],
    ['double', 'c_double'],
    ['CfdPsbtRecordType', 'c_int'],
    ['CfdPsbtRecordKind', 'c_int'],
]


def convert_python(name, response_type, request_parameters):
    res_type = response_type
    req_types = '['
    for base, convert_value in PYTHON_RESPONSE_LIST:
        if response_type == base:
            res_type = convert_value
        else:
            raise Exception(
                'unsupported type: ' + response_type + ', func=' + name)
    for param in request_parameters:
        find = False
        for base, convert_value in PYTHON_PARAM_LIST:
            if param == 'void':
                find = True
                break
            if param == base:
                if req_types != '[':
                    req_types += ', '
                req_types += convert_value
                find = True
                break
        if find is False:
            raise Exception('unsupported type: ' + param + ', func=' + name)
    req_types += ']'
    print('        ("{}", {}, {}),  # noqa: E501'.format(name, res_type, req_types))


def convert_func_list(dir_path, type_str):
    func_list = []
    for file in listdir(dir_path):
        _base, ext = splitext(file)
        if ext == '.h':
            functions = collect_functions(abspath(join(dir_path, file)))
            func_list.append(functions)

    convert_func = convert_python
    if type_str == 'python':
        convert_func = convert_python

    func_list = list(itertools.chain.from_iterable(func_list))
    for func in func_list:
        name, res_type, req_types = parse_func(func)
        convert_func(name, res_type, req_types)


if __name__ == '__main__':
    path = './external/cfd/include/cfdc'
    type_str = 'python'
    if (len(sys.argv) > 1) and (type(sys.argv[1]) is str) and (
            len(sys.argv[1]) > 0):
        path = sys.argv[1]
    if (len(sys.argv) > 2) and (type(sys.argv[2]) is str) and (
            len(sys.argv[2]) > 0):
        type_str = sys.argv[2]
    convert_func_list(path, type_str)
