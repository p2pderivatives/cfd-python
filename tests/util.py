import os
import json


def get_json_file(path):
    cur = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(cur, 'data', path), encoding='utf8') as f:
        return json.load(f)


def load_json_file(test_name):
    return get_json_file(test_name)


def load_test(test_list, test_name):
    for test_data in test_list:
        if test_data['name'] == test_name:
            return test_data['cases']
    print(test_list)
    raise Exception('test {} unknown.'.format(test_name))


def load_test_list(test_list, test_name):
    try:
        _dict = {}
        _search_key = test_name + '.'
        for test_data in test_list:
            if test_data['name'] == test_name:
                _dict[test_data['name']] = test_data['cases']
            elif test_data['name'].startswith(_search_key):
                _dict[test_data['name']] = test_data['cases']
        if len(_dict) > 0:
            return _dict
    except TypeError as err:
        print(err)
        raise err
    print(test_list)
    raise Exception('test {} unknown.'.format(test_name))


def exec_test(test_obj, test_name, test_func):
    _dict = load_test_list(test_obj.test_list, test_name)
    for key_name, tests in _dict.items():
        for test_data in tests:
            try:
                if 'capi' in test_data.get('exclude', []):
                    continue
                if 'python' in test_data.get('exclude', []):
                    continue
                is_error = False
                exp_data = test_data.get('expect', {})
                if 'error' in test_data:
                    exp_data = test_data['error']
                    is_error = True
                test_func(test_obj, key_name, test_data['case'],
                          test_data['request'], exp_data, is_error)
            except Exception as e:
                print('error: {}:{}'.format(key_name, test_data['case']))
                raise e


def assert_equal(test_obj, test_name, case, expect, value,
                 param_name='', log_name=''):
    if isinstance(value, bool) or isinstance(value, int):
        _value = value
    else:
        _value = str(value)
    if not param_name:
        err_msg = expect.get('message', '')
        err_msg = expect.get('cfd', err_msg)
        err_msg = expect.get('capi', err_msg)
        err_msg = expect.get('python', err_msg)
        test_obj.assertEqual(
            err_msg, _value,
            'Fail: {}:{}'.format(test_name, case))
    elif param_name in expect:
        if isinstance(
                expect[param_name],
                str) and (
                not isinstance(
                _value,
                str)):
            _value = str(_value)
        fail_param_name = log_name if log_name else param_name
        test_obj.assertEqual(
            expect[param_name], _value,
            'Fail: {}:{}:{}'.format(test_name, case, fail_param_name))


def assert_match(test_obj, test_name, case, expect, value, param_name):
    _value = value
    if isinstance(expect, str) and (not isinstance(_value, str)):
        _value = str(_value)
    test_obj.assertEqual(
        expect, _value,
        'Fail: {}:{}:{}'.format(test_name, case, str(param_name)))


def assert_log(test_obj, test_name, case):
    test_obj.assertTrue(False, 'Fail: {}:{}'.format(test_name, case))


def assert_message(test_obj, test_name, case, msg):
    test_obj.assertTrue(False, 'Fail: {}:{} {}'.format(test_name, case, msg))


def assert_error(test_obj, test_name, case, is_error_pattern, value=''):
    if is_error_pattern:
        append_msg = '' if value == '' else 'result={}'.format(value)
        msg = 'Fail: "{}:{}" not error occurred. {}'.format(
            test_name, case, append_msg)
        test_obj.assertTrue(False, msg)
        raise Exception(msg)
