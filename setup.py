"""setuptools configuration for cfd """
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext as build_ext_orig
from os.path import isfile, abspath
import multiprocessing
import subprocess
import platform
import os
import shutil

# definition
CFD_LIB_LIST = ['cfd', 'cfdcore', 'univalue', 'wally']
CFD_SINGLE_LIB_LIST = ['cfd']
CFD_BUILD_DIR = 'cmake_build'
CFD_CONFIGURE_COMMAND = 'cmake -S . -B ' + CFD_BUILD_DIR
CFD_ALL_SHARED_OPTION = ['-DENABLE_SHARED=on']
CFD_SINGLE_SHARED_OPTION = [
    '-DENABLE_SHARED=off',
    '-DCFD_SHARED=on',
]
CFD_CONFIGURE_OPTIONS = [
    '-DENABLE_JS_WRAPPER=off',
    '-DENABLE_CAPI=on',
    '-DENABLE_TESTS=off',
    '-DCMAKE_BUILD_TYPE=Release',
    '-DTARGET_RPATH="{}"',
]
CFD_RPATH_LISTS = [
    '../',
    '@executable_path',
    '../' + CFD_BUILD_DIR + '/Release',
    './' + CFD_BUILD_DIR + '/Release',
    '/usr/local/lib',
    '/usr/local/lib64',
]
CFD_BUILD_COMMAND = 'cmake --build cmake_build --parallel {} --config Release'


class CMakeExtension(Extension):

    def __init__(self, name):
        # don't invoke the original build_ext for this special extension
        super().__init__(name, sources=[])


class _build_ext(build_ext_orig):

    user_options = [
        ('cleanup=', None, 'Cleanup option. [True(default), False]'),
        ('use_installed_lib=', None,
            'Using installed library option. [True, False(default)]'),
    ]

    def initialize_options(self):
        super().initialize_options()
        self.cleanup = 'True'
        self.use_installed_lib = 'False'

    def finalize_options(self):
        super().finalize_options()
        assert self.cleanup in (
            'True', 'False'), 'Invalid cleanup option!'
        assert self.use_installed_lib in (
            'True', 'False'), 'Invalid use_installed_lib option!'

    def initialize_build_options(self):
        def convert_to_bool(bool_opt, default_value):
            if bool_opt == 'True':
                return True
            elif bool_opt == 'False':
                return False
            else:
                return default_value

        self.cleanup = convert_to_bool(self.cleanup, True)
        self.use_installed_lib = convert_to_bool(
            self.use_installed_lib, False)
        self.has_win = platform.system() == 'Windows'
        self.has_mac = platform.system() == 'Darwin'
        self.current_dir = os.path.dirname(abspath(__file__)) + '/'

    def call_cmd(self, cmd):
        print('call: ' + cmd)
        subprocess.check_call(cmd.split(' '), cwd=self.current_dir)

    def link_installed_library(self):
        so_ext = 'dylib' if self.has_mac else 'dll' if self.has_win else 'so'
        so_prefix = '' if self.has_win else 'lib'
        try:
            chk_lib_name = '{}cfd.{}'.format(so_prefix, so_ext)
            root_dir = ''
            if self.has_win:
                paths = os.getenv('PATH').split(';')
                for path in paths:
                    try:
                        fs = os.listdir(path)
                        for f in fs:
                            if f == 'lib' and isfile(
                                    path + '\\lib\\' + chk_lib_name):
                                root_dir = path + '\\lib\\'
                    except WindowsError:
                        pass
            else:
                paths = ['/usr/local/lib/', '/usr/local/lib64/']
                for path in paths:
                    if isfile(path + chk_lib_name):
                        root_dir = path

            success = False
            if isfile(root_dir + chk_lib_name):
                # check all files
                libs = CFD_SINGLE_LIB_LIST if self.has_mac else CFD_LIB_LIST
                for lib_name in libs:
                    so_name = '{}{}.{}'.format(so_prefix, lib_name, so_ext)
                    src_so = os.path.join(root_dir, so_name)
                    success = isfile(src_so)
                    if not success:
                        break
            return success
        except Exception as e:
            print(e)
            return False

    def build_cpp_library(self):
        if os.path.exists(CFD_BUILD_DIR) and self.cleanup:
            shutil.rmtree(CFD_BUILD_DIR, ignore_errors=True)

        # make output dir
        out_dir = self.build_lib + '/cfd'
        os.makedirs(out_dir, exist_ok=True)
        print('output dir: ' + out_dir)

        # configure & build on cmake
        shared_opts = CFD_ALL_SHARED_OPTION
        if self.has_mac:
            shared_opts = CFD_SINGLE_SHARED_OPTION
        shared_opt = ' '.join(shared_opts)
        rpath = './' if self.has_win else abspath(out_dir)
        rpath += ';' + ';'.join(CFD_RPATH_LISTS)
        option = ' '.join(CFD_CONFIGURE_OPTIONS).format(rpath)
        config_cmd = '{} {} {}'.format(
            CFD_CONFIGURE_COMMAND, shared_opt, option)
        self.call_cmd(config_cmd)
        self.call_cmd(CFD_BUILD_COMMAND.format(multiprocessing.cpu_count()))

        # copy library file
        so_ext = 'dylib' if self.has_mac else 'dll' if self.has_win else 'so'
        so_prefix = '' if self.has_win else 'lib'
        target_libs = CFD_SINGLE_LIB_LIST if self.has_mac else CFD_LIB_LIST
        for lib_name in target_libs:
            so_name = '{}{}.{}'.format(so_prefix, lib_name, so_ext)
            src_so = os.path.join(CFD_BUILD_DIR, 'Release', so_name)
            dest_so = os.path.join(out_dir, so_name)
            shutil.copyfile(src_so, dest_so)
            print('copy to: ' + dest_so)

    def run(self):
        # Override build_ext.
        self.initialize_build_options()
        success = False
        if self.use_installed_lib:
            success = self.link_installed_library()
        if not success:
            self.build_cpp_library()
        # skip
        # super().run()


kwargs = {
    'ext_modules': [CMakeExtension('cfd')],  # dummy
    'cmdclass': {'build_ext': _build_ext}
}

setup(**kwargs)
