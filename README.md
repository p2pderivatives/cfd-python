# Crypto Finance Development Kit for Python (CFD-PYTHON)

## Dependencies

- Python(CPython) (3.6 or higher)
- C/C++ Compiler
  - can compile c++11
- CMake (3.14.3 or higher)

### Windows

download and install files.
- [Python](https://www.python.org/)
- [CMake](https://cmake.org/) (3.14.3 or higher)
- MSVC
  - [Visual Studio](https://visualstudio.microsoft.com/downloads/) (Verified version is 2017 or higher)
  - [Build Tools for Visual Studio](https://visualstudio.microsoft.com/downloads/) (2017 or higher)
  - (Using only) [msvc redistribution package](https://support.microsoft.com/help/2977003/the-latest-supported-visual-c-downloads)

### MacOS

- [Homebrew](https://brew.sh/)

```Shell
# xcode cli tools
xcode-select --install

# install dependencies using Homebrew
brew install cmake python
```

### Linux(Ubuntu)

```Shell
# install dependencies using APT package Manager
apt-get install -y build-essential cmake python3 python3-dev 
(Ubuntu 20.04 or higher) apt-get install -y python-is-python3
curl https://sh.rustup.rs -sSf | sh  (select is 1)
```

cmake version 3.14.2 or lower, download from website and install cmake.
(https://cmake.org/download/)

### pip install

First update pip:
```
python -m pip install -U --user pip
  or
python3 -m pip install -U --user pip
```

Then install the required packages:
```
pip install --user wheel pipenv
```

### setup pipenv

use pipenv (for developer):
```
pipenv install -d
```

---

## pip install / uninstall

attention: [using python 3.7 or lower on windows](#using-python-37-or-lower-on-windows)

### install from GitHub

```
pip install --user git+https://github.com/cryptogarageinc/cfd-python@master
```

### install from source code

Using unpack source code:
```Shell
pip install --user .
```

### install from wheel

1. get releases asset. (ex. https://github.com/cryptogarageinc/cfd-python/releases/download/v0.0.1/cfd-0.0.1-py3-none-win_amd64.whl )
2. install pip
   ```
   pip install --user cfd-0.0.1-py3-none-win_amd64.whl
   ```

### uninstall

```
pip uninstall -y cfd
```

---

## Build native library on local

### build

use python:
```
python setup.py build
  or
(ubuntu 18.04) python3 setup.py build
```

use pipenv:
```
pipenv run build
  or
(ubuntu 18.04) pipenv run build3
```

### cleanup

```
rm -rf cmake_build
  or
pipenv run cleanup
```

## packaging

### sdist file

```
python ./setup.py sdist
```

### wheel file

```
pip wheel .
```

---

## Test

### Test

use python:
```
python -m unittest discover -v tests
  or
(ubuntu 18.04) python3 -m unittest discover -v tests
```

use pipenv:
```
pipenv run test
  or
(ubuntu 18.04) pipenv run test3
```

---

## Information for developers

### using library

- cfd
  - cfd-core
    - [libwally-core](https://github.com/cryptogarageinc/libwally-core/tree/cfd-develop) (forked from [ElementsProject/libwally-core](https://github.com/ElementsProject/libwally-core))
    - [univalue](https://github.com/jgarzik/univalue) (for JSON encoding and decoding)

### formatter

- autopep8
  use pipenv:
  ```
  pipenv run format
  ```

### linter

- flake8
  use pipenv:
  ```
  pipenv run lint
  ```

### document tool

- doxygen

### support compilers

- Visual Studio (2017 or higher)
- Clang (7.x or higher)
- GCC (5.x or higher)

---

## Note

### using python 3.7 or lower on windows

When using Python 3.7 or lower on Windows, it is necessary to add the install destination to the environment variable PATH. (Must be persistent.)

The path to add must specify where to install cfd, as in the following example:
```
C:\Users\DummyUser\AppData\Local\Programs\Python\Python37\Lib\site-packages\cfd
```

### Git connection:

Git repository connections default to HTTPS.
However, depending on the connection settings of GitHub, you may only be able to connect via SSH.
As a countermeasure, forcibly establish SSH connection by setting `CFD_CMAKE_GIT_SSH=1` in the environment variable.

- Windows: (On the command line. Or set from the system setting screen.)
```
set CFD_CMAKE_GIT_SSH=1
```

- MacOS & Linux(Ubuntu):
```
export CFD_CMAKE_GIT_SSH=1
```

### Ignore git update for CMake External Project:

Depending on your git environment, you may get the following error when checking out external:
```
  Performing update step for 'libwally-core-download'
  Current branch cmake_build is up to date.
  No stash entries found.
  No stash entries found.
  No stash entries found.
  CMake Error at /workspace/cfd-core/build/external/libwally-core/download/libwally-core-download-prefix/tmp/libwally-core-download-gitupdate.cmake:133 (message):


    Failed to unstash changes in:
    '/workspace/cfd-core/external/libwally-core/'.

    You will have to resolve the conflicts manually
```

This phenomenon is due to the `git update` related command.
Please set an environment variable that skips update processing.

- Windows: (On the command line. Or set from the system setting screen.)
```
set CFD_CMAKE_GIT_SKIP_UPDATE=1
```

- MacOS & Linux(Ubuntu):
```
export CFD_CMAKE_GIT_SKIP_UPDATE=1
```

### Precautions when creating a wheel file

(May not be needed if using pip wheel)
If it does not work properly, discard the wheel on the python2 side and set PYTHONPATH:
```
export PYTHONPATH=$PYTHONPATH:~/.local/lib/python3.6/site-packages/wheel
```

If you are using WSL, you also need to set the access permissions on the Windows side. Check out the following issues:
- https://github.com/pypa/packaging-problems/issues/258
