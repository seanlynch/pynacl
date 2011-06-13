#!/usr/bin/env python
"""
Build and install the NaCl wrapper.

Environment variables:

NACL_INCLUDE - location of NaCl's include files. Not needed if they're
               in a normal system location.
NACL_LIB     - location of libnacl.(a|dll) and randombytes.o. Probably
               needed no matter what because of how we find randombytes.o.

"""

import os
from distutils.core import setup, Extension

include_dirs = []
library_dirs = []

NACL_INCLUDE = os.environ.get('NACL_INCLUDE')

if NACL_INCLUDE is not None:
    include_dirs.append(NACL_INCLUDE)

NACL_LIB = os.environ.get('NACL_LIB')

if NACL_LIB is not None:
    library_dirs.append(NACL_LIB)
    extra_objects = ['{0}/randombytes.o'.format(NACL_LIB)]
else:
    # This probably won't work.
    extra_objects = ['randombytes.o']


nacl_module = Extension('_nacl', ['nacl.i'],
                        include_dirs=include_dirs,
                        library_dirs=library_dirs,
                        libraries=['nacl'],
                        extra_objects=extra_objects)

setup (name = 'nacl',
       version = '0.1',
       author      = "Sean Lynch",
       description = """Python wrapper for NaCl""",
       ext_modules = [nacl_module],
       py_modules  = ["nacl"])
