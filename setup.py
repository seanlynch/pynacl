#!/usr/bin/env python

"""
Documentation!
"""

NACL_INCLUDE = '/Users/seanl/src/nacl-20110221/build/seanlMBP13/include/amd64'
NACL_LIB = '/Users/seanl/src/nacl-20110221/build/seanlMBP13/lib/amd64'

from distutils.core import setup, Extension


nacl_module = Extension('_nacl', ['nacl.i'],
                        include_dirs=[NACL_INCLUDE],
                        library_dirs=[NACL_LIB],
                        libraries=['nacl'],
                        extra_objects=['{0}/randombytes.o'.format(NACL_LIB)],
                        swig_opts=['-I{0}'.format(NACL_INCLUDE)])

setup (name = 'nacl',
       version = '0.1',
       author      = "Sean Lynch",
       description = """Python wrapper for NaCl""",
       ext_modules = [nacl_module],
       py_modules  = ["nacl", "test"])
