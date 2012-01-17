#!/usr/bin/env python
"""
Build and install the NaCl wrapper.
"""

import sys, os, platform, re
from distutils.core import setup, Extension

hostname = platform.node()
shost = re.sub(r'[^a-zA-Z0-9]+', '', hostname.split(".")[0])

# http://docs.python.org/library/platform.html#platform.architecture
# recommends this to test the 64-bitness of the current interpreter:
is_64bits = sys.maxsize > 2**32
# My OS-X 10.6 laptop reports platform.uname()[4]=='i386', but
# is_64bits==True, and gcc appears to use -m64 by default. The symptoms of
# getting it wrong are errors during any compilation that tries to use
# libnacl.a:
#  ld: warning: in .../libnacl.a, file is not of required architecture
#  Undefined symbols:
#    "_crypto_hash_sha512_ref", referenced from:
#        _main in ....o
#  ld: symbol(s) not found

# note that system Python will try to compile everything for multiple arches
# at once ("universal binaries"), with "-arch i386 -arch ppc -arch x86_64",
# but each libnacl.a is for just a single arch (there are two copies, in
# lib/x86/ and lib/amd64). So you can expect some harmless "not of required
# architecture" warnings when running setup.py build, probably four:
# (libnacl.a,randombytes.o) * (ppc, i386).

if is_64bits:
    arch='amd64'
else:
    arch='x86'

EMBEDDED_NACL = "nacl-20110221"
BUILD_DIR = os.path.join(EMBEDDED_NACL, "build")
if not os.path.isdir(BUILD_DIR):
    print("""\
It looks like you haven't built NaCl yet. Please do:

 cd %s
 ./do

That will compile in furious silence for a long time (25 minutes on
my 2010 laptop). If you want to watch for progress, look in
%s/*/log .

Then re-run this setup.py command.""") % (EMBEDDED_NACL, BUILD_DIR)
    sys.exit(1)

dirs = os.listdir(BUILD_DIR)
if len(dirs) == 1:
    NACL_DIR = os.path.join(BUILD_DIR, dirs[0])
elif shost in dirs:
    NACL_DIR = os.path.join(BUILD_DIR, shost)
else:
    print("""\
This NaCl directory appears to have been compiled for multiple machines. I
was expecting to use '%s', but found [%s] in:

 %s
""") % (shost, ", ".join(dirs), BUILD_DIR)
    sys.exit(1)

include_dirs = [os.path.join(NACL_DIR, "include", arch)]
library_dirs = [os.path.join(NACL_DIR, "lib", arch)]
extra_objects = [os.path.join(NACL_DIR, "lib", arch, "randombytes.o")]

nacl_module = Extension('_nacl', ['nacl.i'],
                        include_dirs=include_dirs,
                        library_dirs=library_dirs,
                        extra_compiler_args=['-fPIC'],
                        extra_link_args=['-fPIC'],
                        libraries=['nacl'],
                        extra_objects=extra_objects)

setup (name = 'nacl',
       version = '0.1',
       author      = "Sean Lynch",
       description = """Python wrapper for NaCl""",
       ext_modules = [nacl_module],
       py_modules  = ["nacl"])
