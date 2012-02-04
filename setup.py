#!/usr/bin/env python
"""
Build and install the NaCl wrapper.

Environment variables:
NACL_DIR     - location of NaCl's main directory. The INCLUDE and LIB
               build directories are found automatically

THESE ENVIRONMENT VARIABLES ARE NOW OPTIONAL
NACL_INCLUDE - location of NaCl's include files. Not needed if they're
               in a normal system location.
NACL_LIB     - location of libnacl.(a|dll) and randombytes.o. Probably
               needed no matter what because of how we find randombytes.o.

"""

import os
import subprocess
from distutils.core import setup, Extension

include_dirs = []
library_dirs = []

def check_output(command, **kwargs):
    p = subprocess.Popen(command, stdout=subprocess.PIPE, **kwargs)
    output, err = p.communicate()
    rc = p.poll()
    if rc:
        raise subprocess.CalledProcessError(rc, command, output=output)
    return output

try:
    arch = check_output("uname -m", shell=True).rstrip().decode("utf8")
except subprocess.CalledProcessError:
    arch = ''

try:
    shost = check_output("hostname | sed 's/\..*//' | tr -cd '[a-z][A-Z][0-9]'", shell=True).rstrip().decode("utf8")
except subprocess.CalledProcessError:
    shost = ''

if arch == 'x86_64':
    arch='amd64'
if arch in ['i686','oi586','i486','i386']:
    arch='x86'

if os.environ.get("NACL_DIR"):
    NACL_DIR = os.environ.get("NACL_DIR").rstrip("/")
else:
    NACL_DIR="."

if os.environ.get("NACL_INCLUDE") == None:
    NACL_INCLUDE = NACL_DIR + '/build/%s/include/%s' % (shost, arch)
else:
    NACL_INCLUDE = os.environ.get("NACL_INCLUDE")

if os.environ.get("NACL_LIB") == None:
    NACL_LIB = NACL_DIR + '/build/%s/lib/%s' % (shost, arch)
else:
    NACL_LIB = os.environ.get("NACL_LIB")

if NACL_INCLUDE is not None:
    include_dirs.append(NACL_INCLUDE)
else:
    include_dirs.append('.')

if NACL_LIB is not None:
    library_dirs.append(NACL_LIB)
    extra_objects = ['{0}/randombytes.o'.format(NACL_LIB)]
else:
    # This probably won't work.
    extra_objects = ['./randombytes.o']


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
