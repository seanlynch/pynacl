PyNaCl: A Python Wrapper for NaCl
========================

Overview
--------

This is a simple wrapper for the [NaCl](http://nacl.cace-project.eu/)
cryptographic library (not Google's NativeClient). It currently wraps
crypto\_hash\_sha256, crypto\_hash\_sha512, crypto\_randombytes, and
the crypto\_box, crypto\_sign, crypto\_secretbox, and crypto\_stream
default primitives.


API
---

The API is a very straightforward translation of NaCl's C API. Any
function that returns an error code will raise ValueError if it
returns anything but zero. Output arguments are returned, with keypair
functions returning 2-tuples and everything else returning
strings. The wrapper handles all padding, so you can just ignore that
part of NaCl's documentation.

Eventually I'll translate the documentation over, but for now look at
test.py and the [NaCl documentation](http://nacl.cace-project.eu/).


Installation
----------

First, download and build NaCl. Then:

    export NACL_LIB=<location of libnacl.a and randombytes.o, required>
    export NACL_INCLUDE=<location of NaCl header files>
    python setup.py build_ext
    sudo python setup.py install


Testing
-------

To run the tests, just run the script "test.py" in the distribution directory.
