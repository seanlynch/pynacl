PyNaCl: A Python Wrapper for NaCl
========================

Overview
--------

This is a simple wrapper for the [NaCl](http://nacl.cace-project.eu/)
cryptographic library (not Google's NativeClient). It currently wraps
crypto\_hash\_sha256, crypto\_hash\_sha512, crypto\_randombytes, and
the crypto\_box, crypto\_sign, crypto\_secretbox, crypto\_stream,
crypto\_auth, crypto\_scalarmult and crypto\_onetimeauth default primitives.


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

First, download NaCl. NaCl does not build with the -fPIC flag and
therefore you must modify a file:

    cd <location of extracted NaCl>
    sed -i "s/$/ -fPIC/" okcompilers/c*
    
If you want the build status output printed to screen, you may also do:
    
    sed -i "s/exec 2\?>.*//" do
    
You can then build NaCl with:
    
    ./do

Once NaCl is successfully built, you can clone pynacl and run:

    export NACL_DIR=<location of extracted nacl directory>
    python setup.py build
    sudo python setup.py install

Testing
-------

To run the tests, just run the script "test.py" in the distribution directory.


License
------

PyNaCl is released under version 2.0 of the Apache license.
