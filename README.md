PyNaCl: A Python Wrapper for NaCl
========================

Overview
--------

This is a simple wrapper for the [NaCl](http://nacl.cace-project.eu/)
cryptographic library (not Google's NativeClient).


Features
--------

PyNaCl currently wraps the following NaCl functions:

* crypto\_hash\_sha256
* crypto\_hash\_sha512
* crypto\_randombytes

And the following groups of functions (if not otherwise specified by
the suffix, it just wraps the default primitive):

* crypto\_scalarmult\_curve25519
* crypto\_box
* crypto\_sign
* crypto\_secretbox
* crypto\_stream
* crypto\_auth
* crypto\_onetimeauth


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

SWIG is required to generate the wrapper:

    apt-get install swig

Download pynacl with the embedded NaCL (verify it's the latest version):

    git clone git@github.com:seanlynch/pynacl.git

NaCl does not build with the -fPIC flag and therefore you must modify a file:

    cd pynacl/nacl-20110221
    sed -i "s/$/ -fPIC/" okcompilers/c*
    
If you want the build status output printed to screen, you may also do:
    
    sed -i "s/exec 2\?>.*//" do
    
You can then build NaCl with:
    
    ./do

Once NaCl is successfully built, you can run:

    cd ../
    python setup.py build
    sudo python setup.py install

Testing
-------

To run the tests, just run the script "test.py" in the distribution directory.


License
------

PyNaCl is released under version 2.0 of the Apache license.


To do
-----

* Convert to a package so I can add Python code
* Implement a higher-level API
* Implement fromseed versions of other key generation functions
