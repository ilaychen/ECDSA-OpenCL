libsecp256k1
============
Optimized OpenCL library for EC operations on curve secp256k1.

things we've changed so far:
running secp256k1_ecdsa_verify function's tests from tests.c with OpenCL (kernels.cl).



libsecp256k1 is built using autotools:

    $ ./autogen.sh
    $ ./configure
    $ make
    $ ./tests
    $ sudo make install  # optional
