libsecp256k1
Optimized OpenCL library for EC operations on curve secp256k1.

things we've changed so far: running secp256k1_ecdsa_verify function's tests from tests.c with OpenCL (kernels.cl). Makefile supports OpenCL.

Nearly 50% of the OpenCL code has been succsefully tested, the current function to be tested is: 
secp256k1_ecdsa_verifyX ==> secp256k1_ecdsa_sig_verifyX ==>  secp256k1_ecmultX ==> secp256k1_ecmult_strauss_wnafX

libsecp256k1 is built using autotools:

$ ./autogen.sh
$ ./configure
$ make
$ ./tests
$ sudo make install  # optional
