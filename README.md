# ECDSA-OpenCL

This library is a fork of Sipa's Secp256k1 library, currently in use for Bitcoin.
The change we made here is the signature verification unit, we re-wrote it in OpenCL in order for it to be run on a GPU and thus to accelerate signature verification for a Bitcoin block, we wrote the kernel call as well.
The choice of OpenCL as a programming language was to have it run on a wider range of GPUs (unlike with company-owned programming language for GPUs).

We've tested this library in our environment. It has a better throughput than the CPU starting from 2000 signatures.
We've mainly changed secp256k1-latest/src/tests.c and we've created secp256k1-latest/src/k.cl 

To compile it:

1.Download the Git directory.


2.Go inside the secp256k1-latest :

libsecp256k1 is built using autotools:

$ ./autogen.sh $ ./configure $ make $ ./tests $ sudo make install # optional


STATUS: In a near futur, we're going to integrate this library to the Bitcoin-Core and test it.


Copyright Ilay Chen & Yakir Fenton, March 30th 2020.
