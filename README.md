# ECDSA-OpenCL

This library is a fork of Sipa's Secp256k1 library, currently in use for Bitcoin.
The changes we made here is that we took the signature verification unit and re-wrote it in OpenCL in order for it to be run on a GPU and thus to accelerate signature verification for a Bitcoin block.
The choice of OpenCL as a programming language was to have it run on a wider range of GPUs (unlike with company-owned programming language for GPUs).

We've tested this library and in our environment it has a better throughput than with a CPU from a little less than 2000 signatures.
We've mainly changed verify_first/src/tests.c and we've created verify_first/src/k.cl 

To compile it:

1.Download the Git directory.

2.Go inside the verify_first directory and run:


make


To run it, simply write:

./tests



STATUS: In a near futur, we're going to integrate this library to the Bitcoin-Core and test it.


Copyright Ilay Chen & Yakir Fenton, March 30th 2020.
