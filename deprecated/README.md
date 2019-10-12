Converting a simple ECDSA code into OpenCL.
add, sub and mult kernel works. need to convert more functions to OpenCL.
to run: gcc main.c -o run -l OpenCL -w
SECP256K1-CL
SECP256K1-CL is a fork of sipa's (Pieter Wuille) optimized ECDSA library for Bitcoin.

The original SECP256K1 is the fastest crypto library working on Bitcoin's curve. On my computer (i7 3770K), it is able to verify a signature in 0.08 ms.
