small testing enviorment.
We've extracted all of the secp256k1_ecdsa_verify functions into main.c
We've implemented some of the secp256k1_ecdsa functions as kernels in OpenCL and tested them a bit.
Only a few functions were implemented in here because the others need all of the secp256k1 library.
to compile
gcc main.c -o run -l OpenCL -w
