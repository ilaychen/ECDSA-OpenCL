small testing enviorment
We've extracted all the secp256k1_ecdsa_verify functions into main.c
We've implemented some of the secp256k1_ecdsa functions as kernels in OpenCL and tested them
Only a few functions we're implemented in here because the others need all of the secp256k1 library
to compile - 
gcc main.c -o run -l OpenCL -w
