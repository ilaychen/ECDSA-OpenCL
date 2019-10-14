# ECDSA-OpenCL
Work in progress...
bit_cl is an extracted code of the secp256k1 lib for the signature verification routine. A few function of the code were written in OpenCL and have been softly tested.
secp256k1-opencl is the bitcoin-core's lib for ECDSA with our changes - we've converted some of the signature verification functions into OpenCL and integrated them with the original lib's tests. the original code is now compiled wit OpenCL!
STATUS: debugging the conversion to OpenCL and the integration with the origianl secp256k1.
