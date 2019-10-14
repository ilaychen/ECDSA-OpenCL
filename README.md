# ECDSA-OpenCL

Work in progress...

secp256k1-opencl is the bitcoin-core's lib for ECDSA with our changes - we've converted some of the signature verification functions into OpenCL and integrated them with the original lib's tests.

bit_cl is an extracted code of the secp256k1 lib for the signature verification routine. A few functions of the code were implemented in OpenCL and have been softly tested.

deprecated is the first simple ECDSA C code with an implementation in OpenCL

STATUS: we're implementing and debugging the OpenCL code and the integration with the original secp256k1 lib.
