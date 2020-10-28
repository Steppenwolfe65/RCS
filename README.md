# RCS
The Rijndael-256 authenticated Cipher Stream

An authenticated stream cipher using the wide-block form of Rijndael (Rijndael-256), increased rounds, a cryptographically-strong key schedule, and authentication using KMAC. This cipher can use a 256 or 512-bit key.

This implementation uses a base reference code, or AVX implementations of the cipher. For best performance, set the project properties to the highest available SIMD instruction set supported by your CPU. AVX-512 instructions are fully supported in this implementation and offer the best performance profile.

## Disclaimer
This project contains strong cryptography, before downloading the source files, 
it is your responsibility to check if the extended symmetric cipher key lengths (512 bit and higher), and other cryptographic algorithms contained in this project are legal in your country. 
If you use this code, please do so responsibly and in accordance to law in your region.
