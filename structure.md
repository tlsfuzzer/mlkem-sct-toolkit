Structure of the ML-KEM ciphertext
==================================

Both c1. and c2 are compressed byte encodings. c1 is of a 2x1 matrix of
polynomials while c2 is a single polynomial.

The ciphertext at the end is comprised of concatenation of c1 and c2.

Where c1 is the result of compression of u by using d_u bits per element
while c2 is the result of compression of v by using d_v bits per element.


Possible sources of leakage
===========================

Keccack keys
------------
- Hamming weight of the input

NTT and INTT inputs and outputs
-------------------------------
- number of reductions modulo necessary (count of values >= q)
- number of zero values fed to reduction modulo
- bit sizes of values fed to reduction modulo
  - max bit size?
  - weighted average of counts of different bit sizes?
  - sum of bit sizes
  - (see KyberSlash)

ByteDecode and ByteEncode inputs and outputs
--------------------------------------------

Compress and Decompress inputs and outputs
------------------------------------------
- 

Comparison between ciphertext and reconstructed ciphertext
----------------------------------------------------------
- first bit of difference
- last bit of difference
- Hamming distance

Multiplication of polynomials
-----------------------------
- 0, 1 as one of the attacker-controlled values
- number of reductions necessary


References
==========
https://cryptography101.ca/kyber-dilithium/
https://www.chiark.greenend.org.uk/~sgtatham/quasiblog/pq-kem/


Existing vulnerabilities
========================
CVE-2024-37880 - Kyber - expand (decompress) function has secret (the message
  received from decryption) dependant branch

CVE-2024-36405 - Kyber - KyberSlash
