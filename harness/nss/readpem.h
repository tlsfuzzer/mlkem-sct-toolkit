/* read a pem file and return a SECKEYPrivateKey */
#include <stdio.h>
#include <keythi.h>

SECKEYPrivateKey *read_PrivateKey(FILE *fp);
