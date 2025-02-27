import sys
import getopt
import time
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

OIDS = {
    (2, 16, 840, 1, 101, 3, 4, 4, 1): ML_KEM_512,
    (2, 16, 840, 1, 101, 3, 4, 4, 2): ML_KEM_768,
    (2, 16, 840, 1, 101, 3, 4, 4, 3): ML_KEM_1024,
}

import ecdsa.der as der

def mlkem_ek_file_read(filename):
    with open(filename, "rt") as ek_file:
        ek_pem = ek_file.read()

    return mlkem_ek_pem_read(ek_pem)

def mlkem_ek_pem_read(ek_pem):
    ek_der = der.unpem(ek_pem)
    return mlkem_ek_der_read(ek_der)


def mlkem_ek_der_read(ek_der):
    s1, empty = der.remove_sequence(ek_der)
    if empty != b"":
        raise der.UnexpectedDER("Trailing junk after DER public key")

    ver, rest = der.remove_integer(s1)

    if ver != 0:
        raise der.UnexpectedDER("Unexpected format version")

    alg_id, rest = der.remove_sequence(rest)

    alg_id, empty = der.remove_object(alg_id)
    if alg_id not in OIDS:
        raise der.UnexpectedDER(f"Not recognised algoritm OID: {alg_id}")
    if empty != b"":
        raise der.UnexpectedDER("parameters specified for ML-KEM OID")

    kem = OIDS[alg_id]

    key_der, empty = der.remove_octet_string(rest)
    if empty != b"":
        raise der.UnexpectedDER("Trailing junk after the key")

    if len(key_der) == 64:
        _, dk = kem.key_derive(key_der)

        return kem, dk

    keys, empty = der.remove_octet_string(key_der)
    if empty != b"":
        raise der.UnexpectedDER("Trailing junk after the key")

    dk_len = 768 * kem.k + 96
    dk, ek = keys[:dk_len], keys[dk_len:]
    assert len(ek) == 384 * kem.k + 32

    return kem, dk


def help_msg():
    print("""
timing.py -i file -o file -k file -n size

-i file      File with the ciphertexts to decrypt
-o file      File to write the timing data to
-k file      The private key to use for decryption
-n size      Size of individual ciphertexts for decryption
-h | --help  this message
""")


if __name__ == '__main__':
    in_file = None
    out_file = None
    key_file = None
    read_size = None

    argv = sys.argv[1:]
    if not argv:
        help_msg()
        sys.exit(1)
    opts, args = getopt.getopt(argv, "i:o:k:n:h", ["help"])

    for opt, arg in opts:
        if opt == "-h" or opt == "--help":
            help_msg()
            sys.exit(0)
        elif opt == "-i":
            in_file = arg
        elif opt == "-o":
            out_file = arg
        elif opt == "-k":
            key_file = arg
        elif opt == "-n":
            read_size = int(arg)
        else:
            raise ValueError("Unrecognised parameter: {0} {1}"
                             .format(opt, arg))

    if not in_file:
        print("ERROR: no input file specified (-i)", file=sys.stderr)
        sys.exit(1)

    if not out_file:
        print("ERROR: no output file specified (-o)", file=sys.stderr)
        sys.exit(1)

    if not key_file:
        print("ERROR: no key file specified (-k)", file=sys.stderr)
        sys.exit(1)

    if not read_size:
        print("ERROR: size of ciphertexts unspecified (-n)", file=sys.stderr)
        sys.exit(1)

    kem, priv_key = mlkem_ek_file_read(key_file)

    with open(in_file, "rb") as in_fd:
        with open(out_file, "w") as out_fd:
            out_fd.write("raw times\n")

            while True:
                ciphertext = in_fd.read(read_size)
                if not ciphertext:
                    break

                time_start = time.monotonic_ns()

                plaintext = kem.decaps(priv_key, ciphertext)

                diff = time.monotonic_ns() - time_start

                out_fd.write("{0}\n".format(diff))

    print("done")
