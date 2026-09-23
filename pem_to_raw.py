import sys
import getopt
from kyber_py.ml_kem.pkcs import dk_from_pem


def help_msg():
    print(f"""{sys.argv[0]} --in private_key.pem --out-priv priv.bin --out-pub pub.bin

Convert a ML-KEM private key PEM file into a raw expanded key files

 --in file        Input ML-KEM PEM file
 --out-priv file  Output private key file
 --out-pub file   Output public key file
 -h | --help      This message
""")


def main():
    in_file = None
    priv_key = None
    pub_key = None
    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h", [
        "help", "in=", "out-priv=", "out-pub="])
    for opt, arg in opts:
        if opt == "-h" or opt == "--help":
            help_msg()
            sys.exit(0)
        elif opt == "--in":
            in_file = arg
        elif opt == "--out-priv":
            priv_key = arg
        elif opt == "--out-pub":
            pub_key = arg
        else:
            raise ValueError(f"Unknown argument: {opt}")

    if args:
        raise ValueError(f"Unknown arguments: {args}")

    if not all([in_file, priv_key, pub_key]):
        help_msg()
        raise ValueError("Input or output file names missing")

    with open(in_file, "r") as f:
        _, dk, _, ek = dk_from_pem(f.read())

    with open(priv_key, "wb") as f:
        f.write(dk)

    with open(pub_key, "wb") as f:
        f.write(ek)

if __name__ == "__main__":
    main()
