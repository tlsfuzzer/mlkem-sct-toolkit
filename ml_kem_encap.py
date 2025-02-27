import os
import sys
import getopt
import ecdsa.der as der
import random
from threading import Thread, Event
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
from tlsfuzzer.utils.log import Log
from tlsfuzzer.utils.progress_report import progress_report


if sys.version_info < (3, 8):
    print("This script is compatible with Python 3.8 and later only")
    sys.exit(1)


OIDS = {
    (2, 16, 840, 1, 101, 3, 4, 4, 1): ML_KEM_512,
    (2, 16, 840, 1, 101, 3, 4, 4, 2): ML_KEM_768,
    (2, 16, 840, 1, 101, 3, 4, 4, 3): ML_KEM_1024,
}


def read_ml_kem_pubkey_pem(ek_pem):
    ek_der = der.unpem(ek_pem)
    return read_ml_kem_pubkey_der(ek_der)


def read_ml_kem_pubkey_der(ek_der):
    s1, empty = der.remove_sequence(ek_der)
    if empty != b"":
        raise der.UnexpectedDER("Trailing junk after DER public key")

    alg_id, rem = der.remove_sequence(s1)

    alg_id, rest = der.remove_object(alg_id)
    if alg_id not in OIDS:
        raise der.UnexpectedDER(f"Not recognised algoritm OID: {alg_id}")

    if rest != b"":
        raise der.UnexpectedDER("parameters specified for ML-KEM OID")

    kem = OIDS[alg_id]

    key, empty = der.remove_bitstring(rem, 0)
    if empty != b"":
        raise der.UnexpectedDER("Trailing junk after the public key bitstring")

    return kem, key

def read_ml_key_from_file(filename):

    with open(filename, "rt") as ek_file:
        ek_pem = ek_file.read()

    return read_ml_kem_pubkey_pem(ek_pem)


class CiphertextGenerator(object):
    """
    Class for generating different kinds of ML-KEM ciphertexts.
    """

    types = {}

    def __init__(self, kem, public_key):
        self.kem = kem
        self.key = public_key

    types["valid"] = 1

    def valid(self, gen_id):
        """
        Creates a valid ML-KEM ciphertext.

        gen_id is just to have ability to have duplicate generators
        """
        _, encaps = self.kem.encaps(self.key)
        return encaps

    types["invalid"] = 1

    def invalid(self, gen_id):
        """
        Creates an invalid ML-KEM ciphertext.

        The ciphertext is made invalid by inverting a value or a random
        ciphertext byte.

        gen_id is just to have the ability to have duplicate generators
        """
        _, encaps = self.kem.encaps(self.key)
        encaps = bytearray(encaps)
        pos = random.randint(0, len(encaps) - 1)
        encaps[pos] ^= 0xff
        return encaps

def help_msg():
    print(
"""
{0} -c key.pem [-o dir] ciphertext_name[="param1 param2"] [ciphertext_name]

Generate ciphertexts for testing ML-KEM decapsulation interface against
timing side-channel.

-c key.pem       Path to PEM-encoded ML-KEM encapsulation key.
-o dir           Directory that will contain the generated ciphertexts.
                 "ciphertexts" by default.
--describe=name  Describe the specified probe
--repeat=num     Save the ciphertexts in random order in a single file
                 (ciphers.bin) in the specified directory together with a
                 file specifying the order (log.csv). Used for generating
                 input file for timing tests.
--force          Don't abort when the output dir exists
--verbose        Print status progress when generating repeated probes
--help           This message

Supported probes:
{1}
""".format(sys.argv[0], "\n".join("{0}, args: {1}".format(
    i, j) for i, j in CiphertextGenerator.types.items())))


def gen_timing_probes(out_dir, pub, kem, args, repeat, verbose=False):
    generator = CiphertextGenerator(kem, pub)

    probes = {}
    probe_names = []

    # parse the parameters
    for arg in args:
        ret = arg.split('=')
        if len(ret) == 1:
            name = ret[0]
            params = []
        elif len(ret) == 2:
            name, params = ret
            ret = params.split(' ')
            params = [int(i, 16) if i[:2] == '0x' else int(i) for i in ret]
        else:
            print("ERROR: Incorrect formatting of option: {0}".format(arg))

        if len(params) != generator.types[name]:
            print("ERROR: Incorrect number of parameters specified for probe "
                  "{0}, expected: {1}, got {2}".format(
                      name, generator.types[name], len(params)),
                  file=sys.stderr)
            sys.exit(1)


        method = getattr(generator, name)

        probe_name = "_".join([name] + [str(i) for i in params])

        if probe_name in probes:
            print("ERROR: duplicate probe name and/or parameters: {0}, {1}"
                  .format(name, params))
            sys.exit(1)

        probes[probe_name] = (method, params)
        probe_names.append(probe_name)

    # create an order in which we will write the ciphertexts in
    log = Log(os.path.join(out_dir, "log.csv"))

    log.start_log(probes.keys())

    for _ in range(repeat):
        log.shuffle_new_run()

    log.write()

    # reset the log position
    log.read_log()

    try:
        # start progress reporting
        status = [0, len(probe_names) * repeat, Event()]
        if verbose:
            kwargs = {}
            kwargs['unit'] = ' ciphertext'
            kwargs['delay'] = 2
            progress = Thread(target=progress_report, args=(status,),
                              kwargs=kwargs)
            progress.start()

        with open(os.path.join(out_dir, "ciphers.bin"), "wb") as out:
            # start the ciphertext generation
            for executed, index in enumerate(log.iterate_log()):
                status[0] = executed

                p_name = probe_names[index]
                p_method, p_params = probes[p_name]

                ciphertext = p_method(*p_params)

                out.write(ciphertext)
    finally:
        if verbose:
            status[2].set()
            progress.join()
            print()

    print("done")



if __name__ == "__main__":
    key = None
    kem = None
    out_dir = "ciphertexts"
    repeat = None
    force_dir = False
    verbose = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "c:o:", ["help", "describe=", "repeat=",
                                              "force", "verbose"])
    for opt, arg in opts:
        if opt == "-c":
            kem, key = read_ml_key_from_file(arg)
        elif opt == "-o":
            out_dir = arg
        elif opt == "--help":
            help_msg()
            sys.exit(0)
        elif opt == "--force":
            force_dir = True
        elif opt == "--repeat":
            repeat = int(arg)
        elif opt == "--verbose":
            verbose = True
        elif opt == "--describe":
            try:
                fun = getattr(CiphertextGenerator, arg)
            except Exception:
                help_msg()
                raise ValueError("No ciphertext named {0}".format(arg))
            print("{0}:".format(arg))
            print(fun.__doc__)
            sys.exit(0)
        else:
            raise ValueError("Unrecognised option: {0}".format(opt))

    if not args:
        print("ERROR: No ciphertexts specified", file=sys.stderr)
        sys.exit(1)

    if not key:
        print("ERROR: No encapsulation key specified", file=sys.stderr)
        sys.exit(1)

    if repeat is not None and repeat <= 0:
        print("ERROR: repeat must be a positive integer", file=sys.stder)
        sys.exit(1)

    print("Will save ciphertexts to {0}".format(out_dir))

    try:
        os.mkdir(out_dir)
    except FileExistsError:
        if force_dir:
            pass
        else:
            raise

    if repeat is None:
        single_shot(out_dir, key, kem, args)
    else:
        gen_timing_probes(out_dir, key, kem, args, repeat, verbose)

    print("done")
