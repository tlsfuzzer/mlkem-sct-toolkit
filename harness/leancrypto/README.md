# Test harness for leancrypto

## Preparation

Setup:
```
dnf install -y --enablerepo='*' meson gcc
```

Sources:
```
git clone --depth=1 https://github.com/smuellerDD/leancrypto.git
```

Compilation and installation
```
meson setup build
meson compile -C build
meson test -C build
meson install -C build
```

Compile the test harness
```
gcc -lleancrypto -o time_decapsulate time_decapsulate.c
```

Convert the private key to format understandable by the test harness:
```
PYTHONPATH=~/dev/tlsfuzzer python pem_to_raw.py --in ml-kem-768-dk.pem --out-priv ml-kem-768-dk.bin --out-pub ml-kem-768-ek.bin
```

## Generate test vectors

(see main README.md)
```
PYTHONPATH=... python ml_kem_encap.py ...
```

## Run the test harness
```
DIR=test-dir
LD_LIBRARY_PATH=.../leancrypto/build/ taskset --cpu-list 1 harness/leancrypto/time_decapsulate -i $DIR/ciphers.bin -o $DIR/raw_times.bin -k ml-kem-768-dk.bin -n 1088
```

## Extract
```
PYTHONPATH=../tlsfuzzer python3 ../tlsfuzzer/tlsfuzzer/extract.py -o $DIR -l $DIR/log.csv --raw-time $DIR/raw_times.bin --binary 8 --endian little --clock-frequency $TSC
```

## Analyse
Run the analysis as in the main README.md
