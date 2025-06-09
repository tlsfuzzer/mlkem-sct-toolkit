OpenSSL test harness for testing ML-KEM


Compile with:
```
gcc -lcrypto -o time_decapsulate time_decapsulate.c
```

Generate test vectors as in main readme

Run with:
```
taskset --cpu-list 4 ./harness/openssl/time_decapsulate -i test-dir/ciphers.bin -o test-dir/raw_times.bin -k ml-kem-768-dk.pem -n 1088
```

Extract the data:
```
PYTHONPATH=../tlsfuzzer ../tlsfuzzer/venv-py3-opt-deps/bin/python3 ../tlsfuzzer/tlsfuzzer/extract.py -o test-dir -l test-dir/log.csv --raw-time test-dir/raw_times.bin --binary 8 --clock-frequency 3417.600
```

or:
```
PYTHONPATH=../tlsfuzzer:../kyber-py/src/ ../tlsfuzzer/venv-py3-opt-deps/bin/python extract.py -o test-dir --ml-kem-keys ml-kem-768-dk.pem --raw-values test-dir/ciphers.bin -l test-dir/log.csv --raw-time test-dir/raw_times.csv --binary 8 --clock-frequency 3417.600
```

Continue analysis as in main readme
