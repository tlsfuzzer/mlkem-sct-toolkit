Toolkit for testing ML-KEM implementations for side-channel leakage.

Note: it is a very early version of it, with a lot of pieces moving around still.
To understand how it works, I highly recommend first getting familiar with the
general timing analysis in `tlsfuzzer`:
https://tlsfuzzer.readthedocs.io/en/latest/timing-analysis.html
and the Marvin toolkit:
https://github.com/tomato42/marvin-toolkit/

Very rough steps to follow:
----------------

Create private keys for the harness to use:
```
openssl genpkey -algorithm ml-kem-768 -out ml-kem-768-dk.pem
openssl pkey -pubout -in ml-kem-768-dk.pem -out ml-kem-768-ek.pem
```
Generate test vectors:
```
PYTHONPATH=../tlsfuzzer ../tlsfuzzer/venv-py3-opt-deps/bin/python3 ml_kem_encap.py --force -o test-dir/ -c ml-kem-768-ek.pem --repeat 10000 valid=0 valid=1 valid=2 random=0 random=1 xor_u_coefficient="0 1" xor_u_coefficient="-1 1" xor_v_coefficient="0 1" xor_v_coefficient="-1 1" one_u_remain=0 one_u_remain=1 one_u_remain=2 one_v_remain=0 one_v_remain=-1
```
Run the system under test/test harness
```
PYTHONPATH=../tlsfuzzer taskset --cpu-list 0 ../tlsfuzzer/venv-py3-opt-deps/bin/python3 harness/kyber-py/mlkem_decap.py -i test-dir/ciphers.bin -o test-dir/raw_times.csv -k ml-kem-768-dk.pem -n 1088
```
Extract the data:
```
PYTHONPATH=../tlsfuzzer ../tlsfuzzer/venv-py3-opt-deps/bin/python3 ../tlsfuzzer/tlsfuzzer/extract.py -o test-dir -l test-dir/log.csv --raw-time test-dir/raw_times.csv --clock-frequency 1000
```
or, with extracting of the intermediate values:
```
PYTHONPATH=~/dev/tlsfuzzer:~/dev/kyber-py/src/ ~/dev/tlsfuzzer/venv-py3-opt-deps/bin/python extract.py -o test-dir --ml-kem-keys ml-kem-768-dk.pem --raw-values test-dir/ciphers.bin -l test-dir/log.csv --raw-time test-dir/raw_times.csv --clock-frequency 1000
```

Analysis of the data:
```
PYTHONPATH=../tlsfuzzer ../tlsfuzzer/venv-py3-opt-deps/bin/python3 ../tlsfuzzer/tlsfuzzer/analysis.py -o test-dir --verbose
```

Analysis of the intermediate values:
```
for file in bit-size-min-w bit-size-s-hat-dot-u-hat bit-size-w first-diff-c-c-prime hd-c-c-prime hw-c-prime hw-m-prime hw-r-prime hw-s-hat-dot-u-hat hw-w last-diff-c-c-prime; do
    mkdir test-dir-$file
    cp test-dir/measurements-$file.csv test-dir-$file/measurements.csv
    PYTHONPATH=../tlsfuzzer ../tlsfuzzer/venv-py3-opt-deps/bin/python3 ../tlsfuzzer/tlsfuzzer/analysis.py -o test-dir-$file/ --verbose --summary-only --Hamming-weight --minimal-analysis --no-sign-test 
done
```
