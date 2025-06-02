Toolkit for testing ML-KEM implementations for side-channel leakage.


PYTHONPATH=../tlsfuzzer ../tlsfuzzer/venv-py3-opt-deps/bin/python3 ml_kem_encap.py --force -o test-dir/ -c ml-kem-768-ek.pem --repeat 10000 valid=0 valid=1 valid=2 random=0 random=1 xor_u_coefficient="0 1" xor_u_coefficient="-1 1" xor_v_coefficient="0 1" xor_v_coefficient="-1 1" one_u_remain=0 one_u_remain=1 one_u_remain=2 one_v_remain=0 one_v_remain=-1

PYTHONPATH=../tlsfuzzer taskset --cpu-list 0 ../tlsfuzzer/venv-py3-opt-deps/bin/python3 harness/kyber-py/mlkem_decap.py -i test-dir/ciphers.bin -o test-dir/raw_times.csv -k ml-kem-768-dk.pem -n 1088

PYTHONPATH=../tlsfuzzer ../tlsfuzzer/venv-py3-opt-deps/bin/python3 ../tlsfuzzer/tlsfuzzer/extract.py -o test-dir -l test-dir/log.csv --raw-time test-dir/raw_times.csv --clock-frequency 1000

PYTHONPATH=../tlsfuzzer ../tlsfuzzer/venv-py3-opt-deps/bin/python3 ../tlsfuzzer/tlsfuzzer/analysis.py -o test-dir --verbose
