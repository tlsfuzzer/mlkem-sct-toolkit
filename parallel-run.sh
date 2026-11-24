#!/bin/bash

# location of the tlsfuzzer library checkout
export PYTHONPATH=../tlsfuzzer

# where to put the collected data
DST_DIR=/home/test/leancrypto-mlkem/$(uname -m)/$(hostname)/mlkem768
mkdir -p $DST_DIR

# frequency of the clock source in use
TSC=1996.248
# depends on platform
#ENDIAN=big
ENDIAN=little

# number of logical processors to use for test vector generation and value extraction
NPROC=$(nproc --all)

# CPU ID of the isolated core
ISOL_CPU=1

#
# Settings for ML-KEM-512
#

#PEM_KEY="ml-kem-512-ek.pem"
#HARNESS_KEY="ml-kem-512-dk.pem"
#PEM_DK_KEY="ml-kem-512-dk.pem"
#CIPHERTEXT_LEN="768"
#ENCAP_PARAMS=('valid=0' 'valid=1' 'valid=2' 'random=0' 'random=1'
#              "xor_u_coefficient=0 1" "xor_u_coefficient=-1 1"
#              "xor_v_coefficient=0 1" "xor_v_coefficient=-1 1"
#              "one_u_remain=0" "one_u_remain=1"
#              "one_v_remain=0" "one_v_remain=-1")

#
# Settings for ML-KEM-768!
#
PEM_KEY="ml-kem-768-ek.pem"
HARNESS_KEY="ml-kem-768-dk.bin"
PEM_DK_KEY="ml-kem-768-dk.pem"
CIPHERTEXT_LEN="1088"
ENCAP_PARAMS=('valid=0' 'valid=1' 'valid=2' 'random=0' 'random=1'
              "xor_u_coefficient=0 1" "xor_u_coefficient=-1 1"
              "xor_v_coefficient=0 1" "xor_v_coefficient=-1 1"
              'one_u_remain=0' 'one_u_remain=1' 'one_u_remain=2'
              'one_v_remain=0' 'one_v_remain=-1')

#
# Settings for ML-KEM-1024!
#
#PEM_KEY="ml-kem-1024-ek.pem"
#HARNESS_KEY="ml-kem-1024-dk.pem"
#PEM_DK_KEY="ml-kem-1024-dk.pem"
#CIPHERTEXT_LEN="1568"
#ENCAP_PARAMS=('valid=0' 'valid=1' 'valid=2' 'random=0' 'random=1'
#              "xor_u_coefficient=0 1" "xor_u_coefficient=-1 1"
#              "xor_v_coefficient=0 1" "xor_v_coefficient=-1 1"
#              'one_u_remain=0' 'one_u_remain=1' 'one_u_remain=2' 'one_u_remain=3'
#              'one_v_remain=0' 'one_v_remain=-1')


# if re-rerunning the script, bump this number
for RUN in $(seq 0 7); do

    #
    # Generate test vectors
    #
    for i in $(seq 1 $((NPROC-1))); do
        DIR=$DST_DIR/run-$((i+(NPROC*RUN)))
        taskset --cpu-list $i python3 ml_kem_encap.py -o $DIR -c $PEM_KEY -d $PEM_DK_KEY --repeat 10000 "${ENCAP_PARAMS[@]}" & >/dev/null 2>/dev/null
    done
    i=0
    DIR=$DST_DIR/run-$((i+(NPROC*RUN)))
    taskset --cpu-list $i python3 ml_kem_encap.py -o $DIR -c $PEM_KEY -d $PEM_DK_KEY --repeat 10000 --verbose "${ENCAP_PARAMS[@]}"
    wait

    #
    # Execute the test vectors
    #
    for i in $(seq 0 $((NPROC-1))); do
        DIR=$DST_DIR/run-$((i+(NPROC*RUN)))
        echo running $i/$((NPROC-1))
        # LD_LIBRARY_PATH=/root/nettle/install/lib taskset --cpu-list $ISOL_CPU ./harness/nettle/time_decapsulate -i $DIR/ciphers.bin -s $DIR/shared_sec.bin -o $DIR/raw_times.bin -k $HARNESS_KEY -n $CIPHERTEXT_LEN
        LD_LIBRARY_PATH=/usr/local/lib64 taskset --cpu-list $ISOL_CPU ./harness/leancrypto/time_decapsulate -i $DIR/ciphers.bin -s $DIR/shared_sec.bin -o $DIR/raw_times.bin -k $HARNESS_KEY -n $CIPHERTEXT_LEN
    done

    #
    # Extract the data from test vectors
    #
    for i in $(seq 1 $((NPROC-1))); do
        DIR=$DST_DIR/run-$((i+(NPROC*RUN)))
        taskset --cpu-list $i python3 ../tlsfuzzer/tlsfuzzer/extract.py -o $DIR -l $DIR/log.csv --raw-time $DIR/raw_times.bin --binary 8 --endian $ENDIAN --clock-frequency $TSC &>/dev/null &
    done
    i=0
    DIR=$DST_DIR/run-$((i+(NPROC*RUN)))
    taskset --cpu-list $i python3 ../tlsfuzzer/tlsfuzzer/extract.py -o $DIR -l $DIR/log.csv --raw-time $DIR/raw_times.bin --binary 8 --endian $ENDIAN --clock-frequency $TSC
    wait

    echo HW extraction:

    for i in $(seq 1 $((NPROC-1))); do
        DIR=$DST_DIR/run-$((i+(NPROC*RUN)))
        taskset --cpu-list $i python ../tlsfuzzer/tlsfuzzer/extract.py -o $DIR --ml-kem-keys $PEM_DK_KEY --raw-values $DIR/ciphers.bin -l $DIR/log.csv --raw-time $DIR/raw_times.bin --clock-frequency $TSC --binary 8 --endian $ENDIAN &>/dev/null &
    done
    i=0
    DIR=$DST_DIR/run-$((i+(NPROC*RUN)))
    taskset --cpu-list $i python ../tlsfuzzer/tlsfuzzer/extract.py -o $DIR --ml-kem-keys $PEM_DK_KEY --raw-values $DIR/ciphers.bin -l $DIR/log.csv --raw-time $DIR/raw_times.bin --clock-frequency $TSC --binary 8 --endian $ENDIAN --verbose
done

#
# Combine
#
DIR=$DST_DIR/combined
rm -rf $DIR
mkdir $DIR
python ../tlsfuzzer/tlsfuzzer/combine.py -o $DIR $DST_DIR/run*/timing.csv

#
# analyse
#
python3 ../tlsfuzzer/tlsfuzzer/analysis.py -o $DIR --verbose --no-scatter-plot

#
# Then individual parameter data
#
for file in bit-size-min-w bit-size-s-hat-dot-u-hat bit-size-w first-diff-c-c-prime hd-c-c-prime hw-c-prime hw-m-prime hw-r-prime hw-s-hat-dot-u-hat hw-w last-diff-c-c-prime; do
    #
    # combine
    #
    DIR=$DST_DIR/combined-$file
    rm -rf $DIR
    mkdir $DIR
    python ../tlsfuzzer/tlsfuzzer/combine.py -o $DIR --long-format $DST_DIR/run*/measurements-$file.csv

    #
    # analyse
    #
    python3 ../tlsfuzzer/tlsfuzzer/analysis.py -o $DIR --verbose --summary-only --Hamming-weight --minimal-analysis --no-sign-test
done

