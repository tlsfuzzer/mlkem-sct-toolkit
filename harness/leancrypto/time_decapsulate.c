#include <memory.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <errno.h>

#include <leancrypto.h>

void help(char *name) {
    printf("Usage: %s -i file -o file -k file -n num [-h]\n", name);
    printf("\n");
    printf(" -i file    File with concatenated ciphertexts to decrypt\n");
    printf(" -o file    File where to write the time to decrypt the ciphertext\n");
    printf(" -k file    File with the raw ML-KEM private key format\n");
    printf(" -n num     Length of individual ciphertexts in bytes\n");
    printf(" -h         This message\n");
}

/* Get an architecture specific most precise clock source with the lowest
 * overhead. Should be executed at the start of the measurement period
 * (because of barriers against speculative execution
 */
uint64_t get_time_before() {
    uint64_t time_before = 0;
#if defined( __s390x__ )
    /* The 64 bit TOD (time-of-day) value is running at 4096.000MHz, but
     * on some machines not all low bits are updated (the effective frequency
     * remains though)
     */

    /* use STCKE as it has lower overhead,
     * see http://publibz.boulder.ibm.com/epubs/pdf/dz9zr007.pdf
     */
    //asm volatile (
    //    "stck    %0": "=Q" (time_before) :: "memory", "cc");

    uint8_t clk[16];
    asm volatile (
          "stcke %0" : "=Q" (clk) :: "memory", "cc");
    /* since s390x is big-endian we can just do a byte-by-byte copy,
     * First byte is the epoch number (143 year cycle) while the following
     * 8 bytes are the same as returned by STCK */
    time_before = *(uint64_t *)(clk + 1);
#elif defined( __PPC64__ )
    asm volatile (
        "mftb    %0": "=r" (time_before) :: "memory", "cc");
#elif defined( __aarch64__ )
    asm volatile (
        "mrs %0, cntvct_el0": "=r" (time_before) :: "memory", "cc");
#elif defined( __x86_64__ )
    uint32_t time_before_high = 0, time_before_low = 0;
    asm volatile (
        "CPUID\n\t"
        "RDTSC\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t" : "=r" (time_before_high),
        "=r" (time_before_low)::
        "%rax", "%rbx", "%rcx", "%rdx");
    time_before = (uint64_t)time_before_high<<32 | time_before_low;
#else
#error Unsupported architecture
#endif /* ifdef __s390x__ */
    return time_before;
}

/* Get an architecture specific most precise clock source with the lowest
 * overhead. Should be executed at the end of the measurement period
 * (because of barriers against speculative execution
 */
uint64_t get_time_after() {
    uint64_t time_after = 0;
#if defined( __s390x__ )
    /* The 64 bit TOD (time-of-day) value is running at 4096.000MHz, but
     * on some machines not all low bits are updated (the effective frequency
     * remains though)
     */

    /* use STCKE as it has lower overhead,
     * see http://publibz.boulder.ibm.com/epubs/pdf/dz9zr007.pdf
     */
    //asm volatile (
    //    "stck    %0": "=Q" (time_before) :: "memory", "cc");

    uint8_t clk[16];
    asm volatile (
          "stcke %0" : "=Q" (clk) :: "memory", "cc");
    /* since s390x is big-endian we can just do a byte-by-byte copy,
     * First byte is the epoch number (143 year cycle) while the following
     * 8 bytes are the same as returned by STCK */
    time_after = *(uint64_t *)(clk + 1);
#elif defined( __PPC64__ )
    /* Note: mftb can be used with a single instruction on ppc64, for ppc32
     * it's necessary to read upper and lower 32bits of the values in two
     * separate calls and verify that we didn't do that during low value
     * overflow
     */
    asm volatile (
        "mftb    %0": "=r" (time_after) :: "memory", "cc");
#elif defined( __aarch64__ )
    asm volatile (
        "mrs %0, cntvct_el0": "=r" (time_after) :: "memory", "cc");
#elif defined( __x86_64__ )
    uint32_t time_after_high = 0, time_after_low = 0;
    asm volatile (
        "RDTSCP\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        "CPUID\n\t": "=r" (time_after_high),
        "=r" (time_after_low)::
        "%rax", "%rbx", "%rcx", "%rdx");
    time_after = (uint64_t)time_after_high<<32 | time_after_low;
#else
#error Unsupported architecture
#endif /* ifdef __s390x__ */
    return time_after;
}

int main(int argc, char *argv[]) {
    int result = 1, r_ret;
    size_t key_len = 0;
    size_t ciphertext_len = 0;
    char *key_file_name = NULL, *in_file_name = NULL, *out_file_name = NULL;
    int in_fd = -1, out_fd = -1, key_fd = -1;
    struct lc_kyber_ct lc_ciphertext;
    struct lc_kyber_sk lc_key;
    uint8_t *key = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t secret[32];
    struct lc_kyber_ss lc_secret;
    int opt;
    uint64_t time_before, time_after, time_diff;
    const struct ml_kem_params *params;

    while ((opt = getopt(argc, argv, "i:o:k:n:h")) != -1 ) {
        switch (opt) {
            case 'i':
                in_file_name = optarg;
                break;
            case 'o':
                out_file_name = optarg;
                break;
            case 'k':
                key_file_name = optarg;
                break;
            case 'n':
                sscanf(optarg, "%zi", &ciphertext_len);
                break;
            case 'h':
                help(argv[0]);
                exit(0);
                break;
            default:
                fprintf(stderr, "Unknown option: %c\n", opt);
                help(argv[0]);
                exit(1);
                break;
        }
    }

    if (!in_file_name || !out_file_name || !key_file_name || !ciphertext_len) {
        fprintf(stderr, "Missing parameters!\n");
        help(argv[0]);
        exit(1);
    }

    switch (ciphertext_len) {
    case 768:  // ML-KEM-512
        key_len = 1632;
        break;
    case 1088:  // ML-KEM-768
        key_len = 2400;
        break;
    case 1568:  // ML-KEM-1024
        key_len = 3168;
        break;
    default:
        fprintf(stderr, "Unsupported ciphertext length: %zu\n",
                ciphertext_len);
        goto err;
    }

    in_fd = open(in_file_name, O_RDONLY);
    if (in_fd == -1) {
        fprintf(stderr, "can't open input file %s\n", in_file_name);
        goto err;
    }

    out_fd = open(out_file_name, O_WRONLY|O_TRUNC|O_CREAT, 0666);
    if (out_fd == -1) {
        fprintf(stderr, "can't open output file %s\n", out_file_name);
        goto err;
    }

    fprintf(stderr, "malloc(ciphertext)\n");
    ciphertext = malloc(ciphertext_len);
    if (!ciphertext)
        goto err;
    key = malloc(key_len);
    if (!key)
        goto err;

    fprintf(stderr, "fopen()\n");
    key_fd = open(key_file_name, O_RDONLY);
    if (key_fd == -1) {
        fprintf(stderr, "Can't open key file %s\n", key_file_name);
    }

    fprintf(stderr, "Trying to read: %iB from %s\n", key_len, key_file_name);
    r_ret = read(key_fd, key, key_len);
    if (r_ret != key_len) {
        fprintf(stderr, "Key shorter than expected: %i\n", r_ret);
        fprintf(stderr, "ERRNO: %s\n", strerror(errno));
        goto err;
    }

    close(key_fd);

    r_ret = lc_kyber_sk_load(&lc_key, key, key_len);
    if (r_ret != 0) {
        fprintf(stderr, "lc_kyber_sk_load\n");
        goto err;
    }

    fprintf(stderr, "Decrypting ciphertexts...\n");

    while ((r_ret = read(in_fd, ciphertext, ciphertext_len)) > 0) {
        if (r_ret != ciphertext_len) {
            fprintf(stderr, "read less data than expected (truncated file?)\n");
            goto err;
        }
        r_ret = lc_kyber_ct_load(&lc_ciphertext, ciphertext, ciphertext_len);
        if (r_ret != 0) {
            fprintf(stderr, "lc_kyber_ct_load\n");
            goto err;
        }

        time_before = get_time_before();

        r_ret = lc_kyber_dec(&lc_secret, &lc_ciphertext, &lc_key);

        time_after = get_time_after();

        time_diff = time_after - time_before;

        r_ret = write(out_fd, &time_diff, sizeof(time_diff));
        if (r_ret <= 0) {
            fprintf(stderr, "Write error\n");
            goto err;
        }
    }

    result = 0;
    fprintf(stderr, "finished\n");
    goto out;

    err:
    fprintf(stderr, "failed!\n");
    result = 1;

    out:
    free(key);
    free(ciphertext);
    if (in_fd >= 0)
        close(in_fd);
    if (out_fd >= 0)
        close(out_fd);
    return result;
}
