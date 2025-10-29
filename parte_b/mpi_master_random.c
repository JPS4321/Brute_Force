#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <limits.h>
#include <openssl/des.h>
#include <mpi.h>

#define BLOCK_SIZE 500000ULL
#define TAG_WORK 1
#define TAG_STOP 3

void u64_to_desblock(uint64_t keynum, DES_cblock out) {
    keynum &= ((1ULL << 56) - 1);
    for (int i = 0; i < 8; ++i)
        out[i] = (unsigned char)((keynum >> (56 - 8 * i)) & 0xFFULL);
    DES_set_odd_parity(out);
}

int tryKey(uint64_t key, char *ciph, char *search, int len) {
    char temp[len + 1];
    memcpy(temp, ciph, len);
    temp[len] = 0;

    DES_cblock des_key;
    u64_to_desblock(key, des_key);
    DES_key_schedule schedule;

    if (DES_set_key_checked(&des_key, &schedule) != 0) return 0;

    int blocks = len / 8;
    for (int i = 0; i < blocks; ++i)
        DES_ecb_encrypt((const_DES_cblock *)(temp + i * 8),
                        (DES_cblock *)(temp + i * 8),
                        &schedule, DES_DECRYPT);
    return strstr(temp, search) != NULL;
}

void shuffle_u64(uint64_t *a, uint64_t n, unsigned int *seedp) {
    if (n <= 1) return;
    for (uint64_t i = n - 1; i > 0; --i) {
        uint64_t j = (uint64_t)(rand_r(seedp) % (i + 1));
        uint64_t tmp = a[i];
        a[i] = a[j];
        a[j] = tmp;
    }
}

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);

    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    double start_time = 0.0, end_time = 0.0;

    if (argc < 3) {
        if (rank == 0)
            fprintf(stderr, "Uso: mpirun -np <n> ./mpi_windowed_clean <cipher.txt> <search_term> [window_size_in_keys]\n");
        MPI_Finalize();
        return 1;
    }

    const char *filename = argv[1];
    const char *search = argv[2];

    uint64_t default_window_keys = (1ULL << 24);
    uint64_t window_keys = default_window_keys;
    if (argc >= 4) {
        long long tmp = atoll(argv[3]);
        if (tmp > 0) window_keys = (uint64_t) tmp;
    }

    const uint64_t full_space = (1ULL << 56);

    char *ciph = NULL;
    int len = 0;

    if (rank == 0) {
        FILE *f = fopen(filename, "rb");
        if (!f) { perror("Error opening file"); MPI_Abort(MPI_COMM_WORLD, 1); }

        fseek(f, 0, SEEK_END);
        long size_file = ftell(f);
        rewind(f);

        char *buf = (char *)malloc(size_file + 1);
        if (!buf) { fclose(f); perror("malloc"); MPI_Abort(MPI_COMM_WORLD, 1); }

        size_t bytes = fread(buf, 1, size_file, f);
        buf[bytes] = 0;
        fclose(f);

        len = 0;
        for (char *p = buf; *p; ++p)
            if (*p == ' ') ++len;
        len = len + 1;

        ciph = malloc(len);
        if (!ciph) { free(buf); perror("malloc"); MPI_Abort(MPI_COMM_WORLD, 1); }

        int idx = 0;
        char *tok = strtok(buf, " \n\r");
        while (tok) {
            ciph[idx++] = (unsigned char)atoi(tok);
            tok = strtok(NULL, " \n\r");
        }
        free(buf);

        // Formato de salida
        printf("# === Configurations === #\n");
        printf("Processes: %d\n", size);
        printf("Mode: windowed-random\n");
        printf("Search Term: '%s'\n", search);
        printf("Cypher Len: %d bytes\n", len);

        printf("\nCypher:");
        for (int i = 0; i < len; ++i) printf(" %u", (unsigned char)ciph[i]);
        printf("\n");

        printf("\nWindow size: %llu keys (%.2f million keys)\n\n", 
               (unsigned long long)window_keys,
               window_keys / 1e6);
        fflush(stdout);
    }

    MPI_Bcast(&len, 1, MPI_INT, 0, MPI_COMM_WORLD);
    if (rank != 0) {
        ciph = malloc(len);
        if (!ciph) { perror("malloc"); MPI_Abort(MPI_COMM_WORLD, 1); }
    }
    MPI_Bcast(ciph, len, MPI_CHAR, 0, MPI_COMM_WORLD);

    int search_len = strlen(search) + 1;
    MPI_Bcast(&search_len, 1, MPI_INT, 0, MPI_COMM_WORLD);
    char *search_term = malloc(search_len);
    if (!search_term) { perror("malloc"); MPI_Abort(MPI_COMM_WORLD, 1); }
    if (rank == 0) strncpy(search_term, search, search_len);
    MPI_Bcast(search_term, search_len, MPI_CHAR, 0, MPI_COMM_WORLD);

    MPI_Barrier(MPI_COMM_WORLD);
    if (rank == 0) start_time = MPI_Wtime();

    if (rank == 0) {
        unsigned int seed = (unsigned int)time(NULL);
        uint64_t window_start = 0;
        uint64_t found_key = UINT64_MAX;

        uint64_t *block_starts = NULL;
        uint64_t blocks_in_window = 0;
        uint64_t next_block = 0;

        while (window_start < full_space && found_key == UINT64_MAX) {
            uint64_t rem_keys = full_space - window_start;
            uint64_t keys_in_this_window = rem_keys < window_keys ? rem_keys : window_keys;
            blocks_in_window = keys_in_this_window / BLOCK_SIZE;
            if (keys_in_this_window % BLOCK_SIZE) blocks_in_window++;
            if (blocks_in_window == 0) blocks_in_window = 1;

            free(block_starts);
            block_starts = malloc(blocks_in_window * sizeof(uint64_t));
            if (!block_starts) { perror("malloc"); MPI_Abort(MPI_COMM_WORLD, 1); }

            for (uint64_t i = 0; i < blocks_in_window; ++i)
                block_starts[i] = i * BLOCK_SIZE;

            shuffle_u64(block_starts, blocks_in_window, &seed);
            next_block = 0;

            for (int i = 1; i < size && next_block < blocks_in_window; ++i) {
                uint64_t key_start = window_start + block_starts[next_block++];
                MPI_Send(&key_start, 1, MPI_UNSIGNED_LONG_LONG, i, TAG_WORK, MPI_COMM_WORLD);
            }

            while ((next_block < blocks_in_window || 1) && found_key == UINT64_MAX) {
                uint64_t result;
                MPI_Status status;
                MPI_Recv(&result, 1, MPI_UNSIGNED_LONG_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &status);
                int worker = status.MPI_SOURCE;

                if (result != UINT64_MAX && found_key == UINT64_MAX) {
                    found_key = result;
                    for (int w = 1; w < size; ++w)
                        MPI_Send(NULL, 0, MPI_CHAR, w, TAG_STOP, MPI_COMM_WORLD);
                    break;
                }

                if (next_block < blocks_in_window) {
                    uint64_t key_start = window_start + block_starts[next_block++];
                    MPI_Send(&key_start, 1, MPI_UNSIGNED_LONG_LONG, worker, TAG_WORK, MPI_COMM_WORLD);
                } else {
                    break;
                }
            }

            if (found_key != UINT64_MAX) break;
            window_start += window_keys;
            if (window_start >= full_space) break;
        }

        // OUTPUT: RESULTADOS
        printf("\n# === MPI BRUTE RESULT === #\n");
        if (found_key != UINT64_MAX) {
            printf("Key found: %llu (0x%llX)\n", 
                   (unsigned long long)found_key, (unsigned long long)found_key);

            char *message = malloc(len + 1);
            memcpy(message, ciph, len);
            message[len] = 0;

            DES_cblock final_key;
            u64_to_desblock(found_key, final_key);
            DES_key_schedule schedule;
            DES_set_key_checked(&final_key, &schedule);

            for (int i = 0; i < len / 8; ++i)
                DES_ecb_encrypt((const_DES_cblock *)(message + i * 8), (DES_cblock *)(message + i * 8), &schedule, DES_DECRYPT);

            printf("\n~ Key found:");
            for (int i = 0; i < 8; ++i)
                printf(" %u", (unsigned char)((found_key >> (56 - 8 * (i + 1))) & 0xFF));
            printf("\n~ Message: %s\n", message);
            free(message);
        } else {
            printf("Key not found in entire keyspace.\n");
        }

        free(block_starts);
    }

    else {
        uint64_t key_start;
        MPI_Status status;

        while (1) {
            MPI_Recv(&key_start, 1, MPI_UNSIGNED_LONG_LONG, 0, MPI_ANY_TAG, MPI_COMM_WORLD, &status);
            if (status.MPI_TAG == TAG_STOP) break;

            uint64_t result = UINT64_MAX;
            for (uint64_t k = key_start; k < key_start + BLOCK_SIZE; ++k) {
                if (tryKey(k, ciph, search_term, len)) {
                    result = k;
                    break;
                }
            }
            MPI_Send(&result, 1, MPI_UNSIGNED_LONG_LONG, 0, 0, MPI_COMM_WORLD);
        }
    }

    MPI_Barrier(MPI_COMM_WORLD);
    if (rank == 0) {
        end_time = MPI_Wtime();
        printf("\nElapsed (parallel): %.6f s with %d processes\n", end_time - start_time, size);
    }

    free(ciph);
    free(search_term);
    MPI_Finalize();
    return 0;
}
