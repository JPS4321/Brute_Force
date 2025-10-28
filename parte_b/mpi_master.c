#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/des.h>
#include <mpi.h>

#define BLOCK_SIZE 500000ULL
#define TAG_WORK 1
#define TAG_DONE 2
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
    for (int i = 0; i < blocks; ++i) {
        DES_ecb_encrypt((const_DES_cblock *)(temp + i * 8),
                        (DES_cblock *)(temp + i * 8),
                        &schedule, DES_DECRYPT);
    }

    return strstr(temp, search) != NULL;
}

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);

    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    if (argc < 3) {
        if (rank == 0)
            fprintf(stderr, "Uso: mpirun -np <n> ./mpi_master <cipher.txt> <search_term>\n");
        MPI_Finalize();
        return 1;
    }

    const char *filename = argv[1];
    const char *search = argv[2];

    char *ciph = NULL;
    int len = 0;

    // Solo rank 0 lee el archivo
    if (rank == 0) {
        FILE *f = fopen(filename, "rb");
        if (!f) { perror("Error opening file"); MPI_Abort(MPI_COMM_WORLD, 1); }

        fseek(f, 0, SEEK_END);
        long size_file = ftell(f);
        rewind(f);
        char *buf = (char *)malloc(size_file + 1);
        fread(buf, 1, size_file, f);
        buf[size_file] = 0;
        fclose(f);

        // contar bytes cifrados
        len = 1;
        for (char *p = buf; *p; p++) if (*p == ' ') len++;

        ciph = malloc(len);
        int idx = 0;
        char *tok = strtok(buf, " \n\r");
        while (tok) {
            ciph[idx++] = (unsigned char)atoi(tok);
            tok = strtok(NULL, " \n\r");
        }
        free(buf);
    }

    MPI_Bcast(&len, 1, MPI_INT, 0, MPI_COMM_WORLD);
    if (rank != 0) ciph = malloc(len);
    MPI_Bcast(ciph, len, MPI_CHAR, 0, MPI_COMM_WORLD);

    int search_len = strlen(search) + 1;
    MPI_Bcast(&search_len, 1, MPI_INT, 0, MPI_COMM_WORLD);
    char *search_term = malloc(search_len);
    strcpy(search_term, search);
    MPI_Bcast(search_term, search_len, MPI_CHAR, 0, MPI_COMM_WORLD);

    // Proceso Master
    if (rank == 0) {
        uint64_t current_key = 0;
        uint64_t found_key = UINT64_MAX;

        int active_workers = size - 1;
        int blocks_sent = 0;  


        // Asignar trabajo inicial
        for (int i = 1; i < size; i++) {
            MPI_Send(&current_key, 1, MPI_UNSIGNED_LONG_LONG, i, TAG_WORK, MPI_COMM_WORLD);
            current_key += BLOCK_SIZE;
        }

        while (active_workers > 0) {
            uint64_t result;
            MPI_Status status;
            MPI_Recv(&result, 1, MPI_UNSIGNED_LONG_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &status);

            int worker = status.MPI_SOURCE;

            if (result != UINT64_MAX && found_key == UINT64_MAX) {
                found_key = result;

                // Detener a todos los Workers
                for (int i = 1; i < size; i++)
                    MPI_Send(0, 0, MPI_CHAR, i, TAG_STOP, MPI_COMM_WORLD);

                break;
            }

            if (found_key == UINT64_MAX) {
                MPI_Send(&current_key, 1, MPI_UNSIGNED_LONG_LONG, worker, TAG_WORK, MPI_COMM_WORLD);

                blocks_sent++;
                printf("[Master] Asignando bloque #%d: claves desde %llu\n",
                    blocks_sent, (unsigned long long)current_key);

                current_key += BLOCK_SIZE;
            } else {
                MPI_Send(0, 0, MPI_CHAR, worker, TAG_STOP, MPI_COMM_WORLD);
            }
        }

        if (found_key != UINT64_MAX) {
            printf("\n[MASTER] Clave encontrada: %llu (0x%llX)\n",
                   (unsigned long long)found_key,
                   (unsigned long long)found_key);
        } else {
            printf("[MASTER] No se encontró clave en el espacio explorado.\n");
        }
    }

    // Proceso Worker
    else {
        uint64_t key_start;
        MPI_Status status;

        while (1) {
            MPI_Recv(&key_start, 1, MPI_UNSIGNED_LONG_LONG, 0, MPI_ANY_TAG, MPI_COMM_WORLD, &status);

            if (status.MPI_TAG == TAG_STOP) break;

            printf("[Worker %d] Probando claves desde %llu hasta %llu\n",
                rank, (unsigned long long)key_start,
                (unsigned long long)(key_start + BLOCK_SIZE - 1));

            uint64_t result = UINT64_MAX;
            for (uint64_t k = key_start; k < key_start + BLOCK_SIZE; k++) {
                if (tryKey(k, ciph, search_term, len)) {
                    result = k;
                    break;
                }
            }

            MPI_Send(&result, 1, MPI_UNSIGNED_LONG_LONG, 0, 0, MPI_COMM_WORLD);
        }
    }

    free(ciph);
    free(search_term);
    MPI_Finalize();
    return 0;
}
