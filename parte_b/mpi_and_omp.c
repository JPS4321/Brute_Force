#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/des.h>
#include <stdint.h>
#include <sys/time.h>
#include <ctype.h>
#include <mpi.h>
#include <omp.h>

#define MAX_KEY_LEN 7
#define ENCRYPT_MODE 0
#define DECRYPT_MODE 1
#define NAIVE_MODE 2
#define HYBRID_MODE 3

// Función para medir tiempo(el de secuencial)
double get_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}

// ¿la cadena es un entero decimal? (permite trailing 'L'/'l')
static int is_decimal_number(const char *s) {
    while (isspace((unsigned char)*s)) s++;
    if (*s=='+') s++;
    const char *p = s;
    if (!*p) return 0;
    while (*p>='0' && *p<='9') p++;
    // permitir 'L' o 'l' final y nada más
    if (*p=='\0') return 1;
    if ((*p=='L' || *p=='l') && p[1]=='\0') return 1;
    return 0;
}

// parsea decimal a uint64_t e ignora 'L'/'l' final si existe
static uint64_t parse_u64_dec(const char *s) {
    while (isspace((unsigned char)*s) || *s=='+') s++;
    uint64_t v = 0;
    while (*s>='0' && *s<='9') { v = v*10 + (uint64_t)(*s - '0'); s++; }
    return v;
}


// uint64_t (56 bits efectivos) -> DES_cblock (MSB en key[0]) + paridad impar
static void u64_to_desblock(uint64_t keynum, DES_cblock out) {
    keynum &= ((1ULL<<56) - 1);            // solo 56 bits efectivos de DES
    for (int i = 0; i < 8; ++i)
        out[i] = (unsigned char)((keynum >> (56 - 8*i)) & 0xFFULL);
    DES_set_odd_parity(out);
}

void encrypt(char *plain, char *rslt, char *_key, int len){
    DES_cblock key;
    DES_key_schedule schedule;

    // acepta numérica o ASCII sin tronar a palitos
    if (is_decimal_number(_key)) {
        uint64_t kv = parse_u64_dec(_key);
        u64_to_desblock(kv, key);
    } else {
        memset(key, 0, sizeof(DES_cblock));
        memcpy(key, _key, 8);           // ASCII como antes
        DES_set_odd_parity(&key);
    }

    if (DES_set_key_checked(&key, &schedule) != 0) {
        fprintf(stderr, "Error: Weak or Invalid key");
        return; // Invalid key
    }

    int blocks = len/8;
    int rem = len%8;
    for (int i = 0; i < blocks; ++i) {
        DES_ecb_encrypt(
            (const_DES_cblock *)(plain + i * 8),
            (DES_cblock *)(rslt + i * 8),
            &schedule,
            DES_ENCRYPT
        );
    }
    
    if (rem > 0) {
        unsigned char last_block[8] = {0};
        memcpy(last_block, plain + blocks * 8, rem);
        DES_ecb_encrypt(
            (const_DES_cblock *)last_block,
            (DES_cblock *)(rslt + blocks * 8),
            &schedule,
            DES_ENCRYPT
        );
    }
}

void decrypt(char *ciph, char *rslt, char *_key, int len){
    DES_cblock key;
    DES_key_schedule schedule;
    // acepta numérica o ASCII sin tronar a palitos
    if (is_decimal_number(_key)) {
        uint64_t kv = parse_u64_dec(_key);
        u64_to_desblock(kv, key);
    } else {
        memset(key, 0, sizeof(DES_cblock));
        memcpy(key, _key, 8);           // ASCII como antes
        DES_set_odd_parity(&key);
    }

    // más rápido en brute-force:
    DES_set_key_unchecked(&key, &schedule);

    int blocks = len/8;
    int rem = len%8;
    for (int i = 0; i < blocks; ++i) {
        DES_ecb_encrypt(
            (const_DES_cblock *)(ciph + i * 8),
            (DES_cblock *)(rslt + i * 8),
            &schedule,
            DES_DECRYPT
        );
    }
    if (rem > 0) {
        unsigned char last_block[8] = {0};
        memcpy(last_block, ciph + blocks * 8, rem);
        DES_ecb_encrypt(
            (const_DES_cblock *)last_block,
            (DES_cblock *)(rslt + blocks * 8),
            &schedule,
            DES_DECRYPT
        );
    }
}

int tryKey(long _key, char *ciph, char *search, int len){
    char temp[len+1];
    memcpy(temp, ciph, len);
    temp[len]=0;

    DES_cblock key;
    //uint64_t key64 = (uint64_t)_key;
    //for (int i = 0; i < 8; ++i) {
    //    key[7 - i] = (unsigned char)((key64 >> (56 - 8*i)) & 0xFFULL);
    //}
    // for (int i = 0; i<8; i++){
    //     printf("%d ", key[i]);
    // }
    // printf("\n");
    //decrypt(ciph, temp, key, len);
    //return strstr((char *)temp, search) != NULL;
    u64_to_desblock((uint64_t)_key, key);

    DES_key_schedule schedule;
    if (DES_set_key_checked(&key, &schedule) != 0) return 0;

    // decrypt inline
    int blocks = len/8;
    for (int i = 0; i < blocks; ++i) {
        DES_ecb_encrypt((const_DES_cblock *)(temp + i*8),
                        (DES_cblock *)(temp + i*8),
                        &schedule, DES_DECRYPT);
    }

    return strstr(temp, search) != NULL;
}
static uint64_t hybrid_bruteforce(unsigned char *ciph, int len,
                                  const char *search,
                                  int rank, int size, int num_threads) {
    const uint64_t UPPER = (1ULL << 56);
    uint64_t start = (UPPER * (uint64_t)rank) / (uint64_t)size;
    uint64_t end   = (UPPER * (uint64_t)(rank + 1)) / (uint64_t)size;

    uint64_t local_found  = UINT64_MAX;
    uint64_t global_found = UINT64_MAX;

    omp_set_num_threads(num_threads);

    MPI_Barrier(MPI_COMM_WORLD);
    double t0 = MPI_Wtime();

    #pragma omp parallel shared(local_found)
    {
        const char *search_local = search;
        uint64_t thread_found = UINT64_MAX;
        #pragma omp for schedule(dynamic, 1000)
        for (uint64_t k = start; k < end; ++k) {
            #pragma omp cancellation point for
            uint64_t lf_copy;
            #pragma omp atomic read
            lf_copy = local_found;
            if (lf_copy != UINT64_MAX) {
                #pragma omp cancellation point for
                continue;
            }

            if (tryKey((long long)k, (char*)ciph, (char*)search_local, len)) {
                thread_found = k;
                #pragma omp critical
                {
                    if (thread_found < local_found)
                        local_found = thread_found;
                }
                #pragma omp flush(local_found)
                #pragma omp cancel for
            }
        }
    }
    MPI_Allreduce(&local_found, &global_found, 1,
                  MPI_UNSIGNED_LONG_LONG, MPI_MIN, MPI_COMM_WORLD);

    double t1 = MPI_Wtime();

    if (rank == 0) {
        printf("\n# === HYBRID MPI+OpenMP RESULT (CANCEL) === #\n");
        printf("MPI processes: %d, OpenMP threads/process: %d\n", size, num_threads);
        if (global_found != UINT64_MAX)
            printf("Key found: %llu (0x%llX)\n",
                   (unsigned long long)global_found,
                   (unsigned long long)global_found);
        else
            printf("Key NOT found\n");
        printf("Elapsed (hybrid cancel): %.6f s\n", t1 - t0);
    }

    return global_found == UINT64_MAX ? 0ULL : global_found;
}


static uint64_t naive_bruteforce(unsigned char *ciph, int len, const char *search,
                                int rank, int size){
    const uint64_t UPPER = (1ULL << 56);
    // división equitativa (idéntica a tu salida de “división de espacio”)
    uint64_t start = (UPPER * (uint64_t)rank) / (uint64_t)size;
    uint64_t end   = (UPPER * (uint64_t)(rank+1)) / (uint64_t)size;

    // buffer local de trabajo (misma firma que tus funciones)
    char *ciph_local = (char*)ciph;

    // “no encontrado” como infinito (min-reduce lo preserva hasta que alguien encuentra)
    uint64_t local_found  = UINT64_MAX;
    uint64_t global_found = UINT64_MAX;

    const uint64_t CHECK_EVERY = 200000; // reduce overhead de Allreduce
    uint64_t iter_since_check = 0;

    MPI_Barrier(MPI_COMM_WORLD);
    double t0 = MPI_Wtime();

    for (uint64_t k = start; k < end; ++k) {
        // si ya sabemos globalmente que hay solución, salimos
        if (global_found != UINT64_MAX) break;

        if (tryKey((long)k, ciph_local, (char*)search, len)) {
            local_found = k;
            // comunica rápido: el mínimo diferente a UINT64_MAX ganará
            MPI_Allreduce(&local_found, &global_found, 1,
                          MPI_UNSIGNED_LONG_LONG, MPI_MIN, MPI_COMM_WORLD);
            break;
        }

        // chequeo periódico para cortar pronto si otro rank ya encontró
        if (++iter_since_check >= CHECK_EVERY) {
            iter_since_check = 0;
            uint64_t tmp = local_found;
            MPI_Allreduce(&tmp, &global_found, 1,
                          MPI_UNSIGNED_LONG_LONG, MPI_MIN, MPI_COMM_WORLD);
            if (global_found != UINT64_MAX) break;
        }
    }

    // cierre: asegura que todos conocen el hallazgo final
    MPI_Allreduce(&local_found, &global_found, 1,
                  MPI_UNSIGNED_LONG_LONG, MPI_MIN, MPI_COMM_WORLD);

    double t1 = MPI_Wtime();
    if (rank == 0) {
        printf("\n# === MPI BRUTE RESULT === #\n");
        if (global_found != UINT64_MAX) {
            printf("Key found: %llu (0x%llX)\n",
                   (unsigned long long)global_found,
                   (unsigned long long)global_found);
        } else {
            printf("Key NOT found in assigned ranges.\n");
        }
        printf("Elapsed (parallel): %.6f s with %d processes\n", t1 - t0, size);
    }

    return global_found == UINT64_MAX ? 0ULL : global_found;
}

int main(int argc, char *argv[]){
    int rank=0, size=1;

    int provided;
    MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &provided);

    if (provided < MPI_THREAD_MULTIPLE){
        if(rank ==0){
            fprintf(
                stderr, "WARNING: MPI thread support insuficiente!\n"
            );
        }
    }
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    if (argc < 5){
        if (rank == 0) {
            fprintf(stderr,
                "Usage:\n"
                "  %s <source.txt> encrypt <key|number[L]>\n"
                "  %s <source.txt> decrypt <key>\n"
                "  mpirun -np 4 %s <cipher.txt> hybrid \"search term\"\n <threads>\n",
                argv[0], argv[0], argv[0], argv[0]);
        }
        MPI_Finalize();
        return 1;
    }
    const char *filename = argv[1];
    const char *mode_str = argv[2];
    const char *third = (argc >= 4) ? argv[3] : NULL;
    int num_threads;

    // Parse Mode
    // 0 = encrypt, 1 = decrypt
    int mode;
    if (strcmp(mode_str, "encrypt") == 0) {
        mode = ENCRYPT_MODE;
    } else if (strcmp(mode_str, "decrypt") == 0) {
        mode = DECRYPT_MODE;
    } else if (strcmp(mode_str, "naive") == 0) {
        mode = NAIVE_MODE;
    } else if (strcmp(mode_str, "hybrid") == 0) {
        mode = HYBRID_MODE;
        num_threads = atoi(argv[4]);
    }else {
        if (rank == 0) fprintf(stderr, "Error: mode must be one of ['encrypt','decrypt','naive']\n");
        MPI_Finalize();
        return 1;
    }

    // Read source file
    if (mode == ENCRYPT_MODE || mode == DECRYPT_MODE) {
        if (rank != 0) { MPI_Finalize(); return 0; } // otros ranks salen

        // leer archivo plano/cipher
        FILE *f = fopen(filename, "rb");
        if (!f) { perror("Error opening file"); MPI_Finalize(); return 1; }
        fseek(f, 0, SEEK_END);
        long file_size = ftell(f);
        rewind(f);
        char *ciph = (char*)malloc(file_size + 1);
        if (!ciph) { fclose(f); perror("malloc"); MPI_Finalize(); return 1; }
        size_t bytes_read = fread(ciph, 1, file_size, f);
        ciph[bytes_read] = '\0';
        fclose(f);


        // Actual Program
        // 1) Encription
        if (mode == ENCRYPT_MODE){
            // Print recognized values
            printf("# === Configurations === #\n");
            printf("Mode: %s (%d)\n", mode_str, mode);
            //char key_buffer[MAX_KEY_LEN] = {0};
            //strncpy(key_buffer, third, MAX_KEY_LEN - 1);
            printf("Key: '%s'\n", third);
            printf("Chiper Len: %ld bytes\n", file_size);
            printf("Text: \'%s\'\n", ciph);

            // Do encryption
            char *rslt = (char*)malloc(file_size + 1);
            printf("\n# === Encrypted === #\n");
            encrypt(ciph, rslt, (char*)third, file_size);

            // Print Result
            for (size_t i = 0; i < file_size; i++) {
                printf("%d ", (unsigned char)rslt[i]);
            }
            printf("\n");
            free(rslt);
            free(ciph);
            MPI_Finalize();
            return 0;
        }

        // 2) Decryption (given a test key)
        int count = 1;
        for (char *p = ciph; *p; p++) if (*p == ' ') count++;

        unsigned char *prep_ciph = (unsigned char*)malloc(count + 1);
        int idx = 0;
        char *tok, *copy = strdup(ciph);
        for (tok = strtok(copy, " \n\r"); tok; tok = strtok(NULL, " \n\r"))
            prep_ciph[idx++] = (unsigned char)atoi(tok);
        free(copy);

        // Print recognized values
        printf("# === Configurations === #\n");
        printf("Mode: %s (%d)\n", mode_str, mode);
        printf("Key: '%s'\n", third);
        printf("Cypher Len: %d bytes\n", count);
        printf("Cypher: ");
        for (int i=0;i<count;i++) printf("%d ", prep_ciph[i]);

        char *rslt = (char*)malloc(count);
        printf("\n\n# === Decrypted === #\n");
        decrypt((char*)prep_ciph, rslt, (char*)third, count);
        for (int i=0;i<count;i++) printf("%c", rslt[i]);
        printf("\n");

        free(rslt);
        free(prep_ciph);
        free(ciph);
        MPI_Finalize();
        return 0;
    }

    // ====== NAIVE (MPI): rank 0 lee y hace broadcast ======
    // rank 0: lee archivo de cipher "02 32 142 ..."
    unsigned char *prep_ciph = NULL;
    int count = 0;
    if (rank == 0) {
        FILE *f = fopen(filename, "rb");
        if (!f) { perror("Error opening file"); MPI_Abort(MPI_COMM_WORLD, 1); }
        fseek(f, 0, SEEK_END);
        long file_size = ftell(f);
        rewind(f);
        char *buf = (char*)malloc(file_size + 1);
        if (!buf) { fclose(f); perror("malloc"); MPI_Abort(MPI_COMM_WORLD, 1); }
        size_t bytes_read = fread(buf, 1, file_size, f);
        buf[bytes_read] = '\0';
        fclose(f);

        // contar
        count = 1;
        for (char *p = buf; *p; p++) if (*p == ' ') count++;

        prep_ciph = (unsigned char*)malloc(count + 1);
        int idx = 0;
        char *tok, *copy = strdup(buf);
        for (tok = strtok(copy, " \n\r"); tok; tok = strtok(NULL, " \n\r"))
            prep_ciph[idx++] = (unsigned char)atoi(tok);
        free(copy);
        free(buf);
    }

    // broadcast del tamaño y del buffer
    MPI_Bcast(&count, 1, MPI_INT, 0, MPI_COMM_WORLD);
    if (rank != 0) prep_ciph = (unsigned char*)malloc(count + 1);
    MPI_Bcast(prep_ciph, count, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    // cabecera: solo rank 0
    if (rank == 0) {
        // Print recognized values
        printf("# === Configurations === #\n");
        printf("Processes: %d\n", size);
        if (mode == NAIVE_MODE){
            printf("Mode: naive (%d)\n", NAIVE_MODE);
        } else if (mode == HYBRID_MODE){
            printf("Mode: Hibrido (%d), Num_Threads: %d\n", HYBRID_MODE, num_threads);
        }
        
        printf("Search Term: '%s'\n", third);
        printf("Cypher Len: %d bytes\n", count);
        printf("\nCypher: ");
        for (int i=0;i<count;i++) printf("%d ", prep_ciph[i]);
        printf("\n\n");
    }

    // ejecutar búsqueda MPI
    char *rslt = (char*)malloc(count);
    uint64_t found;
    if (mode== NAIVE_MODE){
        found = naive_bruteforce(prep_ciph, count, third, rank, size);
    } else if (mode == HYBRID_MODE){
        found = hybrid_bruteforce(prep_ciph, count, third, rank, size, num_threads);
    }

    // solo rank 0: muestra clave en bytes + mensaje
    if (rank == 0 && found != 0ULL) {
        printf("\n~ Key found: ");
        DES_cblock kb;
        u64_to_desblock((uint64_t)found, kb);
        for (int i=0;i<8;i++) printf("%u ", (unsigned)kb[i]);
        char found_str[32];
        snprintf(found_str, sizeof(found_str), "%llu",
                 (unsigned long long)found);
        decrypt((char*)prep_ciph, rslt, found_str, count);

        printf("\n~ Message: ");
        for(int i = 0; i<count; i++){
            printf("%c", rslt[i]);
        }
        printf("\n");
    }

    free(rslt);
    free(prep_ciph);
    MPI_Finalize();
    return 0;
}