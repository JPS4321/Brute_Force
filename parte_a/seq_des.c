#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/des.h>
#include <stdint.h>
#include <sys/time.h>
#include <ctype.h>

#define MAX_KEY_LEN 7
#define ENCRYPT_MODE 0
#define DECRYPT_MODE 1
#define NAIVE_MODE 2

// Función para medir tiempo
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
    // si viene 'L'/'l', simplemente lo ignoramos
    return v;
}


// uint64_t (56 bits efectivos) -> DES_cblock (MSB en key[0]) + paridad impar
static void u64_to_desblock(uint64_t keynum, DES_cblock out) {
    keynum &= ((1ULL<<56) - 1);            // solo 56 bits efectivos de DES
    for (int i = 0; i < 8; ++i)
        out[i] = (unsigned char)((keynum >> (56 - 8*i)) & 0xFFULL);
    DES_set_odd_parity(out);
}

void encrypt(char *ciph, char *rslt, char *_key, int len){
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
    printf("OG key: ");
    for (int i = 0; i<7; i++){
        printf("%d ", _key[i]);
    }
    printf("\nParity key: ");
    for (int i = 0; i<8; i++){
        printf("%d ", key[i]);
    }
    printf("\n");
    
    if (DES_set_key_checked(&key, &schedule) != 0) {
        fprintf(stderr, "Error: Weak or Invalid key");
        return; // Invalid key
    }

    int blocks = len/8;
    int rem = len%8;
    for (int i = 0; i < blocks; ++i) {
        DES_ecb_encrypt(
            (DES_cblock *)(ciph + i * 8),
            (DES_cblock *)(rslt + i * 8),
            &schedule,
            DES_ENCRYPT
        );
    }

    if (rem > 0) {
        unsigned char last_block[8] = {0};
        memcpy(last_block, ciph + blocks * 8, rem);
        DES_ecb_encrypt(
            (DES_cblock *)last_block,
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

    if (DES_set_key_checked(&key, &schedule) != 0) {
        return; // Invalid key
    }

    int blocks = len/8;
    int rem = len%8;
    for (int i = 0; i < blocks; ++i) {
        DES_ecb_encrypt(
            (DES_cblock *)(ciph + i * 8),
            (DES_cblock *)(rslt + i * 8),
            &schedule,
            DES_DECRYPT
        );
    }

    if (rem > 0) {
        unsigned char last_block[8] = {0};
        memcpy(last_block, ciph + blocks * 8, rem);
        DES_ecb_encrypt(
            (DES_cblock *)last_block,
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
        DES_ecb_encrypt((DES_cblock *)(temp + i*8), 
                       (DES_cblock *)(temp + i*8),
                       &schedule, DES_DECRYPT);
    }
    
    return strstr(temp, search) != NULL;
}

long naive_bruteforce(char *ciph, char *rslt, char *search, int len){
    long upper = (1L << 56);
    long lower = 0;
    long found = 0;

    // Iniciar timer
    double start_time = get_time();
    for(int i = 0; i<upper && (found==0); ++i){
        printf("\r%d keys tested!", i);
        fflush(stdout);
        if(tryKey(i, ciph, search, len)){
            found = i;
            break;;
        }
        if (i % 1000 == 0){
            DES_cblock key;
            uint64_t key64 = (uint64_t)i;
            for (int i = 0; i < 8; ++i) {
                key[7 - i] = (unsigned char)((key64 >> (56 - 8*i)) & 0xFFULL);
            }
            // printf("Key: ");
            // for (int i = 0; i<8; i++){
            //     printf("%d ", key[i]);
            // }
            // printf("\n");
                    
        }
    }
    // Finalizar timer y mostrar
    double end_time = get_time();
    printf("\n\nTime elapsed: %.6f seconds\n", end_time - start_time);
    printf("Keys per second: %.2f\n", (double)found / (end_time - start_time));
    
    return found;
}

int main(int argc, char *argv[]){
    // Argumentos
    if (argc < 4 || argc < 3){
        fprintf(stderr, "Invalid arguments: \'program <source.txt> <encrypt/decrypt/brute> <key/search>\'\n");
        return 1;
    }
    const char *filename = argv[1];
    const char *mode_str = argv[2];
    const char *third = (argc >= 4) ? argv[3] : NULL;

    // Parse Mode
    // 0 = encrypt, 1 = decrypt
    int mode;
    if (strcmp(mode_str, "encrypt") == 0) {
        mode = ENCRYPT_MODE;
    } else if (strcmp(mode_str, "decrypt") == 0) {
        mode = DECRYPT_MODE;
    } else if (strcmp(mode_str, "naive") == 0) {
        mode = NAIVE_MODE;
    }else {
        fprintf(stderr, "Error: mode must be one of ['encrypt', 'decrypt', 'naive']\n");
        return 1;
    }

    // Read source file
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("Error opening file");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);
    char *ciph = malloc(file_size + 1);
    if (!ciph) {
        fclose(f);
        perror("Memory allocation failed");
        return 1;
    }
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
        char *rslt = malloc(file_size + 1);
        printf("\n# === Encrypted === #\n");
        encrypt(ciph, rslt, (char*)third, file_size);

        // Print Result
        for (size_t i = 0; i < file_size; i++) {
            printf("%d ", (unsigned char)rslt[i]);
        }
        printf("\n");
        return 0;
    }

    // 2) Decryption (given a test key)
    if (mode == DECRYPT_MODE){
        // Convert files "02 32 142 ..." into an actual list
        int count = 1;
        for (char *p = ciph; *p; p++) {
            if (*p == ' ') {
                count++;
            };
        }

        unsigned char *prep_ciph = malloc( count + 1 );
        if (!prep_ciph) {
            perror("malloc failed");
            return 1;
        }
        int idx = 0;
        char *token = strtok(ciph, " ");
        while (token != NULL) {
            prep_ciph[idx++] = (unsigned char)atoi(token);
            token = strtok(NULL, " ");
        }

        // Print recognized values
        printf("# === Configurations === #\n");
        printf("Mode: %s (%d)\n", mode_str, mode);
        char key_buffer[MAX_KEY_LEN] = {0};
        strncpy(key_buffer, third, MAX_KEY_LEN - 1);
        printf("Key: \'%s\'\n", key_buffer);
        printf("Cypher Len: %d bytes\n", count);
        printf("Cypher: ");
        for (int i = 0; i <count; i++){
            printf("%d ", prep_ciph[i]);
        }
            
        // Do decrypt
        char *rslt = malloc(count);
        printf("\n\n# === Decrypted === #\n");
        decrypt(prep_ciph, rslt, key_buffer, count);

        // Print Result
        for(int i = 0; i<count; i++){
            printf("%c", rslt[i]);
        }
        
        printf("\n");
        return 0;
    }

    if (mode == NAIVE_MODE){
        // Convert files "02 32 142 ..." into an actual list
        int count = 1;
        for (char *p = ciph; *p; p++) {
            if (*p == ' ') {
                count++;
            };
        }
        unsigned char *prep_ciph = malloc( count + 1 );
        if (!prep_ciph) {
            perror("malloc failed");
            return 1;
        }
        int idx = 0;
        char *token = strtok(ciph, " ");
        while (token != NULL) {
            prep_ciph[idx++] = (unsigned char)atoi(token);
            token = strtok(NULL, " ");
        }

        // Print recognized values
        printf("# === Configurations === #\n");
        printf("Mode: %s (%d)\n", mode_str, mode);
        //char search[MAX_KEY_LEN] = {0};
        // Reemplaza el buffer fijo por un puntero a la cadena completa
        const char *search = third;
        printf("Search Term: '%s'\n", search);
        printf("Cypher Len: %d bytes\n", count);
        printf("Cypher: ");
        for (int i = 0; i <count; i++){
            printf("%d ", prep_ciph[i]);
        }

        printf("\n\n# === Naive === #\n");
        char *rslt = malloc(count);
        long found = naive_bruteforce(prep_ciph, rslt, (char*)search, count);

        DES_cblock found_key;
        uint64_t fkey64 = (uint64_t)found;
        for (int i = 0; i < 8; ++i) {
            found_key[i] = (unsigned char)((fkey64 >> (8*i)) & 0xFFULL);
        }
        printf("\n~ Key found: ");
        
        char found_str[32];
        snprintf(found_str, sizeof(found_str), "%llu", (unsigned long long)found);
        decrypt(prep_ciph, rslt, found_str, count);   // ahora decrypt recibe la clave numérica como string

        DES_cblock kb;
        u64_to_desblock((uint64_t)found, kb);
        for (int i=0;i<8;i++) printf("%u ", (unsigned)kb[i]);
        printf("\n");

        printf("\n~ Message: ");
        for(int i = 0; i<count; i++){
            printf("%c", rslt[i]);
        }
        printf("\n");
        return 0;
    }
    
}