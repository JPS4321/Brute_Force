#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <openssl/des.h>


// Decryption
void decrypt(long _key, char *ciph, char *rslt, int len){
    // parse key to binary
    DES_cblock key;
    uint64_t key64 = (uint64_t)_key;
    for (int i = 0; i < 8; ++i) {
        key[i] = (unsigned char)((key64 >> (56 - 8*i)) & 0xFFULL);
    }

    // Set parity of key
    DES_set_odd_parity(&key);

    // Validity Check
    DES_key_schedule schedule;
    if (DES_set_key_checked(&key, &schedule) != 0) {
        return; // Invalid key
    }

    //Actual encription
    DES_ecb_encrypt((DES_cblock*)ciph,
                (DES_cblock*)rslt,
                &schedule,
                DES_DECRYPT // ENCRYPT flag
              );
}

void encrypt(long _key, char *ciph, char *rslt, int len){
    // parse key to binary
    DES_cblock key;
    uint64_t key64 = (uint64_t)_key;
    for (int i = 0; i < 8; ++i) {
        key[i] = (unsigned char)((key64 >> (56 - 8*i)) & 0xFFULL);
    }

    // Set parity of key
    DES_set_odd_parity(&key);

    // Validity Check
    DES_key_schedule schedule;
    if (DES_set_key_checked(&key, &schedule) != 0) {
        return; // Invalid key
    }

    DES_ecb_encrypt((DES_cblock*)ciph,
                (DES_cblock*)rslt,
                &schedule,
                DES_ENCRYPT // DECRYPT flag
              );
}


char search[] = " the ";
int tryKey(long key, char *ciph, int len){
  char temp[len+1];
  memcpy(temp, ciph, len);
  temp[len]=0;
  decrypt(key, temp, ciph, len);
  return strstr((char *)temp, search) != NULL;
}

unsigned char cipher[] = {108, 245, 65, 63, 125, 200, 150, 66, 17, 170, 207, 170, 34, 31, 70, 215, 0};
int main(int argc, char *argv[]){ //char **argv
  int N, id;
  long upper = (1L <<56); //upper bound DES keys 2^56
  long mylower, myupper;
  MPI_Status st;
  MPI_Request req;
  int flag;
  int ciphlen = strlen(cipher);
  MPI_Comm comm = MPI_COMM_WORLD;

  MPI_Init(NULL, NULL);
  MPI_Comm_size(comm, &N);
  MPI_Comm_rank(comm, &id);

  int range_per_node = upper / N;
  mylower = range_per_node * id;
  myupper = range_per_node * (id+1) -1;
  if(id == N-1){
    //compensar residuo
    myupper = upper;
  }

  long found = 0;

  MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

  for(int i = mylower; i<myupper && (found==0); ++i){
    printf("\r%d keys tested!", i);
    fflush(stdout);
    if(tryKey(i, (char *)cipher, ciphlen)){
      
      found = i;
      for(int node=0; node<N; node++){
        MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
      }
      break;
    }
  }

  if(id==0){
    MPI_Wait(&req, &st);
    char *result;
    decrypt(found, (char *)cipher, result, ciphlen);
    printf("%li %s\n", found, cipher);
  }

  MPI_Finalize();
}
