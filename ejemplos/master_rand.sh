#!/bin/bash
set -e
cd ..
cd parte_b

# Step 1:
cat <<EOF > plain_source.txt
Esta es una prueba de proyecto 2
EOF

# Step 2: Compile the program
echo "Compiling program.c..."
mpicc -O2 -Wall -o bin/mpi_master_rand mpi_master_random.c -lcrypto 

# Step 3: Encrypt
echo "Encrypting Message with key 987654:"
./bin/mpi plain_source.txt encrypt 987654 \
    | tail -n 1 \
    | awk '{$1=$1; print}' \
    > crypt_source.txt

# Step 4 test parallel
echo "Running program:"
mpirun -np 4 ./bin/mpi_master_rand crypt_source.txt "es una prueba de"