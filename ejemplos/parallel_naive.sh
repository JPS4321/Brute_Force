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
mpicc -O2 -Wall -o bin/mpi mpi_des.c -lcrypto 

# Step 3: Encrypt
echo "Encrypting Message w/ key 25923010L:"
./bin/mpi plain_source.txt encrypt 25923010L \
    | tail -n 1 \
    | awk '{$1=$1; print}' \
    > crypt_source.txt

# Step 4 test parallel
echo "Running program:"
mpirun -np 4 ./bin/mpi crypt_source.txt naive "es una prueba de"