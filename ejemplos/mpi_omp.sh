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
mpicc -fopenmp -D_OPENMP=201511 -O2 -Wall -o bin/mpiomp mpi_and_omp.c -lcrypto 

# Step 3: Encrypt
echo "Encrypting Message w/ key 25923010L:"
./bin/mpi plain_source.txt encrypt 25923010L \
    | tail -n 1 \
    | awk '{$1=$1; print}' \
    > crypt_source.txt

# Step 4 test parallel
echo "Running program:"
mpirun -np 4 ./bin/mpiomp crypt_source.txt hybrid "es u" 2