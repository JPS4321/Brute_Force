## Setting Up
Dependencias del proyecto:
- openssl (libreria DES)
- openmpi

```
sudo apt update

sudo apt install openssl libssl-dev -y
sudo apt install openmpi-bin libopenmpi-dev -y
```

Verificar que tienen todo
```
mpicc --version /
mpirun --version /
openssl version
```

## Compilar / Correr

Para la parte A `cd parte_a/` y crear carpeta `bin/`
- Compilar
```
mpicc -Wall -o bin/seq bruteforce.c -lcrypto
```
- Correr
```
mpirun -np <hilos> bin/seq
```