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

Para la parte A `cd parte_a/` y crear la carpeta `bin/`
### Bruteforce.c
```
mpicc -Wall -o bin/seq bruteforce.c -lcrypto
mpirun -np <hilos> bin/seq
```

### seq_des.c
```
gcc -o bin/seq seq_des.c -lcrypto
./bin/seq
```
Para este programa se necesitan tener archivos de texto que contengan el contenido indicado

- Encriptar (dada una llave)
  `plain_source.txt` deberia de tener un mensaje identificable, como "hola mundo!"
  ```
    ./bin/seq plain_source.txt encrypt <key>
  ```
- Desencriptar (dada una llave)
    `crypt_source.txt` deberia tener un mesaje encriptado, preferiblemente en formato "142 30 32 152" para evitar hacernos rollos con hexadecimal y ascii.
    ```
        ./bin/seq crypt_source.txt decrypt <key>
    ```
- Naive Bruteforce (dado un termino de busqueda)
    Necesita un `crypt_source.txt` y el search term que sea algo reconocible del mensaje original. Para el ejemplo de "hola mundo!" el search term podria ser cualquier segmento como "ola m" o "mundo" o "hola", etc.
    ```
        ./bin/seq crypt_source.txt naive <search_term>
    ```

