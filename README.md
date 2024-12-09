# A simple AES Encryption and Decryption using CUDA

This is a simple implementation of AES encryption and decryption using CUDA. It 
uses the AES 128 bit encryption and decryption with PKCS7 padding.

It uses the parallel processing power of the GPU to encrypt and decrypt the data. The data is divided into chunks and processed in parallel. 

Disclaimer: This is a simple implementation for educational purposes. It is not for production use.

# TODO
- Improve the pipeline to reduce the memory transfer overhead.
- Try other ways to read/write a large file(mmap, direct IO etc.) for better performance.
- Add support for AES 192 and 256 bit encryption and decryption.
- Add support for other padding schemes

## Dependencies
- CUDA
- nvcc
- C++11

## Compile and Run
To compile the program, use the following command:
```
make
```
To generate the 128 bit key, use the following command:
```
make genkey
```
To encrypt the data, use the following command:
```
./aes_cuda -e <input_file> <output_file>
```
To decrypt the data, use the following command:
```
./aes_cuda -d <input_file> <output_file>
```


## Miscellaneous
To generate a random file to test the program, use the following command:
```
dd if=/dev/urandom bs=1M count=1024 | base64 > random_text_file.txt
```
To generate a 1GB file with plain text to test the program, use the following command:
```
yes "This is a plain text file used for AES" | head -c 1G > random_text_file.txt
```
To check the performance of the program, use the following command:
```
nvprof ./aes_cuda -e random_text_file.txt random_text_file_encrypted.txt
```
