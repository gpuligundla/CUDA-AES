#ifndef AES_CPP_H
#define AES_CPP_H

#include <cstdint>
#include <cstddef>

// C++ interface functions
void initGPU();
void freeGPU();
void aesEncrypt(uint8_t *data, const uint8_t *key, size_t dataSize);
void aesDecrypt(uint8_t *data, const uint8_t *key, size_t dataSize);

#endif // AES_CPP_H 