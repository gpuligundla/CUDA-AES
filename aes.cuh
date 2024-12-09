#ifndef AES_CUDA_H
#define AES_CUDA_H

#include <cuda.h>
#include <cuda_runtime.h>
#include "aes.h"


// Global pinned memory variables
extern uint8_t* g_pinned_memory;
extern size_t g_pinned_memory_size;

// CUDA-specific declarations
__global__ void aesEncryptKernel(uint8_t *data, const uint8_t *roundKeys, int numBlocks);
__global__ void aesDecryptKernel(uint8_t *data, const uint8_t *roundKeys, int numBlocks);

__device__ void addRoundKey(uint8_t *state, const uint8_t *roundKey);
__device__ void subBytes(uint8_t *state, const uint8_t *sbox);
__device__ void invSubBytes(uint8_t *state, const uint8_t *invSbox);
__device__ void shiftRows(uint8_t *state);
__device__ void invShiftRows(uint8_t *state);
__device__ void mixColumns(uint8_t *state);
__device__ void invMixColumns(uint8_t *state);


// CUDA error checking macro
#define CUDA_CHECK(call) \
    do { \
        cudaError_t error = call; \
        if (error != cudaSuccess) { \
            throw std::runtime_error(std::string("CUDA error: ") + \
                                   cudaGetErrorString(error)); \
        } \
    } while(0)

#endif // AES_CUDA_H
