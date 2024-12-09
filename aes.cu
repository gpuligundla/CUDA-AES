/*
This is a implementation of AES encryption and decryption in CUDA.
It uses the parallelization capabilities of CUDA to encrypt and decrypt data.
This is a kind of light weight implementation of AES. It cant be used for any real world application.
*/
#include <iostream>
#include <string>
#include <stdexcept>
#include <algorithm>
#include "aes.cuh"
#include "aes_constants.h"

// constant variables
__constant__ uint8_t d_SBOX[256];
__constant__ uint8_t d_INV_SBOX[256];
__constant__ uint8_t d_RCON[10];
__constant__ uint8_t d_MUL2[256];
__constant__ uint8_t d_MUL3[256];
__constant__ uint8_t d_MUL9[256];
__constant__ uint8_t d_MUL11[256];
__constant__ uint8_t d_MUL13[256];
__constant__ uint8_t d_MUL14[256];

// Global pinned memory variables
uint8_t* g_pinned_memory = nullptr;
size_t g_pinned_memory_size = 0;

__device__ void addRoundKey(uint8_t *state, const uint8_t *roundKey) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

__device__ void subBytes(uint8_t *state, const uint8_t *sbox) {
    for (int i = 0; i <16; i++) {
        state[i] = sbox[state[i]];
    }
}

__device__ void invSubBytes(uint8_t *state, const uint8_t *invSbox) {
    for (int i = 0; i < 16; i++) {
        state[i] = invSbox[state[i]];
    }
}

__device__ void shiftRows(uint8_t *state) {
    uint8_t temp;

    //Shift second row
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;   

    //Shift third row
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    //Shift fourth row
    temp  = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;

}

__device__ void invShiftRows(uint8_t *state) {
    uint8_t temp;
    
    // Row 1: shift right by 1
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    
    // Row 2: shift right by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift right by 3
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}
__device__ void mixColumns(uint8_t *state) {
    for (int i = 0; i < 4; i++) {
        uint8_t s0 = state[i * 4 + 0];
        uint8_t s1 = state[i * 4 + 1];
        uint8_t s2 = state[i * 4 + 2];
        uint8_t s3 = state[i * 4 + 3];
        
        // Use lookup tables from constant memory
        state[i * 4 + 0] = d_MUL2[s0] ^ d_MUL3[s1] ^ s2 ^ s3;
        state[i * 4 + 1] = s0 ^ d_MUL2[s1] ^ d_MUL3[s2] ^ s3;
        state[i * 4 + 2] = s0 ^ s1 ^ d_MUL2[s2] ^ d_MUL3[s3];
        state[i * 4 + 3] = d_MUL3[s0] ^ s1 ^ s2 ^ d_MUL2[s3];
    }
}

__device__ void invMixColumns(uint8_t *state) {
    for (int i = 0; i < 4; i++) {
        uint8_t s0 = state[i * 4 + 0];
        uint8_t s1 = state[i * 4 + 1];
        uint8_t s2 = state[i * 4 + 2];
        uint8_t s3 = state[i * 4 + 3];
        
        state[i * 4 + 0] = d_MUL14[s0] ^ d_MUL11[s1] ^ d_MUL13[s2] ^ d_MUL9[s3];
        state[i * 4 + 1] = d_MUL9[s0] ^ d_MUL14[s1] ^ d_MUL11[s2] ^ d_MUL13[s3];
        state[i * 4 + 2] = d_MUL13[s0] ^ d_MUL9[s1] ^ d_MUL14[s2] ^ d_MUL11[s3];
        state[i * 4 + 3] = d_MUL11[s0] ^ d_MUL13[s1] ^ d_MUL9[s2] ^ d_MUL14[s3];
    }
}

__global__ void aesEncryptKernel(uint8_t *data, const uint8_t *roundKeys, int numBlocks) {
    __shared__ uint8_t sharedSbox[256];
    __shared__ uint8_t sharedKeys[176];

    // Cooperative loading of SBOX into shared memory
    for (int i = threadIdx.x; i < 256; i += blockDim.x) {
        sharedSbox[i] = d_SBOX[i];
    }

    // Cooperative loading of round keys into shared memory
    for (int i = threadIdx.x; i < 176; i += blockDim.x) {
        sharedKeys[i] = roundKeys[i];
    }

    __syncthreads();

    int idx = blockIdx.x *blockDim.x + threadIdx.x;
    int totalThreads = gridDim.x * blockDim.x;

    for (int block = 0; block < numBlocks; block += totalThreads) {

        uint8_t state[16];

        for (int i = 0; i < 16; i++) {
            state[i] = data[idx * 16 + i];
        }

        // initial round
        addRoundKey(state, sharedKeys);

        // loop through the remaining rounds, except the last one
        for(int round = 1; round < 10; round++) {
            subBytes(state, sharedSbox);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, &sharedKeys[round * 16]);
        }

        // final round
        subBytes(state, sharedSbox);
        shiftRows(state);
        addRoundKey(state, &sharedKeys[10 * 16]);


        // store the result
        for (int i = 0; i < 16; i++) {
            data[idx * 16 + i] = state[i];
        }
    }
}

__global__ void aesDecryptKernel(uint8_t *data, const uint8_t *roundKeys, int numBlocks) {
    __shared__ uint8_t sharedInvSbox[256];
    __shared__ uint8_t sharedKeys[176];

    // Cooperative loading of SBOX into shared memory
    for (int i = threadIdx.x; i < 256; i += blockDim.x) {
        sharedInvSbox[i] = d_INV_SBOX[i];
    }

    // Cooperative loading of round keys into shared memory
    for (int i = threadIdx.x; i < 176; i += blockDim.x) {
        sharedKeys[i] = roundKeys[i];
    }

    __syncthreads();

    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int totalThreads = gridDim.x * blockDim.x;

    for (int block = 0; block < numBlocks; block += totalThreads) {
        if (idx + block >= numBlocks) continue;
        
        uint8_t state[16];
        for (int i = 0; i < 16; i++) {
            state[i] = data[(idx + block) * 16 + i];
        }

        // Initial round
        addRoundKey(state, &sharedKeys[10 * 16]);  // Start with last round key

        // Main rounds
        for(int round = 9; round > 0; round--) {
            invShiftRows(state);
            invSubBytes(state, sharedInvSbox);
            addRoundKey(state, &sharedKeys[round * 16]);
            invMixColumns(state);
        }

        // Final round
        invShiftRows(state);
        invSubBytes(state, sharedInvSbox);
        addRoundKey(state, sharedKeys);  // First round key

        // Store the result
        for (int i = 0; i < 16; i++) {
            data[(idx + block) * 16 + i] = state[i];
        }
    }
}

void initGPU() {
    CUDA_CHECK(cudaMemcpyToSymbol(d_SBOX, SBOX, 256 * sizeof(uint8_t)));
    CUDA_CHECK(cudaMemcpyToSymbol(d_INV_SBOX, INV_SBOX, 256 * sizeof(uint8_t)));
    CUDA_CHECK(cudaMemcpyToSymbol(d_RCON, RCON, 10 * sizeof(uint8_t)));
    CUDA_CHECK(cudaMemcpyToSymbol(d_MUL2, MUL2, 256 * sizeof(uint8_t)));
    CUDA_CHECK(cudaMemcpyToSymbol(d_MUL3, MUL3, 256 * sizeof(uint8_t)));
    CUDA_CHECK(cudaMemcpyToSymbol(d_MUL9, MUL9, 256 * sizeof(uint8_t)));
    CUDA_CHECK(cudaMemcpyToSymbol(d_MUL11, MUL11, 256 * sizeof(uint8_t)));
    CUDA_CHECK(cudaMemcpyToSymbol(d_MUL13, MUL13, 256 * sizeof(uint8_t)));
    CUDA_CHECK(cudaMemcpyToSymbol(d_MUL14, MUL14, 256 * sizeof(uint8_t)));
}

void freeGPU() {
    CUDA_CHECK(cudaDeviceReset());
}

void expandKey(const uint8_t *key, uint8_t *expandedKey) {
    // first round key is the original key
    for (int i = 0; i < 16; i++) {
        expandedKey[i] = key[i];
    }

    // generate the remaining round keys
    uint8_t temp[4];
    int rconIndex = 0;

    for (int i = 16; i < 176; i += 4) {
        // copy the last 4 bytes of the previous key into temp
        for (int j = 0; j < 4; j++) {
            temp[j] = expandedKey[i - 4 + j];
        }

        if (i % 16 == 0) {
            uint8_t k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;

            for (int j = 0; j < 4; j++) {
                temp[j] = SBOX[temp[j]];
            }

            // XOR the result with the rcon value
            temp[0] ^= RCON[rconIndex];
            rconIndex++;
        }

        // XOR with bytes 16 positions earlier to get next 4 bytes
        for (int j = 0; j < 4; j++) {
            expandedKey[i + j] = expandedKey[i - 16 + j] ^ temp[j];
        }
    }
}

void aesEncrypt(uint8_t *data, const uint8_t *key, size_t dataSize) {
    if (dataSize % 16 != 0) {
        throw std::invalid_argument("Data size must be a multiple of 16 bytes");
    }
    
    try {
        // Add CUDA events for timing
        cudaEvent_t start, stop;
        CUDA_CHECK(cudaEventCreate(&start));
        CUDA_CHECK(cudaEventCreate(&stop));
        float kernelTime = 0.0f;

        uint8_t expandedKey[176];
        expandKey(key, expandedKey);

        // Get device properties
        cudaDeviceProp props;
        int deviceId;
        CUDA_CHECK(cudaGetDevice(&deviceId));
        CUDA_CHECK(cudaGetDeviceProperties(&props, deviceId));

        // Optimize thread configuration
        const int threadsPerBlock = 256;  // Optimal for most cases
        const int maxBlocksPerSM = props.maxBlocksPerMultiProcessor;
        const int numSMs = props.multiProcessorCount;
        const int maxBlocks = numSMs * maxBlocksPerSM;

        // Increase chunk size for better throughput
        const size_t chunkSize = 8 * 1024 * 1024; // 8MB chunks
        const int numStreams = 4;

        // Allocate pinned memory
        uint8_t *h_data;
        if (g_pinned_memory == nullptr || g_pinned_memory_size < dataSize) {
            if (g_pinned_memory != nullptr) {
                CUDA_CHECK(cudaFreeHost(g_pinned_memory));
            }
            CUDA_CHECK(cudaMallocHost(&g_pinned_memory, dataSize));
            g_pinned_memory_size = dataSize;
        }
        h_data = g_pinned_memory;
        memcpy(h_data, data, dataSize);

        // Allocate device memory
        uint8_t *d_data[numStreams], *d_expandedKey;
        CUDA_CHECK(cudaMalloc((void **)&d_expandedKey, 176 * sizeof(uint8_t)));
        
        cudaStream_t streams[numStreams];
        for (int i = 0; i < numStreams; ++i) {
            CUDA_CHECK(cudaStreamCreate(&streams[i]));
            CUDA_CHECK(cudaMalloc((void **)&d_data[i], chunkSize));
        }

        // Copy expanded key once
        CUDA_CHECK(cudaMemcpy(d_expandedKey, expandedKey, 176 * sizeof(uint8_t), cudaMemcpyHostToDevice));

        // Start timing
        CUDA_CHECK(cudaEventRecord(start));

        // Process data with improved pipeline
        for (size_t offset = 0; offset < dataSize; offset += chunkSize * numStreams) {
            for (int i = 0; i < numStreams; ++i) {
                size_t currentOffset = offset + i * chunkSize;
                if (currentOffset >= dataSize) break;

                size_t currentChunkSize = std::min(chunkSize, dataSize - currentOffset);
                if (currentChunkSize == 0) break;

                // Stage 1: Copy to device
                CUDA_CHECK(cudaMemcpyAsync(d_data[i], h_data + currentOffset, 
                                         currentChunkSize, cudaMemcpyHostToDevice, 
                                         streams[i]));

                // Stage 2: Process
                int numBlocks = std::min((currentChunkSize / 16 + threadsPerBlock - 1) / threadsPerBlock, 
                                       static_cast<size_t>(maxBlocks));
                
                aesEncryptKernel<<<numBlocks, threadsPerBlock, 0, streams[i]>>>
                    (d_data[i], d_expandedKey, currentChunkSize / 16);
                
                CUDA_CHECK(cudaGetLastError());

                // Stage 3: Copy back to host
                CUDA_CHECK(cudaMemcpyAsync(h_data + currentOffset, d_data[i], 
                                         currentChunkSize, cudaMemcpyDeviceToHost, 
                                         streams[i]));
            }
        }

        // Stop timing
        CUDA_CHECK(cudaEventRecord(stop));
        CUDA_CHECK(cudaEventSynchronize(stop));
        CUDA_CHECK(cudaEventElapsedTime(&kernelTime, start, stop));

        std::cout << "Kernel Time to complete the Encryption is: " << kernelTime << " ms" << std::endl;

        // Synchronize all streams
        for (int i = 0; i < numStreams; ++i) {
            CUDA_CHECK(cudaStreamSynchronize(streams[i]));
        }

        // Copy result back
        memcpy(data, h_data, dataSize);

        // Cleanup
        for (int i = 0; i < numStreams; ++i) {
            CUDA_CHECK(cudaFree(d_data[i]));
            CUDA_CHECK(cudaStreamDestroy(streams[i]));
        }
        CUDA_CHECK(cudaFree(d_expandedKey));

        // Cleanup events
        CUDA_CHECK(cudaEventDestroy(start));
        CUDA_CHECK(cudaEventDestroy(stop));

    } catch (const std::exception& e) {
        cudaDeviceReset();
        throw std::runtime_error("Encryption failed: " + std::string(e.what()));
    }
}

void aesDecrypt(uint8_t *data, const uint8_t *key, size_t dataSize) {
    if (dataSize % 16 != 0) {
        throw std::invalid_argument("Data size must be a multiple of 16 bytes");
    }
    if (data == nullptr || key == nullptr) {
        throw std::invalid_argument("Data and key cannot be null");
    }   

    try {
        // Add CUDA events for timing
        cudaEvent_t start, stop;
        CUDA_CHECK(cudaEventCreate(&start));
        CUDA_CHECK(cudaEventCreate(&stop));
        float kernelTime = 0.0f;

        uint8_t expandedKey[176];
        expandKey(key, expandedKey);

        // Get device properties
        cudaDeviceProp props;
        int deviceId;
        CUDA_CHECK(cudaGetDevice(&deviceId));
        CUDA_CHECK(cudaGetDeviceProperties(&props, deviceId));

        // Optimize thread configuration
        const int threadsPerBlock = 256;  // Optimal for most cases
        const int maxBlocksPerSM = props.maxBlocksPerMultiProcessor;
        const int numSMs = props.multiProcessorCount;
        const int maxBlocks = numSMs * maxBlocksPerSM;

        // Increase chunk size for better throughput
        const size_t chunkSize = 8 * 1024 * 1024; // 8MB chunks
        const int numStreams = 4;

        // Use pinned memory
        uint8_t *h_data;
        if (g_pinned_memory == nullptr || g_pinned_memory_size < dataSize) {
            if (g_pinned_memory != nullptr) {
                CUDA_CHECK(cudaFreeHost(g_pinned_memory));
            }
            CUDA_CHECK(cudaMallocHost(&g_pinned_memory, dataSize));
            g_pinned_memory_size = dataSize;
        }
        h_data = g_pinned_memory;
        memcpy(h_data, data, dataSize);

        // Allocate device memory
        uint8_t *d_data[numStreams], *d_expandedKey;
        CUDA_CHECK(cudaMalloc((void **)&d_expandedKey, 176 * sizeof(uint8_t)));
        
        cudaStream_t streams[numStreams];
        for (int i = 0; i < numStreams; ++i) {
            CUDA_CHECK(cudaStreamCreate(&streams[i]));
            CUDA_CHECK(cudaMalloc((void **)&d_data[i], chunkSize));
        }

        // Copy expanded key once
        CUDA_CHECK(cudaMemcpy(d_expandedKey, expandedKey, 176 * sizeof(uint8_t), cudaMemcpyHostToDevice));

        // Start timing
        CUDA_CHECK(cudaEventRecord(start));

        // Process data with improved pipeline
        for (size_t offset = 0; offset < dataSize; offset += chunkSize * numStreams) {
            for (int i = 0; i < numStreams; ++i) {
                size_t currentOffset = offset + i * chunkSize;
                if (currentOffset >= dataSize) break;

                size_t currentChunkSize = std::min(chunkSize, dataSize - currentOffset);
                if (currentChunkSize == 0) break;

                // Stage 1: Copy to device
                CUDA_CHECK(cudaMemcpyAsync(d_data[i], h_data + currentOffset, 
                                         currentChunkSize, cudaMemcpyHostToDevice, 
                                         streams[i]));

                // Stage 2: Process
                int numBlocks = std::min((currentChunkSize / 16 + threadsPerBlock - 1) / threadsPerBlock, 
                                       static_cast<size_t>(maxBlocks));
                
                aesDecryptKernel<<<numBlocks, threadsPerBlock, 0, streams[i]>>>
                    (d_data[i], d_expandedKey, currentChunkSize / 16);
                
                CUDA_CHECK(cudaGetLastError());

                // Stage 3: Copy back to host
                CUDA_CHECK(cudaMemcpyAsync(h_data + currentOffset, d_data[i], 
                                         currentChunkSize, cudaMemcpyDeviceToHost, 
                                         streams[i]));
            }
        }

        // Stop timing
        CUDA_CHECK(cudaEventRecord(stop));
        CUDA_CHECK(cudaEventSynchronize(stop));
        CUDA_CHECK(cudaEventElapsedTime(&kernelTime, start, stop));

        std::cout << "Kernel Time to complete the Decryption is: " << kernelTime << " ms" << std::endl;

        // Synchronize all streams
        for (int i = 0; i < numStreams; ++i) {
            CUDA_CHECK(cudaStreamSynchronize(streams[i]));
        }

        // Copy result back
        memcpy(data, h_data, dataSize);

        // Cleanup
        for (int i = 0; i < numStreams; ++i) {
            CUDA_CHECK(cudaFree(d_data[i]));
            CUDA_CHECK(cudaStreamDestroy(streams[i]));
        }
        CUDA_CHECK(cudaFree(d_expandedKey));

        // Cleanup events
        CUDA_CHECK(cudaEventDestroy(start));
        CUDA_CHECK(cudaEventDestroy(stop));

    } catch (const std::exception& e) {
        cudaDeviceReset();
        throw std::runtime_error("Decryption failed: " + std::string(e.what()));
    }
}

