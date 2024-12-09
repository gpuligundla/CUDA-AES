#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/fs.h>
#include <sys/syscall.h>
#include <cstdint>
#include <cerrno>
#include "aes.h"

void printUsage(const char* programName){
    std::cerr << "Usage: " << programName << " -e|-d <input_file> <output_file>\n"
              << "  -e: encrypt mode\n"
              << "  -d: decrypt mode\n"
              << "Example:\n"
              << "  Encrypt: " << programName << " -e plaintext.txt encrypted.bin\n"
              << "  Decrypt: " << programName << " -d encrypted.bin decrypted.txt\n";
}

std::vector<uint8_t> readKeyFromFile(const std::string& filename) {
    std::vector<uint8_t> key(16);
    std::ifstream file(filename, std::ios::binary);

    if(!file) {
        throw std::runtime_error("Unable to open key file");
    }

    file.read(reinterpret_cast<char*>(key.data()), 16);
    return key;
}

std::vector<uint8_t> readInputFromFile(const std::string& filename) {
    int fd = open(filename.c_str(), O_RDONLY);
    if (fd == -1) {
        throw std::runtime_error("Cannot open input file: " + filename + " (" + strerror(errno) + ")");
    }

    // Get file size
    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        close(fd);
        throw std::runtime_error("Cannot get file size: " + filename);
    }
    size_t fileSize = sb.st_size;

    // Create a pipe for splice
    int pipefd[2];
    if (pipe2(pipefd, O_NONBLOCK) == -1) {
        close(fd);
        throw std::runtime_error("Cannot create pipe: " + std::string(strerror(errno)));
    }

    // Set pipe size to optimal value
    long pipe_size = fcntl(pipefd[1], F_GETPIPE_SZ);
    fcntl(pipefd[1], F_SETPIPE_SZ, pipe_size * 2);

    std::vector<uint8_t> data(fileSize);
    size_t totalRead = 0;
    
    while (totalRead < fileSize) {
        // Splice from file to pipe
        ssize_t spliced = splice(fd, nullptr, pipefd[1], nullptr, 
                               std::min(size_t(pipe_size), fileSize - totalRead), 
                               SPLICE_F_MOVE | SPLICE_F_MORE);
        
        if (spliced == -1) {
            close(pipefd[0]);
            close(pipefd[1]);
            close(fd);
            throw std::runtime_error("Splice failed: " + std::string(strerror(errno)));
        }

        // Read from pipe
        ssize_t bytesRead = read(pipefd[0], data.data() + totalRead, spliced);
        if (bytesRead == -1) {
            close(pipefd[0]);
            close(pipefd[1]);
            close(fd);
            throw std::runtime_error("Read failed: " + std::string(strerror(errno)));
        }

        totalRead += bytesRead;
    }

    close(pipefd[0]);
    close(pipefd[1]);
    close(fd);
    return data;
}

void writeOutputToFile(const std::string& filename, const uint8_t* data, size_t size) {
    // Open with Linux-specific flags
    int fd = open(filename.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        throw std::runtime_error("Cannot open output file: " + filename + " (" + strerror(errno) + ")");
    }

    // Pre-allocate using ftruncate instead of fallocate
    if (ftruncate(fd, size) == -1) {
        close(fd);
        throw std::runtime_error("Cannot allocate file: " + std::string(strerror(errno)));
    }

    // Use Linux's sendfile for zero-copy writing
    int pipefd[2];
    if (pipe2(pipefd, O_NONBLOCK) == -1) {
        close(fd);
        throw std::runtime_error("Cannot create pipe: " + std::string(strerror(errno)));
    }

    // Optimize pipe size
    long pipe_size = fcntl(pipefd[1], F_GETPIPE_SZ);
    fcntl(pipefd[1], F_SETPIPE_SZ, pipe_size * 2);

    size_t written = 0;
    while (written < size) {
        size_t remaining = size - written;
        size_t chunk_size = std::min(size_t(pipe_size), remaining);

        // Write to pipe
        ssize_t bytes_written = write(pipefd[1], data + written, chunk_size);
        if (bytes_written == -1) {
            close(pipefd[0]);
            close(pipefd[1]);
            close(fd);
            throw std::runtime_error("Write to pipe failed: " + std::string(strerror(errno)));
        }

        // Splice from pipe to file
        ssize_t spliced = splice(pipefd[0], nullptr, fd, nullptr, bytes_written, 
                               SPLICE_F_MOVE | SPLICE_F_MORE);
        if (spliced == -1) {
            close(pipefd[0]);
            close(pipefd[1]);
            close(fd);
            throw std::runtime_error("Splice failed: " + std::string(strerror(errno)));
        }

        written += spliced;
    }

    // Sync file
    fdatasync(fd);

    close(pipefd[0]);
    close(pipefd[1]);
    close(fd);
}

std::vector<uint8_t> addPadding(const std::vector<uint8_t>& data) {
    // Calculate padding size (1 to 16 bytes)
    size_t paddingSize = 16 - (data.size() % 16);
    if (paddingSize == 0) {
        paddingSize = 16;  // If data is already aligned, add full block
    }
    
    // Create new vector with padding
    std::vector<uint8_t> padded = data;
    padded.resize(data.size() + paddingSize, paddingSize);
    
    std::cout << "Added " << (int)paddingSize << " bytes of padding" << std::endl;
    return padded;
}

std::vector<uint8_t> removePadding(std::vector<uint8_t>& padded) {
    if (padded.empty()) {
        throw std::runtime_error("Empty data buffer");
    }

    uint8_t paddingSize = padded.back();
    
    // PKCS7 padding size must be between 1 and 16
    if (paddingSize == 0 || paddingSize > 16) {
        throw std::runtime_error("Invalid padding size: " + std::to_string(paddingSize));
    }

    // Check if we have enough bytes
    if (padded.size() < paddingSize) {
        throw std::runtime_error("Data size smaller than padding size");
    }

    // Verify all padding bytes
    for (size_t i = 0; i < paddingSize; i++) {
        if (padded[padded.size() - 1 - i] != paddingSize) {
            throw std::runtime_error("Invalid padding bytes");
        }
    }

    // Remove padding
    return std::vector<uint8_t>(padded.begin(), padded.end() - paddingSize);
}

int main(int argc, char* argv[]) {
    try {
        if(argc != 4) {
            printUsage(argv[0]);
            return 1;
        }

        bool encryptMode;
        if(strcmp(argv[1], "-e") == 0) {
            encryptMode = true;
        } else if (strcmp(argv[1], "-d") == 0) {
            encryptMode = false;
        } else {
            printUsage(argv[0]);
            return 1;
        }

        std::string inputFile = argv[2];
        std::string outputFile = argv[3];

        // Initialize CUDA
        initGPU();

        // Read key (keep as is since it's small)
        std::cout << "Reading key from 'key.bin'..." << std::endl;
        std::vector<uint8_t> key = readKeyFromFile("key.bin");

        // Read input file
        std::cout << "Reading input file: " << inputFile << std::endl;
        std::vector<uint8_t> data = readInputFromFile(inputFile);
        std::cout << "Read " << data.size() << " bytes" << std::endl;

        // Process data
        if (encryptMode) {
            data = addPadding(data);
            std::cout << "Padding the input file(PKCS7). Padded size: " << data.size() << " bytes" << std::endl;
            std::cout << "Encrypting the data using CUDA..." << std::endl;
            aesEncrypt(data.data(), key.data(), data.size());
        } else {
            std::cout << "Decrypting the data using CUDA..." << std::endl;
            aesDecrypt(data.data(), key.data(), data.size());
            data = removePadding(data);
        }

        // Write output
        std::cout << "Writing " << (encryptMode ? "encrypted" : "decrypted") 
                  << " data to: " << outputFile << std::endl;
        writeOutputToFile(outputFile, data.data(), data.size());

        freeGPU();
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
