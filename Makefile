# Compiler settings
NVCC = nvcc
CXX = g++
NVCCFLAGS = -O3 -arch=sm_70 --compiler-options -Wall -allow-unsupported-compiler
CXXFLAGS = -O3 -Wall -std=c++11 

# Source files
CUDA_SOURCES = aes.cu
CPP_SOURCES = main.cpp
HEADERS = aes.h aes.cuh aes_constants.h

# Object files
OBJECTS = aes.o main.o

# Binary name
TARGET = aes_cuda

# Default target
all: $(TARGET)

# Compile CUDA source files
aes.o: $(CUDA_SOURCES) $(HEADERS)
	$(NVCC) $(NVCCFLAGS) -c $< -o $@

# Compile C++ source files
main.o: $(CPP_SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Link object files
$(TARGET): $(OBJECTS)
	$(NVCC) $(NVCCFLAGS) $(OBJECTS) -o $@

# Clean build files
clean:
	rm -f $(OBJECTS) $(TARGET)

# Generate a test key file
genkey:
	dd if=/dev/urandom of=key.bin bs=16 count=1 2>/dev/null

.PHONY: all clean genkey