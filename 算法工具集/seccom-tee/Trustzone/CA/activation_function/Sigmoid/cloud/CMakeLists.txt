cmake_minimum_required (VERSION 2.8)
project (teec_sigmoid)
cmake_policy (SET CMP0037 OLD)

# Add source files
set(SRCS
        ../Sigmoid_ca.cpp
        ../she.cpp
        ../she.h
        ../sheFloat.cpp
        ../../../../../src/CA/cloud/libteec_adaptor.cpp
        )
message(STATUS "Source files: ${SRCS}")

# Add header file include directories
include_directories(
        ../../../../../include/CA
)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add OpenSSL include directories
include_directories(${OPENSSL_INCLUDE_DIR})

# Set options
set(CMAKE_TEEC_RELU_FLAGS "-fstack-protector-strong -fPIC")
set(CMAKE_TEEC_RELU_FLAGS "${CMAKE_TEEC_RELU_FLAGS} -z text -z now -z relro -z noexecstack -pie")

# Set output dir
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR})

# Generate execute file
add_executable(teec_sigmoid ${SRCS})
target_link_libraries(teec_sigmoid dl pthread OpenSSL::SSL OpenSSL::Crypto)
set_target_properties(teec_sigmoid PROPERTIES COMPILE_FLAGS ${CMAKE_TEEC_RELU_FLAGS})

# Clean output
add_custom_target(clean
        COMMAND rm -rf ${PROJECT_SOURCE_DIR}/teec_sigmoid
        COMMAND @echo "clean up"
        )
