cmake_minimum_required (VERSION 2.8)
project (teec_RMT_M)
cmake_policy (SET CMP0037 OLD)

# Add source files
set(SRCS
        ../crypto_protocol_ca.cpp
        ../crypto_protocol_ca.h
        ../../../../src/CA/cloud/libteec_adaptor.cpp
        )
# 添加utils底下的文件
file(GLOB UTILS_SRCS ../utils/*.cpp)
file(GLOB UTILS_HDRS ../utils/*.h)

# Combine all files
list(APPEND SRCS ${UTILS_SRCS} ${UTILS_HDRS})

# Add header file include directories
include_directories(
        ../../../../include/CA
)
# Find OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Set options
set(CMAKE_CP_FLAGS "-fstack-protector-strong -fPIC -Wno-write-strings")
set(CMAKE_CP_FLAGS "${CMAKE_CP_FLAGS} -z text -z now -z relro -z noexecstack -pie")

# Set output dir
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR})

# Generate execute file
add_executable(teec_RMT_M ${SRCS})
target_link_libraries(teec_RMT_M dl pthread OpenSSL::SSL OpenSSL::Crypto)
set_target_properties(teec_RMT_M PROPERTIES COMPILE_FLAGS ${CMAKE_CP_FLAGS})

# Clean output
add_custom_target(clean
        COMMAND rm -rf ${PROJECT_SOURCE_DIR}/teec_RMT_M
        COMMAND @echo "clean up"
        )
