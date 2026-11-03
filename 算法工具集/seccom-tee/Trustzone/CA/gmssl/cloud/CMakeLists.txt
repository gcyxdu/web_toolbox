cmake_minimum_required (VERSION 2.8)
project (teec_gmssl)
cmake_policy (SET CMP0037 OLD)

# Add source files
set(SRCS
        ../gmssl_ca.cpp
        ../gmssl_ca.h
        ../../../../src/CA/cloud/libteec_adaptor.cpp
        )
# Combine all files
list(APPEND SRCS)

# Add header file include directories
include_directories(
        ../../../../include/CA
)

# Set options
set(CMAKE_CP_FLAGS "-fstack-protector-strong -fPIC -Wno-write-strings")
set(CMAKE_CP_FLAGS "${CMAKE_CP_FLAGS} -z text -z now -z relro -z noexecstack -pie")

# Set output dir
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR})

# Generate execute file
add_executable(teec_gmssl ${SRCS})
target_link_libraries(teec_gmssl dl pthread)
set_target_properties(teec_gmssl PROPERTIES COMPILE_FLAGS ${CMAKE_CP_FLAGS})

# Clean output
add_custom_target(clean
        COMMAND rm -rf ${PROJECT_SOURCE_DIR}/teec_gmssl
        COMMAND @echo "clean up"
        )
