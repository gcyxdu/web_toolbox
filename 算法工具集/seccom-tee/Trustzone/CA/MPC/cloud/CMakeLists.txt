cmake_minimum_required (VERSION 2.8)
project (teec_mpc)
cmake_policy (SET CMP0037 OLD)

# Add source files
set(SRCS
        ../MPC_ca.cpp
        ../MPC_ca.h
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


# Set options
set(CMAKE_TEEC_RELU_FLAGS "-fstack-protector-strong -fPIC")
set(CMAKE_TEEC_RELU_FLAGS "${CMAKE_TEEC_RELU_FLAGS} -z text -z now -z relro -z noexecstack -pie")

# Set output dir
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR})

# Generate execute file
add_executable(teec_mpc ${SRCS})
target_link_libraries(teec_mpc dl pthread)
set_target_properties(teec_mpc PROPERTIES COMPILE_FLAGS ${CMAKE_TEEC_RELU_FLAGS})

# Clean output
add_custom_target(clean
        COMMAND rm -rf ${PROJECT_SOURCE_DIR}/teec_mpc
        COMMAND @echo "clean up"
        )
