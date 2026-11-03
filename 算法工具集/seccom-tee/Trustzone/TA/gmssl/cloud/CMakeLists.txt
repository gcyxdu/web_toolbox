cmake_minimum_required (VERSION 2.8)
project (teec_gmssl)
set(CMAKE_C_COMPILER gcc)
cmake_policy (SET CMP0037 OLD)

# Set variable
set(iTrustee_SDK_PATH ${PROJECT_SOURCE_DIR}/../../../../)
set(SIGNTOOL_DIR ${iTrustee_SDK_PATH}/build/signtools)
set(LIBC ${iTrustee_SDK_PATH}/thirdparty/open_source/musl)
set(LIBSECURE ${iTrustee_SDK_PATH}/thirdparty/open_source/libboundscheck)
include(${iTrustee_SDK_PATH}/Trustzone/TA/common/ta_build_config.cmake)
seccom_prepare_ta_build()

# 查找cpp文件
file(GLOB SRCS "../*.c" "../*.h" "../src/*.c" "../include/*.h")


# 添加单个的 .c 文件
set(SRCS ${SRCS})

# Add header file include directories
include_directories(
        ${LIBC}/libc
        ${LIBC}/libc/arch/aarch64
        ${LIBC}/libc/arch/aarch64/bits
        ${LIBC}/libc/arch/generic
        ${LIBSECURE}/include
        #[[这里引用了TA，同时引用了更多的库]]
        ${iTrustee_SDK_PATH}/include/TA
        ${iTrustee_SDK_PATH}/include/TA/huawei_ext
        ${PROJECT_SOURCE_DIR}/../include  # 添加这一行，将存放gmssl头文件的include目录添加进来
        ${TA_GCC_INCLUDE_DIR}
)

# Set options
set(CMAKE_TA_FLAGS "-DAPI_LEVEL=3 -O  -Wno-unused-const-variable -nostdinc -nodefaultlibs -W -Wall -fno-short-enums -fno-omit-frame-pointer -fstack-protector-strong")
set(CMAKE_TA_FLAGS "${CMAKE_TA_FLAGS} -Wextra -march=armv8-a -Os -Wno-main -fPIC")
set(CMAKE_TA_FLAGS "${CMAKE_TA_FLAGS} -Wno-error=unused-parameter -Wno-error=unused-but-set-variable  -Wno-error=unused-variable -Wno-error=write-strings")
set(CMAKE_TA_LD_FLAGS "-s -z text -z now -z relro -z noexecstack -shared")
set(CMAKE_TA_LD_FLAGS "${CMAKE_TA_LD_FLAGS} -T${iTrustee_SDK_PATH}/build/tools/ta_link_64.ld")

# Set output dir
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR})

# Generate .so file
add_library(tmp_object OBJECT ${SRCS})
set_target_properties(tmp_object PROPERTIES COMPILE_FLAGS ${CMAKE_TA_FLAGS})
add_library(combine SHARED $<TARGET_OBJECTS:tmp_object>)
set_target_properties(combine PROPERTIES LINK_FLAGS ${CMAKE_TA_LD_FLAGS})

# 链接musl和OpenSSL库
target_link_libraries(combine PUBLIC -nodefaultlibs
        ${TA_LIBGCC_PATH})


message(${PROJECT_SOURCE_DIR})

# Custom commands for post-build operations
add_custom_command(TARGET combine
        POST_BUILD
        COMMAND cp -f ${PROJECT_SOURCE_DIR}/../manifest.txt ${PROJECT_SOURCE_DIR}
        # 关于这里的config函数
        COMMAND python3 -B ${SIGNTOOL_DIR}/signtool_v3.py ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR} --config ${TA_CONFIG_FILE}
        )

# Clean output
add_custom_target(clean_custom
        COMMAND rm -rf ${PROJECT_SOURCE_DIR}/libcombine.so ${PROJECT_SOURCE_DIR}/*.sec
        COMMAND @echo "clean up"
        )
