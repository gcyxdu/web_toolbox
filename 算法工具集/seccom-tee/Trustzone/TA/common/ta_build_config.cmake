function(seccom_prepare_ta_build)
    execute_process(
        COMMAND ${CMAKE_C_COMPILER} -print-libgcc-file-name
        OUTPUT_VARIABLE TA_LIBGCC_PATH
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT EXISTS "${TA_LIBGCC_PATH}")
        message(FATAL_ERROR "failed to resolve libgcc path with ${CMAKE_C_COMPILER}")
    endif()

    execute_process(
        COMMAND ${CMAKE_C_COMPILER} -print-file-name=include
        OUTPUT_VARIABLE TA_GCC_INCLUDE_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if("${TA_GCC_INCLUDE_DIR}" STREQUAL "include")
        set(TA_GCC_INCLUDE_DIR "")
    endif()

    set(TA_SIGN_KEY "${PROJECT_SOURCE_DIR}/TA_cert/private_key.pem")
    set(TA_CONFIG_PATH "${PROJECT_SOURCE_DIR}/signed_config/config")
    set(TA_CONFIG_FILE "${CMAKE_CURRENT_BINARY_DIR}/config_cloud.ini")

    configure_file(
        ${PROJECT_SOURCE_DIR}/config_cloud.ini
        ${TA_CONFIG_FILE}
        @ONLY)

    set(TA_LIBGCC_PATH "${TA_LIBGCC_PATH}" PARENT_SCOPE)
    set(TA_GCC_INCLUDE_DIR "${TA_GCC_INCLUDE_DIR}" PARENT_SCOPE)
    set(TA_CONFIG_FILE "${TA_CONFIG_FILE}" PARENT_SCOPE)
endfunction()

function(seccom_resolve_ta_libcrypto output_var)
    get_filename_component(
        TA_LIBCRYPTO
        "${iTrustee_SDK_PATH}/Trustzone/TA/activate_function/lib/libcrypto.a"
        ABSOLUTE)
    if(NOT EXISTS "${TA_LIBCRYPTO}")
        message(FATAL_ERROR "failed to resolve libcrypto.a at ${TA_LIBCRYPTO}")
    endif()
    set(${output_var} "${TA_LIBCRYPTO}" PARENT_SCOPE)
endfunction()
