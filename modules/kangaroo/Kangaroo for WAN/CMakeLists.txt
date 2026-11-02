cmake_minimum_required(VERSION 3.10)
project(SEALDemo VERSION 1.0)


add_executable(server server.cpp)
add_executable(client client.cpp)

target_sources(server
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/server.cpp
)

target_sources(client
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/client.cpp
)

include_directories(/usr/local/include/SEAL-4.1)

set_target_properties(server PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS ON
    COMPILE_FLAGS "-pthread"
    LINK_FLAGS "-pthread"
)

set_target_properties(client PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS ON
    COMPILE_FLAGS "-pthread"
    LINK_FLAGS "-pthread"
)


link_directories("/usr/local/lib")

target_link_libraries(server seal-4.1)
target_link_libraries(client seal-4.1)

target_compile_definitions(client PRIVATE NON_INTERACTIVE_MODE)