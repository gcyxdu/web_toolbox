cmake_minimum_required(VERSION 3.10)
project(SEALDemo VERSION 1.0)


add_executable(examples main.cpp)
add_executable(nonexamples main.cpp)

target_sources(examples
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/main.cpp
)

target_sources(nonexamples
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/main.cpp
)

include_directories(/usr/local/include/SEAL-4.1)

set_target_properties(examples PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS ON
    COMPILE_FLAGS "-pthread"
    LINK_FLAGS "-pthread"
)

set_target_properties(nonexamples PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS ON
    COMPILE_FLAGS "-pthread"
    LINK_FLAGS "-pthread"
)


link_directories("/usr/local/lib")

target_link_libraries(examples seal-4.1)
target_link_libraries(nonexamples seal-4.1)

target_compile_definitions(nonexamples PRIVATE NON_INTERACTIVE_MODE)