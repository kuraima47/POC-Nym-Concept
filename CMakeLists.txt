cmake_minimum_required(VERSION 3.25)
project(untitled C)

set(CMAKE_C_STANDARD 11)

add_executable(untitled main.c class.h node.h utils.h)

find_package(OpenSSL REQUIRED)

if (OPENSSL_FOUND)
    message(STATUS "Found OpenSSL ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL include directory: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
else ()
    message(FATAL_ERROR "OpenSSL not found")
endif ()

# Add OpenSSL include directories and libraries to your target
target_include_directories(untitled PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(untitled ${OPENSSL_LIBRARIES})

target_link_libraries(untitled ws2_32)