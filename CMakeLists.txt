cmake_minimum_required(VERSION 3.10)
project(qpost)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)

pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(OQS REQUIRED liboqs)

include_directories(src include ${SODIUM_INCLUDE_DIRS} ${OQS_INCLUDE_DIRS})
link_directories(${SODIUM_LIBRARY_DIRS} ${OQS_LIBRARY_DIRS})

set(SHARED_SOURCES
    src/handshake.cpp
)

add_executable(qpost src/main.cpp ${SHARED_SOURCES})
target_link_libraries(qpost 
    ${SODIUM_LIBRARIES} 
    ${OQS_LIBRARIES} 
    OpenSSL::Crypto
)