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

add_executable(client src/client.cpp ${SHARED_SOURCES})
target_link_libraries(client 
    ${SODIUM_LIBRARIES} 
    ${OQS_LIBRARIES} 
    OpenSSL::Crypto
)

add_executable(server src/server.cpp ${SHARED_SOURCES})
target_link_libraries(server 
    ${SODIUM_LIBRARIES} 
    ${OQS_LIBRARIES} 
    OpenSSL::Crypto
)