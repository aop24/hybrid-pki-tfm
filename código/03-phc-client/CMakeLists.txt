cmake_minimum_required(VERSION 3.16)
project(phc-client C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -O2)

# Single build against OpenSSL 3.4.0 (/opt/openssl32): it is the only version
# that can use composite keys in TLS, and with oqs-provider it also decodes the
# ML-DSA keys of the Chimera extensions. The RPATH makes the binaries use it
# without LD_LIBRARY_PATH (systemd, containers, other users).
set(OPENSSL_ROOT_DIR /opt/openssl32 CACHE PATH "OpenSSL 3.4.0 prefix")
set(OPENSSL_USE_STATIC_LIBS OFF)
find_package(OpenSSL 3.2 REQUIRED)
set(CMAKE_BUILD_RPATH ${OPENSSL_ROOT_DIR}/lib64)
set(CMAKE_INSTALL_RPATH ${OPENSSL_ROOT_DIR}/lib64)

add_library(phccore STATIC src/chimera.c src/composite.c src/phc_common.c src/revocation.c)
target_include_directories(phccore PUBLIC include)
target_link_libraries(phccore PUBLIC OpenSSL::SSL OpenSSL::Crypto)

add_executable(phc-verify src/phc_verify.c)
target_link_libraries(phc-verify PRIVATE phccore)

add_executable(phc-msg src/phc_msg.c)
target_link_libraries(phc-msg PRIVATE phccore)

add_executable(phc-file src/phc_file.c)
target_link_libraries(phc-file PRIVATE phccore)

add_executable(phc-challenge src/phc_challenge.c)
target_link_libraries(phc-challenge PRIVATE phccore)

add_executable(phc-bench src/phc_bench.c)
target_link_libraries(phc-bench PRIVATE phccore)
