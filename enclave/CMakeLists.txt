# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Generate header with public key of enclave B (2)
if (WIN32)
  set(WIN_BASH ${OE_BASH})
endif ()

add_custom_command(
  OUTPUT attestation_t.h attestation_t.c attestation_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/attestation.edl
  COMMAND
    openenclave::oeedger8r --trusted
    ${CMAKE_SOURCE_DIR}/attestation.edl --search-path ${OE_INCLUDEDIR}
    --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(enclave ecall.cpp)

if (WIN32)
  maybe_build_using_clangw(enclave)
endif ()

target_include_directories(enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(enclave common)

# Generate key A
add_custom_command(
  OUTPUT private_a.pem public_a.pem
  COMMAND openssl genrsa -out private_a.pem -3 3072
  COMMAND openssl rsa -in private_a.pem -pubout -out public_a.pem)

add_custom_target(public_key_a DEPENDS public_a.pem)

# Sign enclave A with key A
add_custom_command(
  OUTPUT enclave.signed
  DEPENDS enclave enc.conf private_a.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave> -c
          ${CMAKE_CURRENT_SOURCE_DIR}/enc.conf -k private_a.pem)

add_custom_target(enclave_signed ALL DEPENDS enclave.signed)
