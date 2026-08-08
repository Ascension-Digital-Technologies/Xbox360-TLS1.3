cmake_minimum_required(VERSION 3.10)
project(XboxTLS13 VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 98)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)
include(CTest)

option(XBOXTLS_BUILD_TESTS "Build XboxTLS13 tests" ON)
option(XBOXTLS_BUILD_OPENSSL_VERIFIER "Build host/reference OpenSSL authentication verifier" ON)

add_library(xboxtls13 STATIC
  src/crypto/sha256.cpp
  src/crypto/hkdf.cpp
  src/crypto/aes_gcm.cpp
  src/crypto/x25519.cpp
  src/crypto/rsa_verify.cpp
  src/crypto/p256_verify.cpp
  src/tls/record.cpp
  src/tls/protected_record.cpp
  src/tls/transcript.cpp
  src/tls/key_schedule.cpp
  src/tls/client_hello.cpp
  src/tls/server_hello.cpp
  src/tls/handshake.cpp
  src/tls/authentication.cpp
  src/tls/connection.cpp
  src/x509/x509.cpp
  src/x509/trust_store.cpp
  src/verifier/native/native_verifier.cpp
  src/platform/xbox360/platform_xbox360.cpp
  src/platform/xbox360/xbox_client.cpp
)
add_library(XboxTLS13::xboxtls13 ALIAS xboxtls13)

target_include_directories(xboxtls13
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if(XBOXTLS_BUILD_OPENSSL_VERIFIER)
  find_package(OpenSSL QUIET)
  if(OpenSSL_FOUND)
    add_library(xboxtls13_openssl STATIC src/verifier/openssl/openssl_verifier.cpp)
    add_library(XboxTLS13::openssl_verifier ALIAS xboxtls13_openssl)
    target_include_directories(xboxtls13_openssl
      PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )
    target_link_libraries(xboxtls13_openssl PUBLIC xboxtls13 OpenSSL::Crypto)
  else()
    message(STATUS "OpenSSL not found: reference verifier will not be built")
  endif()
endif()

if(BUILD_TESTING AND XBOXTLS_BUILD_TESTS)
  add_executable(xboxtls13_tests dev/tests/test_core.cpp)
  target_link_libraries(xboxtls13_tests PRIVATE xboxtls13)
  add_test(NAME core COMMAND xboxtls13_tests)

  add_executable(xboxtls13_auth_tests dev/tests/test_auth.cpp)
  target_link_libraries(xboxtls13_auth_tests PRIVATE xboxtls13)
  add_test(NAME auth COMMAND xboxtls13_auth_tests)

  if(TARGET xboxtls13_openssl)
    add_executable(xboxtls13_openssl_tests dev/tests/test_openssl_verifier.cpp)
    target_link_libraries(xboxtls13_openssl_tests PRIVATE xboxtls13_openssl OpenSSL::Crypto)
    add_test(NAME openssl_verifier COMMAND xboxtls13_openssl_tests
      ${CMAKE_CURRENT_SOURCE_DIR}/dev/tests/fixtures/root.der
      ${CMAKE_CURRENT_SOURCE_DIR}/dev/tests/fixtures/leaf.der
      ${CMAKE_CURRENT_SOURCE_DIR}/dev/tests/fixtures/certverify-rsa-pss.sig)

    add_executable(xboxtls13_native_verifier_tests dev/tests/test_native_verifier.cpp)
    target_link_libraries(xboxtls13_native_verifier_tests PRIVATE xboxtls13 OpenSSL::Crypto)
    add_test(NAME native_verifier COMMAND xboxtls13_native_verifier_tests
      ${CMAKE_CURRENT_SOURCE_DIR}/dev/tests/fixtures/root.der
      ${CMAKE_CURRENT_SOURCE_DIR}/dev/tests/fixtures/leaf.der
      ${CMAKE_CURRENT_SOURCE_DIR}/dev/tests/fixtures/native-rsa-pss.sig
      ${CMAKE_CURRENT_SOURCE_DIR}/dev/tests/fixtures/pss-root.der
      ${CMAKE_CURRENT_SOURCE_DIR}/dev/tests/fixtures/pss-leaf.der)
  endif()
endif()

install(TARGETS xboxtls13
  EXPORT XboxTLS13Targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
if(TARGET xboxtls13_openssl)
  install(TARGETS xboxtls13_openssl
    EXPORT XboxTLS13Targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )
endif()
install(DIRECTORY include/xboxtls DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT XboxTLS13Targets
  FILE XboxTLS13Targets.cmake
  NAMESPACE XboxTLS13::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/XboxTLS13
)

include(CMakePackageConfigHelpers)
if(TARGET xboxtls13_openssl)
  set(XBOXTLS_CONFIG_OPENSSL "include(CMakeFindDependencyMacro)\nfind_dependency(OpenSSL)")
else()
  set(XBOXTLS_CONFIG_OPENSSL "")
endif()
configure_package_config_file(
  dev/cmake/XboxTLS13Config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/XboxTLS13Config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/XboxTLS13
)
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/XboxTLS13ConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)
install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/XboxTLS13Config.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/XboxTLS13ConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/XboxTLS13
)
