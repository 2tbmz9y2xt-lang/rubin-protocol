cmake_minimum_required(VERSION 3.12)
project(rubin_wc_shim C)

set(SHIM_SRC
  ${CMAKE_CURRENT_SOURCE_DIR}/rubin_wc_shim.c
)

add_library(rubin_wc_shim SHARED ${SHIM_SRC})

find_path(WOLFSSL_INCLUDE_DIR wolfssl/options.h)
find_library(WOLFSSL_LIBRARY NAMES wolfssl)

if (WOLFSSL_INCLUDE_DIR)
  target_include_directories(rubin_wc_shim PRIVATE ${WOLFSSL_INCLUDE_DIR})
endif()

if (WOLFSSL_LIBRARY)
  target_link_libraries(rubin_wc_shim PRIVATE ${WOLFSSL_LIBRARY})
endif()

set_target_properties(rubin_wc_shim PROPERTIES
  OUTPUT_NAME "rubin_wc_shim"
  POSITION_INDEPENDENT_CODE ON
)

if (WIN32)
  set_target_properties(rubin_wc_shim PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# ── Keywrap smoke test ─────────────────────────────────────────────────
# Compiles shim source directly (no dlopen) for fast unit-test iteration.
# Run: cmake --build . --target run_keywrap_test
# Or via ctest: ctest -R keywrap --output-on-failure
option(RUBIN_BUILD_KEYWRAP_TEST "Build AES-KW smoke test" ON)

if (RUBIN_BUILD_KEYWRAP_TEST AND WOLFSSL_INCLUDE_DIR AND WOLFSSL_LIBRARY)
  add_executable(test_keywrap
    ${CMAKE_CURRENT_SOURCE_DIR}/test_keywrap.c
  )
  target_include_directories(test_keywrap PRIVATE
    ${WOLFSSL_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
  )
  target_link_libraries(test_keywrap PRIVATE ${WOLFSSL_LIBRARY})
  target_compile_options(test_keywrap PRIVATE -Wall -Wextra)

  add_custom_target(run_keywrap_test
    COMMAND test_keywrap
    DEPENDS test_keywrap
    COMMENT "Running AES-256-KW keywrap smoke test"
  )

  enable_testing()
  add_test(NAME keywrap_smoke COMMAND test_keywrap)
endif()


