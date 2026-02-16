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

