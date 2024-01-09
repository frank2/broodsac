cmake_minimum_required(VERSION 3.15)

if(CMAKE_GENERATOR_PLATFORM NOT STREQUAL "x64")
  message(FATAL_ERROR "This must be built with an x64 target.")
endif()

set(CMAKE_ASM_NASM_OBJECT_FORMAT win64)
project(infection_asm_64 C ASM_NASM) # the C is to include the msvc linker
add_executable(infection_asm_64 main.asm)
target_link_options(infection_asm_64 PUBLIC "LINKER:/ENTRY:main")
