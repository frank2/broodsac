cmake_minimum_required(VERSION 3.15)

if(CMAKE_GENERATOR_PLATFORM NOT STREQUAL "Win32")
  message(FATAL_ERROR "This must be built with a Win32 target.")
endif()

set(CMAKE_ASM_NASM_OBJECT_FORMAT win32)
project(infection_asm_32 C ASM_NASM) # the C is to include the msvc linker
add_executable(infection_asm_32 main.asm)
target_link_options(infection_asm_32 PUBLIC "LINKER:/ENTRY:main")
