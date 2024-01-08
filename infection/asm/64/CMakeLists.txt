cmake_minimum_required(VERSION 3.15)

set(CMAKE_ASM_NASM_OBJECT_FORMAT win64)
project(infection64 C ASM_NASM) # the C is to include the msvc linker
add_executable(infection64 main.asm)
target_link_options(infection64 PUBLIC "LINKER:/ENTRY:main")
