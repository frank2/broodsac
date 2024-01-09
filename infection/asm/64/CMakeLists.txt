cmake_minimum_required(VERSION 3.15)

set(CMAKE_GENERATOR_PLATFORM x64)
set(CMAKE_ASM_NASM_OBJECT_FORMAT win64)
project(infection_asm_64 C ASM_NASM) # the C is to include the msvc linker
add_executable(infection_asm_64 main.asm)
target_link_options(infection_asm_64 PUBLIC "LINKER:/ENTRY:main")
