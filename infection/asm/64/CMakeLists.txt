cmake_minimum_required(VERSION 3.15)

set(CMAKE_ASM_NASM_OBJECT_FORMAT win64)
project(infection64 ASM_NASM)
enable_language(ASM_NASM)
add_executable(infection64 main.asm)
