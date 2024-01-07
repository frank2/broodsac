cmake_minimum_required(VERSION 3.15)

set(CMAKE_ASM_NASM_LINK_EXECUTABLE "C:\\Users\teal\Documents\Tools\Linkers\GoLink\GoLink.exe <LINK_FLAGS> <OBJECTS> /fo <TARGET> <LINK_LIBRARIES>")
set(CMAKE_ASM_NASM_OBJECT_FORMAT bin)
project(payload64 ASM_NASM)
add_executable(payload64 src/payload.asm)
