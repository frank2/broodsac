cmake_minimum_required(VERSION 3.15)

project(infectables_notls_reloc C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(infectables_notls_reloc main.c)
