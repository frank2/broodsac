cmake_minimum_required(VERSION 3.15)

project(infector)

if(CMAKE_GENERATOR_PLATFORM STREQUAL "x64")
  add_subdirectory(c)
  add_subdirectory(asm)
endif()
