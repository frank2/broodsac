cmake_minimum_required(VERSION 3.15)

project(infection_asm)

if(CMAKE_GENERATOR_PLATFORM STREQUAL "Win32")
  add_subdirectory(32)
elseif(CMAKE_GENERATOR_PLATFORM STREQUAL "x64")
  add_subdirectory(64)
endif()
