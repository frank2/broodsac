cmake_minimum_required(VERSION 3.15)

project(infector C ASM_NASM)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
option(BROODSAC_DEBUG "Turn on debugging for Broodsac" OFF)
set(BROODSAC_INFECTABLES "" CACHE STRING "Set the folder for Broodsac to infect, only relevant with BROODSAC_DEBUG")

add_subdirectory(${PROJECT_SOURCE_DIR}/infection/asm/32)
add_subdirectory(${PROJECT_SOURCE_DIR}/infection/asm/64)

add_executable(infector main.c)
target_link_libraries(infector infection_asm_32 infection_asm_64)

if (BROODSAC_DEBUG)
  cmake_path(ABSOLUTE_PATH BROODSAC_INFECTABLES NORMALIZE)
  cmake_path(NATIVE_PATH BROODSAC_INFECTABLES BROODSAC_INFECTABLES)
  string(REPLACE "\\" "\\\\" BROODSAC_INFECTABLES "${BROODSAC_INFECTABLES}")
  target_compile_definitions(infector PUBLIC
    BROODSAC_DEBUG
    BROODSAC_INFECTABLES="${BROODSAC_INFECTABLES}")
endif()
