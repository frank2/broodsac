cmake_minimum_required(VERSION 3.15)

set(CMAKE_ASM_NASM_OBJECT_FORMAT win64)
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LARGEADDRESSAWARE:NO")
project(broodsac_infector CXX ASM_NASM)
project(broodsac_infection CXX ASM_NASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

file(GLOB_RECURSE SRC_FILES FOLLOW_SYMLINKS ${PROJECT_SOURCE_DIR}/src/*.cpp)
file(GLOB_RECURSE ASM_FILES FOLLOW_SYMLINKS ${PROJECT_SOURCE_DIR}/src/*.asm)
file(GLOB_RECURSE HDR_FILES FOLLOW_SYMLINKS ${PROJECT_SOURCE_DIR}/src/*.hpp ${PROJECT_SOURCE_DIR}/res/*.hpp)
file(GLOB_RECURSE RES_FILES FOLLOW_SYMLINKS ${PROJECT_SOURCE_DIR}/res/*.rc)

source_group(TREE "${PROJECT_SOURCE_DIR}" PREFIX "Source Files" FILES ${SRC_FILES})
source_group(TREE "${PROJECT_SOURCE_DIR}" PREFIX "Header Files" FILES ${HDR_FILES})
source_group(TREE "${PROJECT_SOURCE_DIR}" PREFIX "Assembly Files" FILES ${ASM_FILES})
source_group(TREE "${PROJECT_SOURCE_DIR}" PREFIX "Resource Files" FILES ${RES_FILES})

add_executable(broodsac_infector WIN32 src/infector.cpp)
#target_sources(broodsac PRIVATE ${RES_FILES})

add_compile_definitions(BROODSACDEBUG)
add_compile_definitions(UNICODE)
add_compile_definitions(_UNICODE)

#target_link_libraries(goldbox sostav)

target_include_directories(broodsac_infector PUBLIC
  "${PROJECT_SOURCE_DIR}/src"
)
