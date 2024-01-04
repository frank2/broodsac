cmake_minimum_required(VERSION 3.15)

#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LARGEADDRESSAWARE:NO")
project(infectables_tls CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_subdirectory(reloc)
add_subdirectory(noreloc)
add_dependencies(infectables_tls infectables_tls_reloc infectables_tls_noreloc)
