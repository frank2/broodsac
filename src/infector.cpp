#include <cstdint>
#include <iostream>

#include <windows.h>
#include <winternl.h>
/*
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
*/

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
   const PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<const PIMAGE_NT_HEADERS>(reinterpret_cast<const std::uint8_t *>(module)+module->e_lfanew);
   const PIMAGE_EXPORT_DIRECTORY export_directory = reinterpret_cast<const PIMAGE_EXPORT_DIRECTORY>(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
   const PDWORD name_pointers = reinterpret_cast<const PDWORD>(reinterpret_cast<const std::uint8_t *>(module)+export_directory->AddressOfNames);
   const PWORD name_ordinals = reinterpret_cast<const PWORD>(reinterpret_cast<const std::uint8_t *>(module)+expot_directory->AddressOfNameOrdinals);
   const PDWORD functions = reinterpret_cast<const PDWORD>(reinterpret_cast<const std::uint8_t *>(module)+export_directory->AddressOfFunctions);

   for (std::uint32_t i=0; i<export_directory->NumberOfNames; ++i)
   {
      const char *name = reinterpret_cast<const char *>(reinterpret_cast<const std::uint8_t *>(module)+name_pointers[i]);
      std::wcout << name << std::endl;

      if (fnv321a(name) != hash)
         continue;

      return reinterpret_cast<LPCVOID>(reinterpret_cast<const std::uint8_t *>(module)+functions[name_ordinals[i]]);
   }

   return nullptr;
}

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

   std::wcout << "LoadLibraryA: " << std::hex << (std::uintptr_t)get_proc_by_hash(reinterpret_cast<PIMAGE_DOS_HEADER>(kernel32->DllBase), 0x53b2070f) << std::endl;
   std::wcout << "GetProcAddress: " << std::hex << (std::uintptr_t)get_proc_by_hash(reinterpret_cast<PIMAGE_DOS_HEADER>(kernel32->DllBase), 0xf8f45725) << std::endl;
}

int wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
   infect();
   return 0;
}
