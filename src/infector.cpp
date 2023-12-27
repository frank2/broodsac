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

void infect(void)
{
#if defined(BROODSAC32)
   PPEB peb = reinterpret_case<PPEB>(__readfsdword(0x30));
#elif defined(BROODSAC64)
   PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#endif

   PFULL_PEB_LDR_DATA ldr = reinterpret_cast<PFULL_PEB_LDR_DATA>(peb->Ldr);
   PLIST_ENTRY list_entry = ldr->InLoadOrderModuleList.Flink;

   while (list_entry != nullptr)
   {
      /* do the needful */
      PFULL_LDR_DATA_TABLE_ENTRY table_entry = reinterpret_cast<PFULL_LDR_DATA_TABLE_ENTRY>(list_entry);

      std::wcout << table_entry->BaseDllName.Buffer << std::endl;

      list_entry = table_entry->InLoadOrderLinks.Flink;
   }
}

int wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
   infect();
   return 0;
}
