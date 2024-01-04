#include <iostream>

#include <windows.h>

VOID WINAPI tls_callback(PVOID dllHandle, DWORD reason, PVOID reserved)
{
   if (reason == DLL_PROCESS_ATTACH)
      std::cout << "* tls callback" << std::endl;
}

#ifdef _M_AMD64
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:p_tls_callback")
#pragma const_seg(push)
#pragma const_seg(".CRT$XLAAA")
EXTERN_C const PIMAGE_TLS_CALLBACK p_tls_callback = tls_callback;
#pragma const_seg(pop)
#endif
#ifdef _M_IX86
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_p_tls_callback")
#pragma data_seg(push)
#pragma data_seg(".CRT$XLAAA")
EXTERN_C PIMAGE_TLS_CALLBACK p_tls_callback = tls_callback;
#pragma data_seg(pop)

int main(int argc, char *argv[])
{
   std::cout << "* tls" << std::endl;
   std::cout << "* no reloc" << std::endl;
   return 0;
}
