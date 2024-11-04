#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

uintptr_t MAIN_MODULE = 0;
BOOL TLS_CALLED = FALSE;

VOID WINAPI tls_callback(PVOID dll_handle, DWORD reason, PVOID reserved) {
   if (reason == DLL_PROCESS_ATTACH) {
      TLS_CALLED = TRUE;
      MAIN_MODULE = (uintptr_t)GetModuleHandleA(NULL);
   }
}

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:p_tls_callback")
#pragma const_seg(push)
#pragma const_seg(".CRT$XLAAA")
EXTERN_C const PIMAGE_TLS_CALLBACK p_tls_callback = tls_callback;
#pragma const_seg(pop)

int main(int argc, char *argv[]) {
   printf("* tls called: %d\n", TLS_CALLED);
   printf("* main module: %016llx\n", MAIN_MODULE);

   return TRUE;
}
