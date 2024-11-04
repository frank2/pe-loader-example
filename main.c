#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

PIMAGE_NT_HEADERS64 get_nt_headers(const uint8_t *image_base) {
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image_base;
   return (PIMAGE_NT_HEADERS64)&image_base[dos_header->e_lfanew];
}

PIMAGE_SECTION_HEADER get_section_table(const uint8_t *image_base) {
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image_base;
   PIMAGE_NT_HEADERS64 nt_headers = get_nt_headers(image_base);
   size_t section_offset = dos_header->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt_headers->FileHeader.SizeOfOptionalHeader;
   return (PIMAGE_SECTION_HEADER)&image_base[section_offset];
}

int main(int argc, char *argv[]) {
   if (argc != 2)
      return 1;

   char *filename = argv[1];
   HANDLE file_handle = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

   if (file_handle == INVALID_HANDLE_VALUE)
      return 1;

   DWORD file_size = GetFileSize(file_handle, NULL);
   uint8_t *disk_buffer = (uint8_t *)malloc(file_size);

   if (!ReadFile(file_handle, disk_buffer, file_size, NULL, NULL))
      return 1;

   /* get the nt headers */
   PIMAGE_NT_HEADERS64 disk_headers = nt_headers(disk_buffer);
   uint8_t *valloc_buffer;
   
   /* valloc a buffer of OptionalHeader.ImageSize */
   /* if IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE is not set, attempt allocation with the image base */
   if ((disk_headers->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0)
      valloc_buffer = (uint8_t *)VirtualAlloc(disk_headers->OptionalHeader.ImageBase,
                                              disk_headers->OptionalHeader.SizeOfImage,
                                              MEM_COMMIT,
                                              PAGE_EXECUTE_READWRITE);
   else
      valloc_buffer = (uint8_t *)VirtualAlloc(0,
                                              disk_headers->OptionalHeader.SizeOfImage,
                                              MEM_COMMIT,
                                              PAGE_EXECUTE_READWRITE);

   if (valloc_buffer == NULL)
      return 1;
   
   /* copy the image into the valloc buffer */
   memcpy(valloc_buffer, disk_buffer, disk_headers->OptionalHeader.SizeOfHeaders);

   PIMAGE_SECTION_HEADER section_table = get_section_table(disk_buffer);

   for (size_t i=0; i<disk_headers->FileHeader.NumberOfSections; ++i)
      memcpy(&valloc_buffer[section_table[i].VirtualAddress],
             &disk_buffer[section_table[i].PointerToRawData],
             section_table[i].SizeOfRawData);

   free(disk_buffer);
   
   PIMAGE_NT_HEADERS64 valloc_headers = nt_headers(valloc_buffer);
   DWORD reloc_rva = valloc_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

   /* if the image has a relocation directory, use it */
   if (reloc_rva != 0) {
      uintptr_t base_delta = (uintptr_t)valloc_buffer - valloc_headers->OptionalHeader.ImageBase;
      uint8_t *base_reloc = &valloc_buffer[reloc_rva];

      while (((PIMAGE_BASE_RELOCATION)base_reloc)->VirtualAddress != 0) {
         PIMAGE_BASE_RELOCATION base_reloc_block = (PIMAGE_BASE_RELOCATION)base_reloc;
         PIMAGE_RELOCATION_ENTRY entry_table = (PIMAGE_RELOCATION_ENTRY)&base_reloc[sizeof(PIMAGE_BASE_RELOCATION)];
         size_t entries = (base_reloc_block->SizeOfBlock-sizeof(PIMAGE_BASE_RELOCATION))/sizeof(WORD);

         for (size_t i=0; i<entries; ++i) {
            DWORD reloc_rva = base_reloc_block->VirtualAddress + entry_table[i].Offset;
            uintptr_t *reloc_ptr = (uintptr_t *)&valloc_buffer[reloc_rva];
               
            if (entry_table[i].Type == IMAGE_REL_BASED_DIR64)
               *reloc_ptr += base_delta;
         }
            
         base_reloc += base_reloc_block->SizeOfBlock;
      }
   }

   /* resolve the import table */
   DWORD import_rva = valloc_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
   DWORD import_size = valloc_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

   if (import_rva != 0) {
      PIMAGE_IMPORT_DESCRIPTOR import_table = (PIMAGE_IMPORT_DESCRIPTOR)&valloc_buffer[import_rva];

      while (import_table->OriginalFirstThunk != 0) {
         HMODULE module = LoadLibraryA((const char *)&valloc_buffer[import_table->Name]);
         uintptr_t *original_thunks = (uintptr_t *)&valloc_buffer[import_table->OriginalFirstThunk];
         uintptr_t *import_addrs = (uintptr_t *)&valloc_buffer[import_table->FirstThunk];
         void *proc;

         while (*original_thunks != 0) {
            if (*original_thunks & 0x8000000000000000)
               *import_addrs = (uintptr_t)GetProcAddress(module, MAKEINTRESOURCE(*original_thunks & 0xFFFF));
            else if (*original_thunks >= import_rva && *original_thunks < import_rva+import_size) {
               char *forwarder = (char *)&valloc_buffer[thunk_rva];
               char *fwd_copy = (char *)malloc(strlen(forwarder));
               memcpy(fwd_copy, forwarder, strlen(forwarder)+1);
               char *fwd_dll = fwd_copy;
               char *fwd_func;

               for (size_t i=0; i<strlen(forwarder); ++i) {
                  if (fwd_copy[i] == '.') {
                     fwd_copy[i] = 0;
                     fwd_func = &fwd_copy[i+1];
                     break;
                  }
               }

               *import_addrs = (uintptr_t)GetProcAddress(LoadLibraryA(fwd_dll), fwd_func);
               free(fwd_dll);
            }
            else {
               PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)&valloc_buffer[*original_thunks];
               *import_addrs = (uintptr_t)GetProcAddress(module, import_by_name->Name);
            }

            ++import_table;
            ++original_thunks;
         }

         ++import_table;
      }
   }

   /* initialize the tls callbacks */
   DWORD tls_rva = valloc_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;

   if (tls_rva != 0) {
      PIMAGE_TLS_DIRECTORY64 tls_dir = (PIMAGE_TLS_DIRECTORY64)&valloc_buffer[tls_rva];
      void (**callbacks)(PVOID, DWORD, PVOID) = (void (**)(PVOID, DWORD, PVOID))tls_dir->AddressOfCallbacks;

      while (*callbacks != NULL) {
         *callbacks(valloc_buffer, DLL_PROCESS_ATTACH, NULL);
         ++callbacks;
      }
   }

   /* call the entrypoint */
   if ((valloc_headers->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0) {
      BOOL (WINAPI *dll_main)(HINSTANCE, DWORD, LPVOID) = (BOOL (*)(HINSTANCE, DWORD, LPVOID))&valloc_buffer[valloc_headers->OptionalHeader.AddressOfEntryPoint];
      dll_main((HINSTANCE)valloc_buffer, DLL_PROCESS_ATTACH, NULL);
   }
   else {
      int (*main)(PVOID) = (int (*)(PVOID))&valloc_buffer[valloc_headers->OptionalHeader.AddressOfEntryPoint];
      main(valloc_buffer);
   }

   VirtualFree(valloc_buffer);

   return 0;
}
