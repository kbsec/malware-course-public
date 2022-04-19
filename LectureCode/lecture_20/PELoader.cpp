#include "PELoader.h"



BYTE* MemoryMapPE(BYTE* peFileBytes){
    // Parse the DOS Header. Use this to find the start of the nt headders
    IMAGE_DOS_HEADER* lpDOSHeader  = (IMAGE_DOS_HEADER*) peFileBytes;
    IMAGE_NT_HEADERS* ntImageHeaders = (IMAGE_NT_HEADERS*) (((UINT_PTR) lpDOSHeader) + (UINT_PTR) lpDOSHeader->e_lfanew);


    // base address of the pe
    UINT_PTR lpPreferedImageBase = ntImageHeaders->OptionalHeader.ImageBase;

    // size of exe image
    DWORD dwImageSize = ntImageHeaders->OptionalHeader.SizeOfImage;
    // Get the RVA of the entry point
    DWORD dwEntryRVA = ntImageHeaders->OptionalHeader.AddressOfEntryPoint;
    DWORD dwHeaderSize = ntImageHeaders->OptionalHeader.SizeOfHeaders;

    printf("[+] Entrypoint RVA: %lu\n",  dwEntryRVA);
    printf("[+] Preferred Image Base address: %p\n", (void*) lpPreferedImageBase);
    printf("[+] Image size: %lu\n", dwImageSize);
    printf("[+] Size of headers: %lu\n", dwHeaderSize);
    
    // Allocate a contiguous buffer for our PE
    BYTE* lpImageBase =  (BYTE*)::VirtualAlloc(
//      (VOID*)lpPreferedImageBase, 
        NULL,
        dwImageSize, 
        MEM_RESERVE | MEM_COMMIT, 
        PAGE_READWRITE // was PAGE_READWRITE fix later 
        );
    if(!lpImageBase){
        printf("Failed to allocate virtual memory: %lu\n", ::GetLastError());
        return NULL;
    }
    printf("[+] Image Base Address %p\n", (void*) lpImageBase);

    // Map PE sections into memory 
    memcpy(lpImageBase, peFileBytes, dwHeaderSize);

    printf("[+] Wrote %lu bytes for the headers\n", dwHeaderSize);

    // Image Section Start
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntImageHeaders); 

    // Iterate through ach section
    printf("[+] Memory mapping the PE sections...");
    for(int i=0; i<ntImageHeaders->FileHeader.NumberOfSections; ++i) {
        // calculate the virtual Address from the RVA 
        // section[i].VirtualAddress is the RVA
        void* dest = (void*) ((UINT_PTR) lpImageBase + (UINT_PTR) sections[i].VirtualAddress); 
        void* sBytes = (void*)((UINT_PTR)peFileBytes + (UINT_PTR)sections[i].PointerToRawData);


        if(sections[i].SizeOfRawData > 0) {
            // Copy section into memory
            printf("Copying Section %s:%lu \n", sections[i].Name, sections[i].SizeOfRawData);
            memcpy(dest,   sBytes, sections[i].SizeOfRawData);
        } else {
            memset(dest, 0, sections[i].Misc.VirtualSize);
            printf("Skipping Secion %s\n", sections[i].Name);
        }
    }
    // at this point the PE sections are mapped 
    return lpImageBase;
}


BOOL BuildImports(BYTE* lpImageBase){
    IMAGE_DOS_HEADER* lpDOSHeader  = (IMAGE_DOS_HEADER*) lpImageBase;
    IMAGE_NT_HEADERS* ntImageHeaders = (IMAGE_NT_HEADERS*) (((UINT_PTR) lpDOSHeader) + (UINT_PTR) lpDOSHeader->e_lfanew);

    // start imports 
    IMAGE_DATA_DIRECTORY* lpDataDirectory = ntImageHeaders->OptionalHeader.DataDirectory;

    DWORD importDescriptorRVA = lpDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

        // load the address of the import descriptors list 
    IMAGE_IMPORT_DESCRIPTOR* lpImportDescriptorList = (IMAGE_IMPORT_DESCRIPTOR*) ( lpImageBase + importDescriptorRVA );

     // this array is terminated with an ImportDescriptor with all zero values
     // PSeudocode: For Each imported Library...
    for(int i=0; lpImportDescriptorList[i].OriginalFirstThunk != 0; ++i) {
        
        // Get the name of the dll, and import it
        char* moduleName = (char*) lpImageBase + lpImportDescriptorList[i].Name;
        HMODULE hImportModule = LoadLibraryA(moduleName);
        if(hImportModule == NULL) {
            printf("[!] Failed to Load %s because of %lu\n", moduleName, ::GetLastError());
            return FALSE ;
        }
        printf("[+] Loaded %s at %p\n", moduleName, (void*) hImportModule );

        // the lookup table points to function names or ordinals => it is the IDT
        IMAGE_THUNK_DATA* lookup_table = (IMAGE_THUNK_DATA*) (lpImageBase + lpImportDescriptorList[i].OriginalFirstThunk);

        // the address table is a copy of the lookup table at first
        // but we put the addresses of the loaded function inside => that's the IAT
        IMAGE_THUNK_DATA* address_table = (IMAGE_THUNK_DATA*) (lpImageBase + lpImportDescriptorList[i].FirstThunk);
        //pseudo code: For each function in the imported library...
          // null terminated array, again
        for(int i=0; lookup_table[i].u1.AddressOfData != 0; ++i) {
            void* function_handle = NULL;

            // Check the lookup table for the adresse of the function name to import
             UINT_PTR lookup_addr = lookup_table[i].u1.AddressOfData;

            if((lookup_addr & IMAGE_ORDINAL_FLAG) == 0) { //if first bit is not 1
                // import by name : get the IMAGE_IMPORT_BY_NAME struct
                IMAGE_IMPORT_BY_NAME* image_import = (IMAGE_IMPORT_BY_NAME*) (lpImageBase + lookup_addr);
                // this struct points to the ASCII function name
                char* funct_name = (char*) &(image_import->Name);
                // get that function address from it's module and name
                function_handle = (void*) GetProcAddress(hImportModule, funct_name);
                printf("|___->[+] Resolved %s$%s to %p\n",moduleName, funct_name, function_handle);
            } else {
                // import by ordinal, directly
                function_handle = (void*) GetProcAddress(hImportModule, (LPSTR) lookup_addr);
                printf("\t[+] Resolved (ordinal) %s to %p\n", (LPSTR) lookup_addr, function_handle);
            }

            if(function_handle == NULL) {
                return FALSE;
            }

            // change the IAT, and put the function address inside.
            address_table[i].u1.Function = (UINT_PTR) function_handle;
        }

    }
    return TRUE;
}

// Helper struct to make parsing Relocations easier 
struct relocationBlock{
    DWORD pageRVA;
    DWORD dwBlockSize;
    WORD wRelocation[];
};



BOOL HandleRelocations(BYTE* lpImageBase){
    IMAGE_DOS_HEADER* lpDOSHeader  = (IMAGE_DOS_HEADER*) lpImageBase;
    IMAGE_NT_HEADERS* ntImageHeaders = (IMAGE_NT_HEADERS*) (((UINT_PTR) lpDOSHeader) + (UINT_PTR) lpDOSHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY* lpDataDirectory = ntImageHeaders->OptionalHeader.DataDirectory;

    UINT_PTR lpPreferedImageBase = ntImageHeaders->OptionalHeader.ImageBase;
    // calculate the delta of preferred VA vs actual VA
    ptrdiff_t vaRelocDelta = (ptrdiff_t)( lpImageBase - lpPreferedImageBase);
    if (vaRelocDelta ==0){
        printf("[+] We got our prefred VA. No relocations to be done!\n");
        return TRUE;
    }
    DWORD relocDirRVA = lpDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    if(relocDirRVA == 0){
        printf("[!] Warning, there is no Relocation Table!\n");
        return TRUE ;
    }
    printf("[+] Shifted Base by %p \n", (void*) vaRelocDelta);
    printf("[+] Image Base Reloc VA %lu\n", lpDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    printf("[+] Relocation Size: %lu\n", lpDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size );

    printf("[+] There are relocations to perform...\n");
    struct relocationBlock* relocation =  (relocationBlock*) (lpImageBase + relocDirRVA);
    printf("[+] Relocation Blocks start at %p\n", (void*) relocation);

    while(relocation->pageRVA > 0 ){
        // calculate the number of relocations to perform in this block 
        DWORD dwRelocs = (relocation->dwBlockSize - (sizeof(DWORD) * 2) )/(sizeof(WORD) );
        printf("[+] Block: %lu\n", dwRelocs);
        printf("[+] RVA of relocation: %lu\n", relocation->pageRVA);
        // base address of the 
        UINT_PTR lpDest  = (UINT_PTR)(lpImageBase + relocation->pageRVA );

        for(DWORD i = 0; i < dwRelocs; i++){
            WORD wBlock = relocation->wRelocation[i];
            

            // Type of Relocation to perform
            DWORD dwRelocType = wBlock >> 12;
            // offset to perform relocation 
            INT intOffset =  wBlock & 0xfff ;
            printf("|___[+] Relocation type: %lu, offset: %d\n", dwRelocType, intOffset);
             
            // perform relocation 
            ULONGLONG *lpRelocVA = NULL;
            
            switch (dwRelocType){
                case IMAGE_REL_BASED_ABSOLUTE:
                    printf("|___[+] IMAGE_REL_BASED_ABSOLUTE --> Nothing to be done\n");
                    break;
                case IMAGE_REL_BASED_DIR64:
                    // we add the offset from the VA
                    printf("");
                    lpRelocVA= (UINT_PTR*) (lpDest + intOffset);
                    *lpRelocVA += (UINT_PTR) vaRelocDelta;
                    break;
                default:
                    printf("|___[!] Unrecognized Relocation Type: %lu\n", dwRelocType);
                    break;
            };
        }
       
        relocation =(relocationBlock*) ((UINT_PTR) relocation + relocation->dwBlockSize);
        printf("|___[+] Next Block: %p->%lu\n", (void*) relocation, relocation->dwBlockSize);
    }
    return TRUE;
}


BOOL FixSectionPermissions(BYTE* lpImageBase){
    IMAGE_DOS_HEADER* lpDOSHeader  = (IMAGE_DOS_HEADER*) lpImageBase;
    IMAGE_NT_HEADERS* ntImageHeaders = (IMAGE_NT_HEADERS*) (((UINT_PTR) lpDOSHeader) + (UINT_PTR) lpDOSHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntImageHeaders); 
    DWORD oldProtect;

    VirtualProtect(lpImageBase, ntImageHeaders->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProtect);
    // stolen from rdll
    for(int i=0; i<ntImageHeaders->FileHeader.NumberOfSections; ++i) {
        BYTE* dest = (BYTE*)lpImageBase + sections[i].VirtualAddress;
        DWORD s_perm = sections[i].Characteristics;
        DWORD v_perm = 0; //flags are not the same between virtal protect and the section header
        if(s_perm & IMAGE_SCN_MEM_EXECUTE) {
            v_perm = (s_perm & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else {
            v_perm = (s_perm & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
        }
        printf("[+] Setting permission of %s to %lu \n", sections[i].Name, v_perm);
        if (!VirtualProtect(dest, sections[i].Misc.VirtualSize, v_perm, &oldProtect)){
            printf("[!] Failed to change permissions: %lu\n", ::GetLastError());
            return FALSE;
        }

    } 

    printf("[+] Base and offset: %p %lu\n", (void*)lpImageBase, ntImageHeaders->OptionalHeader.AddressOfEntryPoint);
  return TRUE;

    
}

UINT_PTR CalculateEntrypoint(BYTE* lpImageBase){
    IMAGE_DOS_HEADER* lpDOSHeader  = (IMAGE_DOS_HEADER*) lpImageBase;
    IMAGE_NT_HEADERS* ntImageHeaders = (IMAGE_NT_HEADERS*) (((UINT_PTR) lpDOSHeader) + (UINT_PTR) lpDOSHeader->e_lfanew);
    return (UINT_PTR) (lpImageBase +  (UINT_PTR)ntImageHeaders->OptionalHeader.AddressOfEntryPoint);
}

void HandleTLS(BYTE* lpImageBase){

}