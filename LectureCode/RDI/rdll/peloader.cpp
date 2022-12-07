#include "peloader.h"
#include <windows.h>

// Modified https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.c#L38
// WIN_GET_CALLER gets the return address of the current function
// This allows us to work our way backwards in memory to found our base address  
#ifdef __MINGW32__
#define WIN_GET_CALLER() __builtin_extract_return_addr(__builtin_return_address(0))
#else
#pragma intrinsic(_ReturnAddress)
#define WIN_GET_CALLER() _ReturnAddress()
#endif

__declspec(noinline) ULONG_PTR caller( VOID ) { return (ULONG_PTR)WIN_GET_CALLER(); }


#define __forceinline __attribute__((always_inline))



// We start with no context! We don't know where kernel32.dll is
// We don't have cruntime functions like printf or memcpy avaiable to us! 
// We need to populate the above functions with valid function pointers 

  BOOL PerformBaseRelocation(BYTE* lpBaseAddr,IMAGE_NT_HEADERS* ntHeaders)
{
    //unsigned char * codeBase = pLoadedModule->pCodeBase;
    PIMAGE_BASE_RELOCATION relocation;
    PIMAGE_DATA_DIRECTORY directory = &(ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];


    UINT_PTR delta = 	 (UINT_PTR)lpBaseAddr - (UINT_PTR)ntHeaders->OptionalHeader.ImageBase;
    if (directory->Size == 0)
    {
        return (delta == 0);
    }

    relocation = (PIMAGE_BASE_RELOCATION)(lpBaseAddr + directory->VirtualAddress);
    for (; relocation->VirtualAddress > 0; )
    {
        DWORD i;
        unsigned char * dest = lpBaseAddr + relocation->VirtualAddress;
        unsigned short * RelInfo = (unsigned short *)((unsigned char *)relocation + sizeof(IMAGE_BASE_RELOCATION));
        for (i = 0; i < ((relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2); i++, RelInfo++)
        {
            DWORD * patchAddrHL;
#ifdef _WIN64
            ULONGLONG * patchAddr64;
#endif
            INT type, offset;

            // the upper 4 bits define the type of relocation
            type = *RelInfo >> 12;
            // the lower 12 bits define the offset
            offset = *RelInfo & 0xfff;

            switch (type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                // skip relocation
                break;

            case IMAGE_REL_BASED_HIGHLOW:
                // change complete 32 bit address
                patchAddrHL = (DWORD *)(dest + offset);
                *patchAddrHL += (DWORD)delta;
                break;

#ifdef _WIN64
            case IMAGE_REL_BASED_DIR64:
                patchAddr64 = (ULONGLONG *)(dest + offset);
                *patchAddr64 += (ULONGLONG)delta;
                break;
#endif

            default:
                break;
            }
        }

        // advance to next relocation block
        relocation = (PIMAGE_BASE_RELOCATION)(((char *)relocation) + relocation->SizeOfBlock);
    }
    return TRUE;
}

 BYTE* LoadFileBytes(LPWSTR filePath, DWORD* dwSize, _VirtualAlloc hVirtualAlloc){
    HANDLE hFile = NULL;
    wprintf(L"[*] Loading binary payload: %S\n", filePath);

    hFile = CreateFileW(
        filePath, 
        GENERIC_READ, 
        FILE_SHARE_READ, 
        NULL, 
        OPEN_EXISTING, 
        FILE_ATTRIBUTE_NORMAL, 
        NULL);

    if (!hFile) {
        wprintf(L"[!] Could not open payload: %S\n", filePath);
        return NULL;
    }
        // Note the maximum size in bytes is 2^32 
        // this is about 4 GB?
        *dwSize = GetFileSize(hFile, NULL);
        DWORD dwBytesRead = 0;
        BYTE* buffer = (BYTE*) ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, *dwSize);

        if (! ::ReadFile(hFile, buffer, *dwSize, &dwBytesRead, NULL)) {
            wprintf(L"[!] Could not read file: %d!\n", ::GetLastError());
            HeapFree(::GetProcessHeap(), 0 ,buffer);
            buffer = NULL;
        }
    
    CloseHandle(hFile);
    return buffer;
}

// Parse the Nt Headers frmom the Raw peBytes
 IMAGE_NT_HEADERS* parseNtHeader(BYTE* peBytes){
     // Parse the DOS header
    IMAGE_DOS_HEADER* ntDOSHeader  = (IMAGE_DOS_HEADER*) peBytes;
    // The NT Headers begin at the offset of the PE bytes + the Address of the new headers (e_lfanew)
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*) (((UINT_PTR) ntDOSHeader) + (UINT_PTR) ntDOSHeader->e_lfanew);
    return ntHeaders;


}


// Map the PE into memory. This includes headers and sections 
 void*  MemoryMapPE(BYTE* peBytes, IMAGE_NT_HEADERS* ntHeaders, _VirtualAlloc hVirtualAlloc){

    // prefered base address of the PE
    UINT_PTR preferedBaseAddress = ntHeaders->OptionalHeader.ImageBase;

    // size of PE image in bytes
    DWORD dwImageSize = ntHeaders->OptionalHeader.SizeOfImage;

    // Get the RVA of the entry poiny
    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    
    // size of header in bytes
    DWORD dwSizeOfHeaders = ntHeaders->OptionalHeader.SizeOfHeaders;
    // allocate a buffer for the PE

    BYTE* lpImageBaseAddress = NULL;
    
    // try mapping image into it's prefered address 
    lpImageBaseAddress = (BYTE*) hVirtualAlloc(
       (void*) preferedBaseAddress, 
       // NULL,
        dwImageSize, 
        MEM_RESERVE | MEM_COMMIT, 
        PAGE_EXECUTE_READWRITE
    );
    if( !lpImageBaseAddress){
        lpImageBaseAddress = (BYTE*) hVirtualAlloc(
        NULL, 
        dwImageSize, 
        MEM_RESERVE | MEM_COMMIT, 
        PAGE_EXECUTE_READWRITE 
        );
        if(!lpImageBaseAddress){
            //wprintf(L"Failed to allocate virtual memory: %d\n", ::GetLastError());
            // Allocation failed 
            return NULL;
            }
    } else{
    }
    
    // Copy PE Headers to New base address
    //memcpy(lpImageBaseAddress, peBytes, dwSizeOfHeaders);
    for(int si = 0; si < dwSizeOfHeaders; si++){
        // equivilant of lpImageBaseAddress[si] = peBytes[si]
        *(lpImageBaseAddress +si) = *(peBytes + si ); 
    }

    // Get pointer to Begininig of Image sections
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders); 

    // Iterate over Image Sections 
    for(int i=0; i<ntHeaders->FileHeader.NumberOfSections; ++i) {
        // Calculate VA by adding the RVA to the Base Address
        
        // Pointer to Section Bytes in the file (offset of file)
        void* sBytes = (void*)((UINT_PTR)peBytes + (UINT_PTR)sections[i].PointerToRawData);

        // Where we want to write the section bytes (RVA --> VA)
        void* dest = (void*) ((UINT_PTR) lpImageBaseAddress + (UINT_PTR) sections[i].VirtualAddress); 
        
        char *csrc = (char *)sBytes;
        char *cdest = (char *)dest;
        
        // check if there is Raw data to copy
        if(sections[i].SizeOfRawData > 0) {
            //  Equivilant of memcpy(dest,   sBytes, sections[i].SizeOfRawData);           
            for(DWORD si = 0; si <sections[i].SizeOfRawData; si++ ){
                //*(copy+i)=*(ptr+i);
                *(cdest + si) = * (csrc + si);
            }

        } else {
            for(DWORD si = 0; si < sections[i].Misc.VirtualSize; si ++ ){
                // equivilant of memset(dest, 0, sections[i].Misc.VirtualSize);
                // just zero it out. We might need to fill this up later. 
                *(cdest + si) = 0;

            }
        }
    }
    // we return a pointer to the base address of the Newly mapped PE
    return lpImageBaseAddress;
}

 BOOL FixSectionPermissions(void* lpImageBase,  IMAGE_NT_HEADERS* ntHeaders, _VirtualProtect hVirtualProtect){
    // Map PE sections privileges 

     // Get pointer to Begininig of Image sections
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders); 
    DWORD oldProtect = 0;
    // Headers should be Read Only
    if (!hVirtualProtect(
        lpImageBase, 
        ntHeaders->OptionalHeader.SizeOfHeaders, 
        PAGE_READONLY, 
        &oldProtect
        )){
            return FALSE;
        }

    //  Walk sections and fix permissions
    for(int i=0; i<ntHeaders->FileHeader.NumberOfSections; ++i) {
        // Compute Virtual Address by adding rva to the image base
        BYTE* dest = (BYTE*)lpImageBase + sections[i].VirtualAddress;

        DWORD sectionCharacteristic = sections[i].Characteristics;
        DWORD dwMemProtect = 0; //flags are not the same between virtal protect and the section header



        if(sectionCharacteristic & IMAGE_SCN_MEM_EXECUTE) {
            dwMemProtect = (sectionCharacteristic & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;

        } else {
            dwMemProtect = (sectionCharacteristic & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;

        }
        if (!hVirtualProtect(dest, sections[i].Misc.VirtualSize, dwMemProtect, &oldProtect)){
            return FALSE;
        }

    } 
    return TRUE;
}

// Build the Import Address table
 BOOL BuildIAT(void* lpImgBaseAddr,IMAGE_NT_HEADERS* ntHeaders, _LoadLibraryA hLoadLibraryA, _GetProcAddress hGetProcAddress ){
   // lpDatadir = ntHeaders->OptionalHeader.DataDirectory;
   // Get the Import Directory Table to iterate over Required DLLs
   
   IMAGE_DATA_DIRECTORY importDataDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
   if (importDataDir.Size == 0){
       return TRUE;
   }
   
   // Calculate pointer to Import Directory Table Object
   IMAGE_IMPORT_DESCRIPTOR* importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)( (UINT_PTR)lpImgBaseAddr + importDataDir.VirtualAddress);

    for(int i = 0; importDescriptor[i].Name != NULL; i++){
        // Find the RVA of the start of the LPCSTR 
        char* moduleName = (char*) ((UINT_PTR)lpImgBaseAddr + importDescriptor[i].Name); 

        HMODULE hModule = hLoadLibraryA(moduleName);
        
        // if we can't resolve our imports...just give up :D
        if(!hModule){
            // panic
            return FALSE;
        }
        // the IDT has all of the libraries we need to import.
        // Now we walk import lookup table (ILT) to find all
       
        // thunk
        IMAGE_THUNK_DATA* lookupTable = (IMAGE_THUNK_DATA*) ((UINT_PTR)lpImgBaseAddr + importDescriptor[i].OriginalFirstThunk);

        if(!importDescriptor[i].OriginalFirstThunk){
            lookupTable = (IMAGE_THUNK_DATA*) ((UINT_PTR)lpImgBaseAddr + importDescriptor[i].FirstThunk);
        }
        // the address table is a copy of the lookup table at first
        // but we put the addresses of the loaded function inside.
        // this is exactly the IAT
        // func
        IMAGE_THUNK_DATA* addressTable = (IMAGE_THUNK_DATA*) ( (UINT_PTR)lpImgBaseAddr +  importDescriptor[i].FirstThunk);

        // iterate over Lookup Table 
        for(int j=0; lookupTable[j].u1.AddressOfData != 0; ++j) {
            FARPROC* hFunction = NULL;

            // Check the lookup table for the adresse of the function name to import
             UINT_PTR lookupAddr = lookupTable[j].u1.AddressOfData;

            // the first bit here tells us whether or not we import by name or ordinal
            ////if first bit is not 1
            if((lookupAddr & IMAGE_ORDINAL_FLAG) == 0) { 
                // import by name : get the IMAGE_IMPORT_BY_NAME struct
         
                IMAGE_IMPORT_BY_NAME* imageImport = (IMAGE_IMPORT_BY_NAME*) ((UINT_PTR)lpImgBaseAddr + lookupAddr);
                // The null terminated function name  
                char* funcName = (char*) &(imageImport->Name);
                // The null terminated function name  
                // get that function address from it's module and name
                hFunction = (FARPROC*) hGetProcAddress(hModule, funcName);
            } else {
                // import by ordinal, directly
                hFunction = (FARPROC*) GetProcAddress(hModule, (LPSTR) lookupAddr);
            }

            if(!hFunction) {
                return NULL;
            }

            // change the IAT, and put the function address inside.
            addressTable[j].u1.Function = (UINT_PTR) hFunction;
        }
    }
    return TRUE;
}


inline void HandleTLSCallbacks(void* lpImageBase,  IMAGE_NT_HEADERS* ntHeaders){
     if(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
   {
      PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)( (UINT_PTR)lpImageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
      PIMAGE_TLS_CALLBACK *callback = (PIMAGE_TLS_CALLBACK *) tls->AddressOfCallBacks;

      while(*callback)
      {
         (*callback)((LPVOID) lpImageBase, DLL_PROCESS_ATTACH, NULL);
         callback++;
      }
   } else{
       // no TLS callbacks
       return;
   }
}

// Finds the base address of our loaded PE
void* FindBaseAddr(){
    // initilize to the address of the return of this function
    UINT_PTR baseAddr = caller();
    UINT_PTR uiHeaderValue;

    while( TRUE )
	{
        //Find the MZ header, and do some sanity checks 
		if( ((PIMAGE_DOS_HEADER)baseAddr)->e_magic == IMAGE_DOS_SIGNATURE )
		{
			uiHeaderValue = ((PIMAGE_DOS_HEADER)baseAddr)->e_lfanew;

			// some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
			// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
			if( uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024 )
			{
				uiHeaderValue += baseAddr;
				// break if we have found a valid MZ/PE header: 0x00004550 -->"PE\0\0" (ASCII)
				if( ((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE )
					break;
			}
		}
        // we need to go back further! This isn't the base address
        // Note this is 1 byte at a time 
		baseAddr--;
	}
    return (void*)  baseAddr;
}


void* GetProcAddressR(void* lpBaseAddr, char* funName){

}


// C++ will mangle names in exported functions. This is why we use edtern "C"
extern "C" __declspec(dllexport) UINT_PTR  WINAPI Loader( LPVOID lpParameter)
{
    // This is where we call the reflectiveloader 
    UINT_PTR *funcs = (UINT_PTR*) lpParameter; 
    _LoadLibraryA hLoadLibraryA = (_LoadLibraryA) funcs[0];
    _GetProcAddress hGetProcAddress = (_GetProcAddress) funcs[1];
      _VirtualAlloc hVirtualAlloc = (_VirtualAlloc) funcs[2];
    _VirtualProtect hVirtualProtect = (_VirtualProtect) funcs[3];
   
    
    // base address of our PE in memory
    BYTE* peBaseAddr = (BYTE*) FindBaseAddr();
    IMAGE_NT_HEADERS* ntHeaders = parseNtHeader(peBaseAddr);
    IMAGE_DOS_HEADER* ntDOSHeader  = (IMAGE_DOS_HEADER*) peBaseAddr;
     // Map the headers and sections into memory 
    void* lpImageBaseAddress = MemoryMapPE(peBaseAddr, ntHeaders, hVirtualAlloc);

    // Handle imports 
    // Handle Relocations 
    UINT_PTR addrDelta = 	 (UINT_PTR)lpImageBaseAddress - (UINT_PTR)ntHeaders->OptionalHeader.ImageBase;

    if(!PerformBaseRelocation((BYTE*)lpImageBaseAddress, ntHeaders  )){
    }
    BuildIAT(lpImageBaseAddress, ntHeaders, hLoadLibraryA, hGetProcAddress );

    FixSectionPermissions(lpImageBaseAddress, ntHeaders, hVirtualProtect );
    HandleTLSCallbacks(lpImageBaseAddress, ntHeaders );

    UINT_PTR lpVoidEntry =  (UINT_PTR)lpImageBaseAddress +  (UINT_PTR) ntHeaders->OptionalHeader.AddressOfEntryPoint ;

    ((DLLMAIN)lpVoidEntry)( (HINSTANCE)lpImageBaseAddress, DLL_PROCESS_ATTACH, NULL );
    return (UINT_PTR) lpImageBaseAddress;
}


 

/*
void* ReflectiveLoader(UINT_PTR loadLibraryA, UINT_PTR getProcAddress ){
    _LoadLibraryA hLoadLibraryA =(_LoadLibraryA) loadLibraryA;
    _GetProcAddress hGetProcAddress =(_GetProcAddress) getProcAddress;

    // might get placed in the data direcotry?
    HMODULE hKernel32 =  hLoadLibraryA("kernel32.dll");
     _VirtualAlloc hVirtualAlloc = (_VirtualAlloc) hGetProcAddress(hKernel32, "VirtualAlloc");
    _VirtualProtect hVirtualProtect = (_VirtualProtect) hGetProcAddress(hKernel32, "VirtualProtect");
    
    // base address of our PE in memory
    BYTE* peBaseAddr = (BYTE*) FindBaseAddr();
    IMAGE_NT_HEADERS* ntHeaders = parseNtHeader(peBaseAddr);
    IMAGE_DOS_HEADER* ntDOSHeader  = (IMAGE_DOS_HEADER*) peBaseAddr;
     // Map the headers and sections into memory 
    void* lpImageBaseAddress = MemoryMapPE(peBaseAddr, ntHeaders, hVirtualAlloc);

    // Handle imports 
    // Handle Relocations 
    UINT_PTR addrDelta = 	 (UINT_PTR)lpImageBaseAddress - (UINT_PTR)ntHeaders->OptionalHeader.ImageBase;

    if(!PerformBaseRelocation((BYTE*)lpImageBaseAddress, ntHeaders  )){
    }
    BuildIAT(lpImageBaseAddress, ntHeaders, hLoadLibraryA, hGetProcAddress );

    FixSectionPermissions(lpImageBaseAddress, ntHeaders, hVirtualProtect );
    HandleTLSCallbacks(lpImageBaseAddress, ntHeaders );

    UINT_PTR lpVoidEntry =  (UINT_PTR)lpImageBaseAddress +  (UINT_PTR) ntHeaders->OptionalHeader.AddressOfEntryPoint ;

    ((DLLMAIN)lpVoidEntry)( (HINSTANCE)lpImageBaseAddress, DLL_PROCESS_ATTACH, NULL );
    return lpImageBaseAddress;


}
*/