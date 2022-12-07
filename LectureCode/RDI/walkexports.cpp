#include <windows.h>
#include <stdio.h>


// Addresses in memory will differ greatly from Offsets on disk!
DWORD Rva2Offset( DWORD dwRva, UINT_PTR uiBaseAddress )
{    
	WORD wIndex                          = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders         = NULL;
	
	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);
    //compute sections 
	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    if( dwRva < pSectionHeader[0].PointerToRawData )
        return dwRva;
    for( wIndex=0 ; wIndex < pNtHeaders->FileHeader.NumberOfSections ; wIndex++ )
    {   
        if( dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData) )           
           return ( dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData );
    }
    
    return 0;
}

//
DWORD WalkExportTable(BYTE* peBytes, char* name){
    wprintf(L"[+] File base ADDR of bytes: %p \n", (void*) peBytes);
    // Get the DOS header
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*) peBytes;
    wprintf(L"[+] Parsed DOS Header: %p\n", (void*) dosHeader);
    // Get the RVA of NT Headers
    IMAGE_NT_HEADERS* ntHeaders =  (IMAGE_NT_HEADERS*) (((UINT_PTR) dosHeader) + (UINT_PTR) dosHeader->e_lfanew);
    //UINT_PTR lpBaseAddr = ntHeaders->OptionalHeader.ImageBase;
    wprintf(L"[+] Parsed NT Header: %p\n", (void*) ntHeaders );

    // Get the data directory 
    IMAGE_DATA_DIRECTORY* dataDirectory = ntHeaders->OptionalHeader.DataDirectory;
    wprintf(L"[+] Parsed Data Directory: %p\n", (void*) dataDirectory );

    // parse the export directory 
    IMAGE_DATA_DIRECTORY exportDirectoryEntry = dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT ];
    wprintf(L"[+] Parsed Export Directory Entry: %p\n", (void*) &exportDirectoryEntry );

    // add offset to the base address of the PE bytes to get the data directory
    IMAGE_EXPORT_DIRECTORY* exportDir =(IMAGE_EXPORT_DIRECTORY*) ( (UINT_PTR) peBytes + Rva2Offset(exportDirectoryEntry.VirtualAddress,(UINT_PTR) peBytes));

    wprintf(L"[+] Export Directory: %p\n", (void*) exportDir);

    wprintf(L"[+] RVA: %d\n",exportDir->AddressOfFunctions );
    DWORD* functionArray = (DWORD*)(  ( (UINT_PTR) peBytes +  Rva2Offset(exportDir->AddressOfFunctions, (UINT_PTR)peBytes)));

    wprintf(L"[+] Start Address of functionArray: %p\n", (void*) functionArray);
    
    DWORD* nameArray = (DWORD*) ((UINT_PTR)peBytes + Rva2Offset(exportDir->AddressOfNames, (UINT_PTR)peBytes));
    
    wprintf(L"[+] Start Address of functionNameArray: %p\n", (void*) nameArray);

    DWORD dwNames = exportDir->NumberOfNames;
    wprintf(L"Walking Exports\n");
    for(int i = 0; i < dwNames; i++){
        if(functionArray[i] == NULL){
            wprintf(L"[!] Skipping %d as the function addr is null...\n", i);
            continue;
        }

        char* fName = (char*)( (UINT_PTR) peBytes + Rva2Offset(nameArray[i],(UINT_PTR) peBytes));
        if(!strcmp(fName, name)){
            wprintf(L"[!!] Found %s at %p\n ", name,  (void*)functionArray[i] );
            auto x =  Rva2Offset(functionArray[i],(UINT_PTR) peBytes);
            wprintf(L"Fileoffset is %p\n", (void*)x);
            return x;
        }
        //wprintf(L"[+] Exported function %s at RVA %p\n", fName, (void*)functionArray[i] );
    }
return 0;
}



/*
int wmain(int argc, WCHAR* argv[]){
    if (argc != 3){
        wprintf(L"Usage: %S <path_to_pe> <outfile> \n", argv[0]);
        return 0;
    }
    DWORD dwFileSize = 0;
    BYTE* fileBytes = LoadFileBytes(argv[1], &dwFileSize);
    wprintf(L"[+] File size: %d bytes\n", dwFileSize);
    if (!fileBytes){
        return 0;
    } 
    WalkExportTable(fileBytes, "VirtualAlloc");
}
*/