#include "readbytes.h"

BYTE* LoadFileBytes(char* filePath, DWORD* dwSize){
    HANDLE hFile = NULL;
    printf("[*] Loading binary payload: %s\n", filePath);

    hFile = CreateFileA(
        filePath, 
        GENERIC_READ, 
        FILE_SHARE_READ, 
        NULL, 
        OPEN_EXISTING, 
        FILE_ATTRIBUTE_NORMAL, 
        NULL);

    if (!hFile) {
        printf("[!] Could not open payload: %s\n", filePath);
        return NULL;
    }
        // Note the maximum size in bytes is 2^32 
        // this is about 4 GB?
        *dwSize = GetFileSize(hFile, NULL);
        DWORD dwBytesRead = 0;
        BYTE* buffer = (BYTE*) malloc(*dwSize);
        //::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, *dwSize);

        if (! ::ReadFile(hFile, buffer, *dwSize, &dwBytesRead, NULL)) {
            printf("[!] Could not read file: %lu!\n", ::GetLastError());
            free(buffer);
            //HeapFree(::GetProcessHeap(), 0 ,buffer);
            buffer = NULL;
        }
    
    CloseHandle(hFile);
    printf("[+] Loaded PE!");
    return buffer;
}
