#include "PELoader.h"
#include "readbytes.h"

typedef void EntryPoint(void);


int main(int argc, char* argv[]){
    if (argc != 2){
        printf("Usage: %s <path to PE>\n", argv[0]);
        return 0;
    }
    DWORD dwFileSize = 0;
    BYTE* lpFileBytes = LoadFileBytes(argv[1], &dwFileSize);
    if (lpFileBytes ==NULL){
        printf("Failed to load %s\n", lpFileBytes);
        return 0;
    }
    BYTE* lpImageBase = MemoryMapPE(lpFileBytes);
    free(lpFileBytes);
    BuildImports(lpImageBase);
    HandleRelocations(lpImageBase);
    FixSectionPermissions(lpImageBase);
    UINT_PTR lpEntryPoint = CalculateEntrypoint(lpImageBase);
    printf("Running PE:%p->%p\n",(void *) lpImageBase, (void *) lpEntryPoint );
    //MessageBoxA(NULL, "DEBUG", "", MB_OK);
    ((EntryPoint*) lpEntryPoint)();
    return 0;

}