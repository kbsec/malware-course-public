#include <windows.h>
#include <stdio.h>


void PrintFileSize(LPSTR filePath){
    HANDLE hFile = NULL;
    hFile = CreateFileA(
        filePath,
        GENERIC_READ ,
        0, // Don't share access
        NULL, // Default security
        OPEN_EXISTING, // overwrite
        FILE_ATTRIBUTE_NORMAL,
        NULL// NO template
        );
    if (hFile == INVALID_HANDLE_VALUE){
        printf("Failed to open %s: %d\n", filePath, GetLastError() );
        return;
    }
    LARGE_INTEGER lFileSize;
    BOOL bGetSize = GetFileSizeEx(hFile, &lFileSize);
    if(bGetSize == FALSE){
        printf("Failed to open %s: %d\n", filePath, GetLastError() );
    } else{
        printf("File Size for %s: %llu\n",filePath,  lFileSize.QuadPart);
    }
    if (hFile != NULL && hFile != INVALID_HANDLE_VALUE){
        CloseHandle(hFile);
    }
    return;
}

int main(int argc, char* argv[]){
    for(int i = 1; i < argc; i++){
        if(strcmp(argv[0], argv[i]) ==0){
            printf("Fun fact, %s just opened %s while it is running!\n", argv[0], argv[i]);
        }
        PrintFileSize(argv[i]);
    }
    return 0;
}