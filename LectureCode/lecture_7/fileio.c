#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]){
    char data[] = "I am a good Noodle!\n";
    DWORD dataLen = sizeof(data) - 1;
    DWORD dataWritten = 0;
    BOOL bErrorFlag = FALSE;

    HANDLE hFile = NULL;
    hFile = CreateFileA(
        "file.txt",
        GENERIC_READ | GENERIC_WRITE,
        0, // Don't share access
        NULL, // Default security
        CREATE_ALWAYS, // overwrite
        FILE_ATTRIBUTE_NORMAL,
        NULL// NO template
        );
    if (hFile == NULL || hFile == INVALID_HANDLE_VALUE){ 
        printf("Failed to Create File Object: %d\n", GetLastError());
        return 1 ;
    }
    bErrorFlag = WriteFile(hFile, data,dataLen,&dataWritten, NULL);
    if (bErrorFlag == FALSE){
        printf("Failed to write to File: %d\n", GetLastError());
        return 1;
    }   
    printf("Wrote %d bytes to the file\n", dataWritten);
    return 0;
}