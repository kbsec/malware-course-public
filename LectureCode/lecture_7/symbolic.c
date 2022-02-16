#include <windows.h>
#include <stdio.h>

void ExpandSymLink(char* link){

    CHAR buffer[MAX_PATH ];
    ZeroMemory(buffer, sizeof(buffer));
    if (QueryDosDeviceA(link, buffer, sizeof(buffer) ) == 0){
        if( GetLastError() == ERROR_INSUFFICIENT_BUFFER){
            printf("Not enough buffer space!\n");
            return;
        } else{
            printf("Error: %d\n", GetLastError());
        }
        return;
    }

            printf("<%s>:%s\n", link,  buffer);

}


int main(int argc, char* argv[]){
    for(int i = 1; i < argc; i++){
        ExpandSymLink(argv[i]);
    }
    return 0;
}