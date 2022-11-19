#include <windows.h>
#include <stdio.h>


typedef int (__stdcall *fSurprise)();

int main(){
    auto handle = LoadLibraryA("surprise.dll");
    if (!handle){
        printf("Failed!\n");
    return 0;
    }
    fSurprise f = (fSurprise) GetProcAddress(handle, "Surprise");
    f();
    Sleep(100000);
    printf("Done!");
    
}