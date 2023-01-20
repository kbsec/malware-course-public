#include <windows.h>

typedef int(__stdcall *msgbox)(HWND, LPCSTR, LPCSTR, UINT);

int main(){
    HMODULE hModule = ::LoadLibraryA("User32.dll");
    msgbox f = NULL;
    if (hModule != NULL){
        f = reinterpret_cast<msgbox>(::GetProcAddress(hModule, "MessageBoxA"));
        if( f != NULL){
            (*f)(NULL, "Hello there from User32.dll", "I was dynamically loaded!", MB_OK);
        }
    ::FreeLibrary(hModule);
    }
}