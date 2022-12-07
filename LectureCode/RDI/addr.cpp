#include <windows.h>
#include <stdio.h>
#include <intrin.h>
#ifdef __MINGW32__
#define WIN_GET_CALLER() __builtin_extract_return_addr(__builtin_return_address(0))
#else
#pragma intrinsic(_ReturnAddress)
#define WIN_GET_CALLER() _ReturnAddress()
#endif

__declspec(noinline) ULONG_PTR caller( VOID ) { return (ULONG_PTR)WIN_GET_CALLER(); }

void f(){
    // Put the address of the Value in the Stack point
    //MOV RAX , qword ptr [RSP]
    // RET
    UINT_PTR x = caller();
    //printf("Ret Addr: %p\n", (void*) &x);
    while(true){
    PIMAGE_DOS_HEADER Y = (PIMAGE_DOS_HEADER) x;
    if( Y->e_magic == IMAGE_DOS_SIGNATURE){
        //
    }
    x--;
    }

}
int main(){
    MessageBoxA(NULL, "", "", MB_OK);
    f();

}