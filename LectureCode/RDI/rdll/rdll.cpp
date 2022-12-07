#include <windows.h>
#include "peloader.h"




BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{

    // Fun fact, doing anything crazy in here will BREAK EVERYTHING YOU KNOW AND LOVE

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        ::MessageBoxA(NULL,"Look Ma!", "No Disk!", MB_OK );
        ::OutputDebugStringW(L"DLL_PROCESS_ATTACH");
        break;

    case DLL_THREAD_ATTACH:
        ::OutputDebugStringW(L"DLL_THREAD_ATTACH");
        break;

    case DLL_THREAD_DETACH:
        ::OutputDebugStringW(L"DLL_THREAD_DETACH");
        break;

    case DLL_PROCESS_DETACH:
        ::OutputDebugStringW(L"DLL_PROCESS_DETACH");
        break;
    }

    return TRUE;
}