#include <windows.h>
#include <stdio.h>

// Function Pointer for...

// LoadLibraryA
typedef HMODULE (WINAPI* _LoadLibraryA)(
  LPCSTR lpLibFileName
);
typedef BOOL (WINAPI* DLLMAIN)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);


// FreeLibrary
typedef BOOL (WINAPI* _FreeLibrary)(
  HMODULE hLibModule
);

// GetProcAddr
typedef FARPROC (WINAPI*_GetProcAddress)(
  HMODULE hModule,
  LPCSTR  lpProcName
);

// VirtualProtect
typedef BOOL  (WINAPI* _VirtualProtect )(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flNewProtect,
  PDWORD lpflOldProtect
);

// VirtualAlloc
typedef LPVOID (WINAPI*_VirtualAlloc)( 
    LPVOID lpAddress,
    SIZE_T dwSize, 
    DWORD flAllocationType, 
    DWORD flProtect
);

typedef int (WINAPI* _MessageBoxA) (
  HWND   hWnd,
  LPCSTR lpText,
  LPCSTR lpCaption,
  UINT   uType
);

void* ReflectiveLoader(UINT_PTR loadLibraryA, UINT_PTR getProcAddress );