#include <windows.h>
#include <stdio.h>


BYTE* MemoryMapPE(BYTE* peFileBytes);
BOOL BuildImports(BYTE* lpImageBase);
BOOL HandleRelocations(BYTE* lpImageBase);
BOOL FixSectionPermissions(BYTE* lpImageBase);
void HandleTLS(BYTE* lpImageBase);
UINT_PTR CalculateEntrypoint(BYTE* lpImageBase);