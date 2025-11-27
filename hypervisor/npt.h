#pragma once
#include <ntifs.h>

#pragma pack(push, 1)

typedef union _NPT_PTE
{
    struct
    {
        UINT64 Present : 1;
        UINT64 Write : 1;
        UINT64 User : 1;
        UINT64 WriteThrough : 1;
        UINT64 CacheDisable : 1;
        UINT64 Accessed : 1;
        UINT64 Dirty : 1;
        UINT64 LargePage : 1;
        UINT64 Global : 1;
        UINT64 Reserved1 : 3;
        UINT64 PageFrame : 40;
        UINT64 Reserved2 : 11;
        UINT64 Nx : 1;
    };

    UINT64 Value;
} NPT_PTE;

typedef NPT_PTE NPT_PDE;
typedef NPT_PTE NPT_PDPE;
typedef NPT_PTE NPT_PML4E;

#pragma pack(pop)

typedef struct _NPT_STATE
{
    PVOID Pml4;
    PHYSICAL_ADDRESS Pml4Pa;
} NPT_STATE;

NTSTATUS NptInitialize(NPT_STATE* State);
VOID NptDestroy(NPT_STATE* State);
