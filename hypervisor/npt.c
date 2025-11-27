#include "npt.h"
#include <ntifs.h>

#define PAGE_ALIGN(x) ((x) & ~0xFFFULL)

static NPT_ENTRY * NptAllocTable(PHYSICAL_ADDRESS * outPa)
{
    NPT_ENTRY* tbl = (NPT_ENTRY*)ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, 'TPTN');
    if (!tbl) return NULL;

    RtlZeroMemory(tbl, PAGE_SIZE);
    *outPa = MmGetPhysicalAddress(tbl);
    return tbl;
}

//
// Internal page walk for NPT
//
static NPT_ENTRY* NptGetEntry(
    NPT_STATE* State,
    UINT64 gpa,
    UINT64* outLevel)
{
    UINT64 gpaPage = gpa >> 12;

    UINT64 pml4_i = (gpa >> 39) & 0x1FF;
    UINT64 pdpt_i = (gpa >> 30) & 0x1FF;
    UINT64 pd_i = (gpa >> 21) & 0x1FF;
    UINT64 pt_i = (gpa >> 12) & 0x1FF;

    NPT_ENTRY* pml4 = State->Pml4;
    if (!pml4[pml4_i].Present)
        return NULL;

    NPT_ENTRY* pdpt = (NPT_ENTRY*)MmGetVirtualForPhysical(
        (PHYSICAL_ADDRESS) {
        pml4[pml4_i].PageFrame << 12
    });

    if (!pdpt[pdpt_i].Present)
        return NULL;

    if (pdpt[pdpt_i].LargePage)
    {
        *outLevel = 1;
        return &pdpt[pdpt_i];
    }

    NPT_ENTRY* pd = (NPT_ENTRY*)MmGetVirtualForPhysical(
        (PHYSICAL_ADDRESS) {
        pdpt[pdpt_i].PageFrame << 12
    });

    if (!pd[pd_i].Present)
        return NULL;

    if (pd[pd_i].LargePage)
    {
        *outLevel = 2;
        return &pd[pd_i];
    }

    NPT_ENTRY* pt = (NPT_ENTRY*)MmGetVirtualForPhysical(
        (PHYSICAL_ADDRESS) {
        pd[pd_i].PageFrame << 12
    });

    *outLevel = 3;
    return &pt[pt_i];
}

//
// GPA → HPA
//
PHYSICAL_ADDRESS NptTranslateGpaToHpa(NPT_STATE* State, UINT64 gpa)
{
    PHYSICAL_ADDRESS pa = { 0 };
    UINT64 level;

    NPT_ENTRY* entry = NptGetEntry(State, gpa, &level);
    if (!entry)
        return pa;

    UINT64 offset = gpa & 0xFFFULL;
    pa.QuadPart = (entry->PageFrame << 12) + offset;
    return pa;
}

//
// GVA → HPA through NPT (relies on guest CR3 page walk)
//
PHYSICAL_ADDRESS NptTranslateGvaToHpa(NPT_STATE* State, UINT64 gva)
{
    // Этот метод реализуется через guest_mem.c
    PHYSICAL_ADDRESS pa = { 0 };
    UNREFERENCED_PARAMETER(State);
    UNREFERENCED_PARAMETER(gva);
    return pa;
}

//
// Hook GPA → другой HPA (EPT-like hook)
//
BOOLEAN NptHookPage(NPT_STATE* State, UINT64 targetGpaPage, UINT64 newHpaPage)
{
    UINT64 level;

    NPT_ENTRY* entry = NptGetEntry(State, targetGpaPage, &level);
    if (!entry)
        return FALSE;

    entry->PageFrame = (newHpaPage >> 12);
    entry->Dirty = 1;
    entry->Accessed = 1;

    return TRUE;
}

//
// Initialize full NPT (identity map) for entire 48-bit GPA
//
NTSTATUS NptInitialize(NPT_STATE* State)
{
    if (!State) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(State, sizeof(*State));

    PHYSICAL_ADDRESS paPml4;
    NPT_ENTRY* pml4 = NptAllocTable(&paPml4);
    if (!pml4)
        return STATUS_INSUFFICIENT_RESOURCES;

    State->Pml4 = pml4;
    State->Pml4Pa = paPml4;

    //
    // Создаем PDPT, PD, PT как identity-map всего 512GB пространства
    //
    for (UINT64 i4 = 0; i4 < 512; i4++)
    {
        PHYSICAL_ADDRESS paPdpt;
        NPT_ENTRY* pdpt = NptAllocTable(&paPdpt);
        if (!pdpt) return STATUS_INSUFFICIENT_RESOURCES;

        pml4[i4].Present = 1;
        pml4[i4].Write = 1;
        pml4[i4].PageFrame = paPdpt.QuadPart >> 12;

        for (UINT64 i3 = 0; i3 < 512; i3++)
        {
            PHYSICAL_ADDRESS paPd;
            NPT_ENTRY* pd = NptAllocTable(&paPd);
            if (!pd) return STATUS_INSUFFICIENT_RESOURCES;

            pdpt[i3].Present = 1;
            pdpt[i3].Write = 1;
            pdpt[i3].PageFrame = paPd.QuadPart >> 12;

            for (UINT64 i2 = 0; i2 < 512; i2++)
            {
                PHYSICAL_ADDRESS paPt;
                NPT_ENTRY* pt = NptAllocTable(&paPt);
                if (!pt) return STATUS_INSUFFICIENT_RESOURCES;

                pd[i2].Present = 1;
                pd[i2].Write = 1;
                pd[i2].PageFrame = paPt.QuadPart >> 12;

                for (UINT64 i1 = 0; i1 < 512; i1++)
                {
                    UINT64 phys = ((i4 << 39) |
                        (i3 << 30) |
                        (i2 << 21) |
                        (i1 << 12));

                    pt[i1].Present = 1;
                    pt[i1].Write = 1;
                    pt[i1].User = 1;
                    pt[i1].PageFrame = phys >> 12;
                }
            }
        }
    }

    return STATUS_SUCCESS;
}

//
// Cleanup
//
VOID NptDestroy(NPT_STATE* State)
{
    // В данном минимальном варианте ничего не освобождаем,
    // но при необходимости можно рекурсивно free всех таблиц.
    UNREFERENCED_PARAMETER(State);
}

