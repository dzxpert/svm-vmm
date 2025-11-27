#include "guest_mem.h"
#include "npt.h"
#include "vcpu.h"
#include "vmcb.h"

static BOOLEAN ReadGuestPhysical(VCPU* V, UINT64 GuestPhysical, PVOID Buffer, SIZE_T Size)
{
    PHYSICAL_ADDRESS hpa = GuestTranslateGpaToHpa(Vcpu, GuestPhysical);
    if (hpa.QuadPart == 0) return FALSE;

    PVOID mapped = MmMapIoSpace(hpa, Size, MmNonCached);
    if (!mapped) return FALSE;

    RtlCopyMemory(Buffer, mapped, Size);
    MmUnmapIoSpace(mapped, Size);
    return TRUE;
}

static UINT64 ReadGuestQword(VCPU* V, UINT64 gpa)
{
    UINT64 val = 0;
    ReadGuestPhysical(V, gpa, &val, sizeof(val));
    return val;
}

PHYSICAL_ADDRESS GuestTranslateGvaToGpa(VCPU* V, UINT64 Gva)
{
    UINT64 cr3 = VmcbState(V->Vmcb)->Cr3;

    UINT64 pml4 = cr3 & ~0xFFFULL;
    UINT64 index = (Gva >> 39) & 0x1FF;

    UINT64 pml4e = ReadGuestQword(V, pml4 + index * 8);
    if (!(pml4e & 1)) return { 0 };

    UINT64 pdpt = (pml4e & ~0xFFFULL);
    index = (Gva >> 30) & 0x1FF;

    UINT64 pdpte = ReadGuestQword(V, pdpt + index * 8);
    if (!(pdpte & 1)) return { 0 };

    if (pdpte & (1ULL << 7))
    {
        PHYSICAL_ADDRESS pa;
        pa.QuadPart = (pdpte & ~0x3FFFFFFFULL) + (Gva & 0x3FFFFFFFULL);
        return pa;
    }

    UINT64 pd = (pdpte & ~0xFFFULL);
    index = (Gva >> 21) & 0x1FF;

    UINT64 pde = ReadGuestQword(V, pd + index * 8);
    if (!(pde & 1)) return { 0 };

    if (pde & (1ULL << 7))
    {
        PHYSICAL_ADDRESS pa;
        pa.QuadPart = (pde & ~0x1FFFFFULL) + (Gva & 0x1FFFFFULL);
        return pa;
    }

    UINT64 pt = (pde & ~0xFFFULL);
    index = (Gva >> 12) & 0x1FF;

    UINT64 pte = ReadGuestQword(V, pt + index * 8);
    if (!(pte & 1)) return { 0 };

    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (pte & ~0xFFFULL) + (Gva & 0xFFFULL);
    return pa;
}

PHYSICAL_ADDRESS GuestTranslateGpaToHpa(VCPU* V, UINT64 Gpa)
{
    return NptTranslateGpaToHpa(&V->Npt, Gpa);
}

BOOLEAN GuestReadGva(VCPU* V, UINT64 Gva, PVOID Buffer, SIZE_T Size)
{
    PHYSICAL_ADDRESS gpa = GuestTranslateGvaToGpa(V, Gva);
    if (!gpa.QuadPart) return FALSE;

    return ReadGuestPhysical(V, gpa.QuadPart, Buffer, Size);
}

BOOLEAN GuestWriteGva(VCPU* V, UINT64 Gva, PVOID Buffer, SIZE_T Size)
{
    PHYSICAL_ADDRESS hpa = GuestTranslateGvaToHpa(V, Gva);
    if (!hpa.QuadPart) return FALSE;

    PVOID mapped = MmMapIoSpace(hpa, Size, MmNonCached);
    if (!mapped) return FALSE;

    RtlCopyMemory(mapped, Buffer, Size);
    MmUnmapIoSpace(mapped, Size);
    return TRUE;
}
