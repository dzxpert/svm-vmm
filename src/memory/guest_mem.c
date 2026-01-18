#include "guest_mem.h"
#include "npt.h"
#include "vcpu.h"
#include "vmcb.h"
#include "hooks.h"

static BOOLEAN ReadGuestPhysical(VCPU* V, UINT64 GuestPhysical, PVOID Buffer, SIZE_T Size)
{
    UNREFERENCED_PARAMETER(V);
    
    // Use MmCopyMemory for safe physical memory access at any address
    MM_COPY_ADDRESS srcAddr = {0};
    srcAddr.PhysicalAddress.QuadPart = GuestPhysical;
    
    SIZE_T bytesTransferred = 0;
    NTSTATUS status = MmCopyMemory(Buffer, srcAddr, Size, MM_COPY_MEMORY_PHYSICAL, &bytesTransferred);
    
    if (!NT_SUCCESS(status) || bytesTransferred != Size) {
        DbgPrint("SVM-HV: MmCopyMemory FAILED for PA=0x%llX Status=0x%X\n", GuestPhysical, status);
        return FALSE;
    }
    
    return TRUE;
}

static BOOLEAN WriteGuestPhysical(VCPU* V, UINT64 GuestPhysical, PVOID Buffer, SIZE_T Size)
{
    UNREFERENCED_PARAMETER(V);
    
    // For writes, we use MDL to map the physical page
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = GuestPhysical;
    
    // Try to map the physical address
    PVOID mapped = MmMapIoSpace(pa, Size, MmNonCached);
    if (mapped) {
        RtlCopyMemory(mapped, Buffer, Size);
        MmUnmapIoSpace(mapped, Size);
        return TRUE;
    }
    
    // Fallback: for high physical addresses, use MmAllocatePagesForMdlEx + MmMapLockedPagesSpecifyCache
    // This is more complex but works for any physical address
    DbgPrint("SVM-HV: WriteGuestPhysical MmMapIoSpace failed for PA=0x%llX\n", GuestPhysical);
    return FALSE;
}

static UINT64 ReadGuestQword(VCPU* V, UINT64 gpa)
{
    UINT64 val = 0;
    ReadGuestPhysical(V, gpa, &val, sizeof(val));
    return val;
}

PHYSICAL_ADDRESS GuestTranslateGvaToGpa(VCPU* V, UINT64 Gva)
{
    PHYSICAL_ADDRESS pa = { 0 };
    
    // Mask for extracting physical frame from page table entry
    // Bits 12-51 contain the physical frame, we need to mask off NX (bit 63) and reserved bits
    #define PTE_FRAME_MASK 0x000FFFFFFFFFF000ULL

    UINT64 cr3_enc = VmcbState(&V->GuestVmcb)->Cr3;
    // Use guest CR3 directly - HookDecryptCr3 handles CR3 XOR decryption if active
    UINT64 cr3 = HookDecryptCr3(V, cr3_enc);

    DbgPrint("SVM-HV: GVA->GPA: Gva=0x%llX, cr3_enc=0x%llX, cr3=0x%llX\n", Gva, cr3_enc, cr3);

    UINT64 pml4 = cr3 & PTE_FRAME_MASK;
    UINT64 index = (Gva >> 39) & 0x1FF;

    UINT64 pml4e = ReadGuestQword(V, pml4 + index * 8);
    DbgPrint("SVM-HV: PML4[%llu] @ 0x%llX = 0x%llX\n", index, pml4 + index * 8, pml4e);
    if (!(pml4e & 1)) {
        DbgPrint("SVM-HV: PML4E not present!\n");
        return pa;
    }

    UINT64 pdpt = (pml4e & PTE_FRAME_MASK);
    index = (Gva >> 30) & 0x1FF;

    UINT64 pdpte = ReadGuestQword(V, pdpt + index * 8);
    DbgPrint("SVM-HV: PDPT[%llu] @ 0x%llX = 0x%llX\n", index, pdpt + index * 8, pdpte);
    if (!(pdpte & 1)) {
        DbgPrint("SVM-HV: PDPTE not present!\n");
        return pa;
    }

    if (pdpte & (1ULL << 7))
    {
        // 1GB page
        pa.QuadPart = (pdpte & 0x000FFFFFC0000000ULL) + (Gva & 0x3FFFFFFFULL);
        DbgPrint("SVM-HV: 1GB page -> GPA=0x%llX\n", pa.QuadPart);
        return pa;
    }

    UINT64 pd = (pdpte & PTE_FRAME_MASK);
    index = (Gva >> 21) & 0x1FF;

    UINT64 pde = ReadGuestQword(V, pd + index * 8);
    DbgPrint("SVM-HV: PD[%llu] @ 0x%llX = 0x%llX\n", index, pd + index * 8, pde);
    if (!(pde & 1)) {
        DbgPrint("SVM-HV: PDE not present!\n");
        return pa;
    }

    if (pde & (1ULL << 7))
    {
        // 2MB page
        pa.QuadPart = (pde & 0x000FFFFFFFE00000ULL) + (Gva & 0x1FFFFFULL);
        DbgPrint("SVM-HV: 2MB page -> GPA=0x%llX\n", pa.QuadPart);
        return pa;
    }

    UINT64 pt = (pde & PTE_FRAME_MASK);
    index = (Gva >> 12) & 0x1FF;

    UINT64 pte = ReadGuestQword(V, pt + index * 8);
    DbgPrint("SVM-HV: PT[%llu] @ 0x%llX = 0x%llX\n", index, pt + index * 8, pte);
    if (!(pte & 1)) {
        DbgPrint("SVM-HV: PTE not present!\n");
        return pa;
    }

    pa.QuadPart = (pte & PTE_FRAME_MASK) + (Gva & 0xFFFULL);
    DbgPrint("SVM-HV: 4KB page -> GPA=0x%llX\n", pa.QuadPart);
    return pa;
    
    #undef PTE_FRAME_MASK
}

PHYSICAL_ADDRESS GuestTranslateGpaToHpa(VCPU* V, UINT64 Gpa)
{
    // Use NPT tables for GPA->HPA translation
    return NptTranslateGpaToHpa(&V->Npt, Gpa);
}

PHYSICAL_ADDRESS GuestTranslateGvaToHpa(VCPU* V, UINT64 Gva)
{
    PHYSICAL_ADDRESS gpa = GuestTranslateGvaToGpa(V, Gva);
    if (!gpa.QuadPart) return gpa;

    return GuestTranslateGpaToHpa(V, gpa.QuadPart);
}

BOOLEAN GuestReadGva(VCPU* V, UINT64 Gva, PVOID Buffer, SIZE_T Size)
{
    PHYSICAL_ADDRESS gpa = GuestTranslateGvaToGpa(V, Gva);
    if (!gpa.QuadPart) return FALSE;

    return ReadGuestPhysical(V, gpa.QuadPart, Buffer, Size);
}

BOOLEAN GuestWriteGva(VCPU* V, UINT64 Gva, PVOID Buffer, SIZE_T Size)
{
    PHYSICAL_ADDRESS gpa = GuestTranslateGvaToGpa(V, Gva);
    if (!gpa.QuadPart) return FALSE;

    return WriteGuestPhysical(V, gpa.QuadPart, Buffer, Size);
}

BOOLEAN GuestReadGpa(VCPU* V, UINT64 Gpa, PVOID Buffer, SIZE_T Size)
{
    return ReadGuestPhysical(V, Gpa, Buffer, Size);
}

BOOLEAN GuestWriteGpa(VCPU* V, UINT64 Gpa, PVOID Buffer, SIZE_T Size)
{
    return WriteGuestPhysical(V, Gpa, Buffer, Size);
}
