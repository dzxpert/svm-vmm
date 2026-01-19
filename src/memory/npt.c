#include "npt.h"
#include "svm.h"
#include <ntifs.h>

#ifndef PAGE_ALIGN
#define PAGE_ALIGN(x) ((x) & ~0xFFFULL)
#endif

// PA->VA lookup table since MmGetVirtualForPhysical doesn't work with pool memory
#define MAX_NPT_TABLES 2048  // Increased for 16+ core support (~35 tables per core)
static struct {
    UINT64 pa;
    PVOID va;
} g_NptTableMap[MAX_NPT_TABLES];
static ULONG g_NptTableCount = 0;
static KSPIN_LOCK g_NptTableLock;
static BOOLEAN g_NptTableLockInitialized = FALSE;

static VOID NptInitTableLock(VOID)
{
    if (!g_NptTableLockInitialized)
    {
        KeInitializeSpinLock(&g_NptTableLock);
        g_NptTableLockInitialized = TRUE;
    }
}

//
// Call this ONCE from DriverEntry before any SmpInitialize
//
VOID NptGlobalInit(VOID)
{
    if (!g_NptTableLockInitialized)
    {
        KeInitializeSpinLock(&g_NptTableLock);
        g_NptTableLockInitialized = TRUE;
        g_NptTableCount = 0;
        RtlZeroMemory(g_NptTableMap, sizeof(g_NptTableMap));
        DbgPrint("SVM-HV: NPT global state initialized\n");
    }
}


static VOID NptRegisterTable(UINT64 pa, PVOID va)
{
    KIRQL oldIrql;
    
    NptInitTableLock();
    KeAcquireSpinLock(&g_NptTableLock, &oldIrql);
    
    if (g_NptTableCount < MAX_NPT_TABLES)
    {
        g_NptTableMap[g_NptTableCount].pa = pa;
        g_NptTableMap[g_NptTableCount].va = va;
        g_NptTableCount++;
    }
    else
    {
        DbgPrint("SVM-HV: WARNING - NPT table map full!\n");
    }
    
    KeReleaseSpinLock(&g_NptTableLock, oldIrql);
}

PVOID NptLookupTable(UINT64 pa)
{
    KIRQL oldIrql;
    PVOID result = NULL;
    
    NptInitTableLock();
    KeAcquireSpinLock(&g_NptTableLock, &oldIrql);
    
    for (ULONG i = 0; i < g_NptTableCount; i++)
    {
        if (g_NptTableMap[i].pa == pa)
        {
            result = g_NptTableMap[i].va;
            break;
        }
    }
    
    KeReleaseSpinLock(&g_NptTableLock, oldIrql);
    return result;
}

static NPT_ENTRY* NptAllocTable(PHYSICAL_ADDRESS* outPa)
{
    PHYSICAL_ADDRESS low = { 0 };
    PHYSICAL_ADDRESS high = { .QuadPart = ~0ULL };
    PHYSICAL_ADDRESS skip = { 0 };

    NPT_ENTRY* tbl = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low, high, skip, MmCached);
    
    if (!tbl)
    {
        tbl = (NPT_ENTRY*)ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, 'NPTB');
        if (!tbl)
        {
            DbgPrint("SVM-HV: CRITICAL - NPT table allocation failed!\n");
            return NULL;
        }
    }

    RtlZeroMemory(tbl, PAGE_SIZE);
    *outPa = MmGetPhysicalAddress(tbl);
    
    // Fix #4: Validate physical address
    if (outPa->QuadPart == 0 || outPa->QuadPart == ~0ULL)
    {
        DbgPrint("SVM-HV: CRITICAL - Invalid physical address 0x%llX for NPT table!\n", 
                 outPa->QuadPart);
        
        // Try to free the memory
        __try {
            MmFreeContiguousMemory(tbl);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            ExFreePoolWithTag(tbl, 'NPTB');
        }
        
        return NULL;
    }
    
    NptRegisterTable(outPa->QuadPart, tbl);
    
    // DbgPrint("SVM-HV: NPT table allocated - VA=%p PA=0x%llX\n", tbl, outPa->QuadPart);  // Commented to reduce noise
    return tbl;
}

static NPT_ENTRY* NptResolveTableFromEntry(NPT_ENTRY* entry)
{
    if (!entry || !entry->Present)
        return NULL;
        
    UINT64 pa = (UINT64)entry->PageFrame << 12;
    if (pa == 0)
        return NULL;
        
    PVOID va = NptLookupTable(pa);
    if (!va)
    {
        DbgPrint("SVM-HV: NptResolveTableFromEntry - lookup failed for PA 0x%llX\n", pa);
    }
    return (NPT_ENTRY*)va;
}

static NPT_ENTRY* NptEnsureSubtable(NPT_ENTRY* parent, UINT64 index)
{
    // Validate parent pointer before access
    if (!parent)
    {
        DbgPrint("SVM-HV: NptEnsureSubtable - NULL parent!\n");
        return NULL;
    }
    
    // Check if address is valid before dereferencing
    if (!MmIsAddressValid(parent))
    {
        DbgPrint("SVM-HV: NptEnsureSubtable - invalid parent address %p\n", parent);
        return NULL;
    }
    
    if (!parent[index].Present)
    {
        PHYSICAL_ADDRESS pa;
        NPT_ENTRY* tbl = NptAllocTable(&pa);
        if (!tbl)
            return NULL;

        parent[index].Present = 1;
        parent[index].Write = 1;
        parent[index].User = 1;  // Required for NPT - allows supervisor mode access
        parent[index].PageFrame = pa.QuadPart >> 12;
    }

    return NptResolveTableFromEntry(&parent[index]);
}


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

    NPT_ENTRY* pdpt = (NPT_ENTRY*)NptLookupTable(pml4[pml4_i].PageFrame << 12);
    if (!pdpt)
        return NULL;

    if (!pdpt[pdpt_i].Present)
        return NULL;

    if (pdpt[pdpt_i].LargePage)
    {
        *outLevel = 1;
        return &pdpt[pdpt_i];
    }

    NPT_ENTRY* pd = (NPT_ENTRY*)NptLookupTable(pdpt[pdpt_i].PageFrame << 12);
    if (!pd)
        return NULL;

    if (!pd[pd_i].Present)
        return NULL;

    if (pd[pd_i].LargePage)
    {
        *outLevel = 2;
        return &pd[pd_i];
    }

    NPT_ENTRY* pt = (NPT_ENTRY*)NptLookupTable(pd[pd_i].PageFrame << 12);
    if (!pt)
        return NULL;

    *outLevel = 3;
    return &pt[pt_i];
}

static BOOLEAN NptReadGuestQword(NPT_STATE* State, UINT64 gpa, UINT64* outValue)
{
    PHYSICAL_ADDRESS hpa = NptTranslateGpaToHpa(State, gpa);
    if (!hpa.QuadPart)
        return FALSE;

    PVOID mapped = MmMapIoSpace(hpa, sizeof(UINT64), MmNonCached);
    if (!mapped)
        return FALSE;

    *outValue = *(volatile UINT64*)mapped;
    MmUnmapIoSpace(mapped, sizeof(UINT64));
    return TRUE;
}

static VOID NptProtectPageForTrap(NPT_STATE* State, UINT64 gpa, NPT_ENTRY* entry,
    UINT64* originalFrame,
    BOOLEAN arm)
{
    if (!entry)
        return;

    if (arm)
    {
        *originalFrame = entry->PageFrame;
        entry->Present = 0; 
    }
    else
    {
        entry->PageFrame = *originalFrame;
        entry->Present = 1;
    }
}


PHYSICAL_ADDRESS NptTranslateGpaToHpa(NPT_STATE* State, UINT64 gpa)
{
    // NPT is identity mapped (GPA == HPA)
    // Hardware uses NPT tables during VMRUN, but for software translation
    // we can return GPA directly since it equals HPA
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = gpa;
    return pa;
}


PHYSICAL_ADDRESS NptTranslateGvaToHpa(NPT_STATE* State, UINT64 gva)
{
    PHYSICAL_ADDRESS pa = { 0 };

    if (!State->ShadowCr3)
        return pa;

    UINT64 cr3 = State->ShadowCr3 & ~0xFFFULL;
    UINT64 index = (gva >> 39) & 0x1FF;

    UINT64 pml4e;
    if (!NptReadGuestQword(State, cr3 + index * sizeof(UINT64), &pml4e) || !(pml4e & PAGE_PRESENT))
        return pa;

    UINT64 pdpt = pml4e & ~0xFFFULL;
    index = (gva >> 30) & 0x1FF;

    UINT64 pdpte;
    if (!NptReadGuestQword(State, pdpt + index * sizeof(UINT64), &pdpte) || !(pdpte & PAGE_PRESENT))
        return pa;

    if (pdpte & (1ULL << 7))
    {
        pa.QuadPart = (pdpte & ~0x3FFFFFFFULL) + (gva & 0x3FFFFFFFULL);
        pa = NptTranslateGpaToHpa(State, pa.QuadPart);
        return pa;
    }

    UINT64 pd = pdpte & ~0xFFFULL;
    index = (gva >> 21) & 0x1FF;

    UINT64 pde;
    if (!NptReadGuestQword(State, pd + index * sizeof(UINT64), &pde) || !(pde & PAGE_PRESENT))
        return pa;

    if (pde & (1ULL << 7))
    {
        pa.QuadPart = (pde & ~0x1FFFFFULL) + (gva & 0x1FFFFFULL);
        pa = NptTranslateGpaToHpa(State, pa.QuadPart);
        return pa;
    }

    UINT64 pt = pde & ~0xFFFULL;
    index = (gva >> 12) & 0x1FF;

    UINT64 pte;
    if (!NptReadGuestQword(State, pt + index * sizeof(UINT64), &pte) || !(pte & PAGE_PRESENT))
        return pa;

    pa.QuadPart = (pte & ~0xFFFULL) + (gva & 0xFFFULL);
    pa = NptTranslateGpaToHpa(State, pa.QuadPart);
    return pa;
}


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

VOID NptUpdateShadowCr3(NPT_STATE* State, UINT64 GuestCr3)
{
    State->ShadowCr3 = GuestCr3;
}

static BOOLEAN NptArmTrap(NPT_STATE* State, UINT64 gpa, NPT_ENTRY* entry,
    UINT64* originalFrame,
    BOOLEAN* armed)
{
    if (!entry)
        return FALSE;

    NptProtectPageForTrap(State, gpa, entry, originalFrame, TRUE);
    *armed = TRUE;
    return TRUE;
}

static BOOLEAN NptPromoteTrapToFake(NPT_STATE* State, NPT_ENTRY* entry)
{
    if (!entry)
        return FALSE;

    ULONG slot = State->FakePageIndex & 1;
    PHYSICAL_ADDRESS fakePa = State->FakePagePa[slot];
    if (!fakePa.QuadPart)
        return FALSE;

    entry->PageFrame = fakePa.QuadPart >> 12;
    entry->Present = 1;
    entry->Write = 1;
    entry->Accessed = 1;
    entry->Dirty = 1;

    State->FakePageIndex ^= 1; 
    return TRUE;
}

static BOOLEAN NptHandleSingleTrigger(NPT_STATE* State,
    UINT64 gpa,
    NPT_ENTRY* entry,
    UINT64* originalFrame,
    BOOLEAN* armed,
    BOOLEAN* usingFake,
    UINT64* mailboxValue)
{
    if (!*armed || !entry)
        return FALSE;

    if ((gpa & ~0xFFFULL) != (entry->PageFrame << 12) && entry->Present)
    {
       
        return FALSE;
    }

    if (!*usingFake)
    {
        *usingFake = NptPromoteTrapToFake(State, entry);
        *armed = FALSE;
        if (mailboxValue)
            *mailboxValue = gpa;
        return *usingFake;
    }

    return FALSE;
}

BOOLEAN NptSetupHardwareTriggers(NPT_STATE* State, UINT64 apicGpa, UINT64 acpiGpa, UINT64 smmGpa, UINT64 mmioGpa)
{
    UINT64 level;

    NPT_ENTRY* apic = NptGetEntry(State, apicGpa, &level);
    NPT_ENTRY* acpi = NptGetEntry(State, acpiGpa, &level);
    NPT_ENTRY* smm = NptGetEntry(State, smmGpa, &level);
    NPT_ENTRY* mmio = NptGetEntry(State, mmioGpa, &level);

    BOOLEAN ok = TRUE;
    ok &= NptArmTrap(State, apicGpa, apic, &State->Apic.OriginalPageFrame, &State->Apic.Armed);
    ok &= NptArmTrap(State, acpiGpa, acpi, &State->Acpi.OriginalPageFrame, &State->Acpi.Armed);
    ok &= NptArmTrap(State, smmGpa, smm, &State->Smm.OriginalPageFrame, &State->Smm.Armed);
    ok &= NptArmTrap(State, mmioGpa, mmio, &State->Mmio.OriginalPageFrame, &State->Mmio.Armed);

    State->Apic.GpaPage = apicGpa & ~0xFFFULL;
    State->Acpi.GpaPage = acpiGpa & ~0xFFFULL;
    State->Smm.GpaPage = smmGpa & ~0xFFFULL;
    State->Mmio.GpaPage = mmioGpa & ~0xFFFULL;

    State->Apic.UsingFakePage = FALSE;
    State->Acpi.UsingFakePage = FALSE;
    State->Smm.UsingFakePage = FALSE;
    State->Mmio.UsingFakePage = FALSE;

    State->Mailbox.GpaPage = apicGpa & ~0xFFFULL;
    State->Mailbox.Active = TRUE;
    State->Mailbox.LastMessage = 0;

    return ok;
}

BOOLEAN NptHandleHardwareTriggers(NPT_STATE* State, UINT64 faultGpa, UINT64* mailboxValue)
{
    UINT64 level;

    NPT_ENTRY* apic = NptGetEntry(State, State->Apic.GpaPage, &level);
    NPT_ENTRY* acpi = NptGetEntry(State, State->Acpi.GpaPage, &level);
    NPT_ENTRY* smm = NptGetEntry(State, State->Smm.GpaPage, &level);
    NPT_ENTRY* mmio = NptGetEntry(State, State->Mmio.GpaPage, &level);

    if (NptHandleSingleTrigger(State, faultGpa, apic, &State->Apic.OriginalPageFrame, &State->Apic.Armed, &State->Apic.UsingFakePage, mailboxValue))
        return TRUE;
    if (NptHandleSingleTrigger(State, faultGpa, acpi, &State->Acpi.OriginalPageFrame, &State->Acpi.Armed, &State->Acpi.UsingFakePage, mailboxValue))
        return TRUE;
    if (NptHandleSingleTrigger(State, faultGpa, smm, &State->Smm.OriginalPageFrame, &State->Smm.Armed, &State->Smm.UsingFakePage, mailboxValue))
        return TRUE;
    if (NptHandleSingleTrigger(State, faultGpa, mmio, &State->Mmio.OriginalPageFrame, &State->Mmio.Armed, &State->Mmio.UsingFakePage, mailboxValue))
        return TRUE;

    return FALSE;
}

VOID NptRearmHardwareTriggers(NPT_STATE* State)
{
    UINT64 level;
    NPT_ENTRY* apic = NptGetEntry(State, State->Apic.GpaPage, &level);
    NPT_ENTRY* acpi = NptGetEntry(State, State->Acpi.GpaPage, &level);
    NPT_ENTRY* smm = NptGetEntry(State, State->Smm.GpaPage, &level);
    NPT_ENTRY* mmio = NptGetEntry(State, State->Mmio.GpaPage, &level);

    if (State->Apic.UsingFakePage)
    {
        if (apic)
        {
            apic->PageFrame = State->Apic.OriginalPageFrame;
            apic->Present = 0;
        }
        State->Apic.UsingFakePage = FALSE;
        State->Apic.Armed = TRUE;
    }

    if (State->Acpi.UsingFakePage)
    {
        if (acpi)
        {
            acpi->PageFrame = State->Acpi.OriginalPageFrame;
            acpi->Present = 0;
        }
        State->Acpi.UsingFakePage = FALSE;
        State->Acpi.Armed = TRUE;
    }

    if (State->Smm.UsingFakePage)
    {
        if (smm)
        {
            smm->PageFrame = State->Smm.OriginalPageFrame;
            smm->Present = 0;
        }
        State->Smm.UsingFakePage = FALSE;
        State->Smm.Armed = TRUE;
    }

    if (State->Mmio.UsingFakePage)
    {
        if (mmio)
        {
            mmio->PageFrame = State->Mmio.OriginalPageFrame;
            mmio->Present = 0;
        }
        State->Mmio.UsingFakePage = FALSE;
        State->Mmio.Armed = TRUE;
    }
}

BOOLEAN NptInstallShadowHook(NPT_STATE* State, UINT64 TargetGpa, UINT64 NewHpa)
{
    if (!State)
        return FALSE;

    State->ShadowHook.TargetGpaPage = TargetGpa & ~0xFFFULL;
    State->ShadowHook.NewHpaPage = NewHpa & ~0xFFFULL;
    State->ShadowHook.Active = TRUE;
    
    // Mark that TLB needs flushing on next VMRUN
    // The VMCB TlbControl field will be set by the caller or VMEXIT handler
    // NOTE: For proper multi-core support, an IPI should be sent to all cores
    // to flush their TLBs. For now, we rely on the ASID/TLB control mechanism.
    State->TlbFlushPending = TRUE;
    
    return TRUE;
}

VOID NptClearShadowHook(NPT_STATE* State)
{
    if (!State)
        return;

    State->ShadowHook.Active = FALSE;
    State->ShadowHook.TargetGpaPage = 0;
    State->ShadowHook.NewHpaPage = 0;
    
    // Mark TLB flush needed to restore original mappings
    State->TlbFlushPending = TRUE;
}

static UINT64 NptGetMaxPhysicalAddress()
{
    UINT64 maxPa = 0;

    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges)
        return 0;

    for (PPHYSICAL_MEMORY_RANGE r = ranges; r->BaseAddress.QuadPart || r->NumberOfBytes.QuadPart; r++)
    {
        UINT64 end = r->BaseAddress.QuadPart + r->NumberOfBytes.QuadPart;
        if (end > maxPa)
            maxPa = end;
    }

    ExFreePool(ranges);
    return maxPa;
}


NTSTATUS NptInitialize(NPT_STATE* State)
{
    if (!State) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(State, sizeof(*State));

    // Initialize spinlock for table map
    NptInitTableLock();

    // Allocate fake pages (for hardware trigger traps)
    for (ULONG i = 0; i < 2; i++)
    {
        State->FakePageVa[i] =
            MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE,
                (PHYSICAL_ADDRESS) { 0 },
                (PHYSICAL_ADDRESS) { .QuadPart = ~0ULL },
                (PHYSICAL_ADDRESS) { 0 }, MmCached);

        if (!State->FakePageVa[i])
        {
            DbgPrint("SVM-HV: NPT fake page alloc failed (slot=%lu)\n", i);
            return HV_STATUS_NPT_FAKEPAGE;
        }

        RtlZeroMemory(State->FakePageVa[i], PAGE_SIZE);
        State->FakePagePa[i] = MmGetPhysicalAddress(State->FakePageVa[i]);
    }

    // ==========================================================================
    // SIMPLE 1GB PAGE IDENTITY MAPPING (like reference project)
    // This covers the ENTIRE 512GB address space using 1GB huge pages
    // No need for complex per-range mapping - just identity map everything
    // ==========================================================================
    
    DbgPrint("SVM-HV: Using 1GB huge page NPT for full identity mapping\n");
    
    // Allocate PML4 (512 entries)
    PHYSICAL_ADDRESS low = { 0 };
    PHYSICAL_ADDRESS high = { .QuadPart = ~0ULL };
    PHYSICAL_ADDRESS skip = { 0 };
    
    NPT_ENTRY* pml4 = MmAllocateContiguousMemorySpecifyCache(
        sizeof(NPT_ENTRY) * 512, low, high, skip, MmCached);
    if (!pml4)
    {
        DbgPrint("SVM-HV: Failed to allocate PML4\n");
        return HV_STATUS_NPT_PML4;
    }
    RtlZeroMemory(pml4, sizeof(NPT_ENTRY) * 512);
    
    State->Pml4 = pml4;
    State->Pml4Pa = MmGetPhysicalAddress(pml4);
    NptRegisterTable(State->Pml4Pa.QuadPart, pml4);
    
    // Allocate PDPT entries array (512 PML4 entries x 512 PDPT entries = 262144 entries)
    // Each PDPT entry with LargePage=1 covers 1GB
    // Total coverage = 512 * 512 * 1GB = 256TB (full x64 address space)
    SIZE_T pdptSize = sizeof(NPT_ENTRY) * 512 * 512;
    NPT_ENTRY* allPdpt = MmAllocateContiguousMemorySpecifyCache(
        pdptSize, low, high, skip, MmCached);
    if (!allPdpt)
    {
        DbgPrint("SVM-HV: Failed to allocate PDPT array (%llu bytes)\n", (UINT64)pdptSize);
        MmFreeContiguousMemory(pml4);
        return HV_STATUS_NPT_PDPT;
    }
    RtlZeroMemory(allPdpt, pdptSize);
    
    State->PdptEntries = allPdpt;
    State->PdptEntriesPa = MmGetPhysicalAddress(allPdpt);
    
    DbgPrint("SVM-HV: Allocated PML4 at %p (PA=0x%llX)\n", pml4, State->Pml4Pa.QuadPart);
    DbgPrint("SVM-HV: Allocated PDPT array at %p (PA=0x%llX, size=0x%llX)\n", 
             allPdpt, State->PdptEntriesPa.QuadPart, (UINT64)pdptSize);
    
    // Setup all 512 PML4 entries, each pointing to a block of 512 PDPT entries
    for (ULONG64 pml4Index = 0; pml4Index < 512; pml4Index++)
    {
        // Each PML4 entry points to a contiguous set of 512 PDPT entries
        NPT_ENTRY* thisPdpt = &allPdpt[pml4Index * 512];
        PHYSICAL_ADDRESS pdptPa = MmGetPhysicalAddress(thisPdpt);
        
        pml4[pml4Index].Present = 1;
        pml4[pml4Index].Write = 1;
        pml4[pml4Index].User = 1;  // Supervisor bit for NPT
        pml4[pml4Index].PageFrame = pdptPa.QuadPart >> 12;
        
        // NOTE: We intentionally do NOT call NptRegisterTable for each PDPT block
        // since we have a contiguous allocation. The table map has limited size
        // and would overflow with 512 entries per CPU * N CPUs.
        
        
        // Setup all 512 PDPT entries as 1GB huge pages (identity mapped)
        for (ULONG64 pdpIndex = 0; pdpIndex < 512; pdpIndex++)
        {
            // Physical address this 1GB page maps to:
            // Page index = pml4Index * 512 + pdpIndex
            // Physical address = pageIndex * 1GB = pageIndex * 0x40000000
            // PageFrame field = physAddr >> 12 = pageIndex << 18
            UINT64 pageIndex = pml4Index * 512ULL + pdpIndex;
            
            thisPdpt[pdpIndex].Present = 1;
            thisPdpt[pdpIndex].Write = 1;
            thisPdpt[pdpIndex].User = 1;       // Supervisor for NPT
            thisPdpt[pdpIndex].LargePage = 1;  // 1GB huge page!
            thisPdpt[pdpIndex].PageFrame = pageIndex << 18;  // Correct: physAddr >> 12
        }
    }
    
    DbgPrint("SVM-HV: Identity mapped 256TB using 1GB pages (512 PML4 x 512 PDPT)\n");
    DbgPrint("SVM-HV: NPT initialization complete\n");
    
    return STATUS_SUCCESS;
}




VOID NptDestroy(NPT_STATE* State)
{
    if (!State)
        return;

    // Free fake pages
    for (ULONG i = 0; i < 2; i++)
    {
        if (State->FakePageVa[i])
            MmFreeContiguousMemory(State->FakePageVa[i]);
    }

    // Free contiguous PDPT allocation (allocated as single block in NptInitialize)
    // This is the FIX for ~1MB memory leak per VCPU
    if (State->PdptEntries)
    {
        MmFreeContiguousMemory(State->PdptEntries);
        State->PdptEntries = NULL;
    }

    // Free PML4
    if (State->Pml4)
    {
        MmFreeContiguousMemory(State->Pml4);
        State->Pml4 = NULL;
    }
}

