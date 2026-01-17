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
    
    DbgPrint("SVM-HV: NPT table allocated - VA=%p PA=0x%llX\n", tbl, outPa->QuadPart);
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

    // Allocate PML4
    PHYSICAL_ADDRESS pml4Pa;
    NPT_ENTRY* pml4 = NptAllocTable(&pml4Pa);
    if (!pml4)
    {
        DbgPrint("SVM-HV: NPT PML4 alloc failed\n");
        return HV_STATUS_NPT_PML4;
    }

    State->Pml4 = pml4;
    State->Pml4Pa = pml4Pa;

    // ========== FIX #1: Map only valid RAM ranges from Windows ==========
    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges)
    {
        DbgPrint("SVM-HV: MmGetPhysicalMemoryRanges failed\n");
        return HV_STATUS_NPT_RANGES;
    }

    DbgPrint("SVM-HV: Physical Memory Ranges:\n");

    // Map ONLY valid RAM ranges
    for (PPHYSICAL_MEMORY_RANGE r = ranges; 
         r->BaseAddress.QuadPart || r->NumberOfBytes.QuadPart; 
         r++)
    {
        UINT64 rangeStart = r->BaseAddress.QuadPart;
        UINT64 rangeEnd = rangeStart + r->NumberOfBytes.QuadPart;
        
        DbgPrint("  Range: 0x%016llX - 0x%016llX (%llu MB)\n", 
                 rangeStart, rangeEnd, 
                 r->NumberOfBytes.QuadPart / (1024*1024));

        // Align to 2MB boundaries (NPT uses 2MB large pages)
        // Round DOWN start to include any 2MB page containing RAM
        // Round UP end to include all RAM
        UINT64 pageStart = rangeStart & ~0x1FFFFFULL;  // Round down
        UINT64 pageEnd = (rangeEnd + 0x1FFFFFULL) & ~0x1FFFFFULL;  // Round up
        
        DbgPrint("  Mapping 2MB pages: 0x%llX - 0x%llX\n", pageStart, pageEnd);
        
        // Map each 2MB page in this range
        for (UINT64 phys = pageStart; phys < pageEnd; phys += 0x200000ULL)
        {
            UINT64 pml4_i = (phys >> 39) & 0x1FF;
            UINT64 pdpt_i = (phys >> 30) & 0x1FF;
            UINT64 pd_i = (phys >> 21) & 0x1FF;

            NPT_ENTRY* pdpt = NptEnsureSubtable(pml4, pml4_i);
            if (!pdpt)
            {
                DbgPrint("SVM-HV: NPT PDPT alloc failed (pml4=%llu)\n", pml4_i);
                ExFreePool(ranges);
                return HV_STATUS_NPT_PDPT;
            }

            NPT_ENTRY* pd = NptEnsureSubtable(pdpt, pdpt_i);
            if (!pd)
            {
                DbgPrint("SVM-HV: NPT PD alloc failed (pml4=%llu pdpt=%llu)\n", 
                         pml4_i, pdpt_i);
                ExFreePool(ranges);
                return HV_STATUS_NPT_PD;
            }

            NPT_ENTRY* pde = &pd[pd_i];
            if (!pde->Present)
            {
                pde->Present = 1;
                pde->Write = 1;
                pde->User = 1;      // Required for NPT
                pde->LargePage = 1; // 2MB page
                pde->PageFrame = phys >> 12;
            }
        }
    }

    ExFreePool(ranges);

    // ========== Map critical MMIO regions ==========
    DbgPrint("SVM-HV: Mapping MMIO regions...\n");
    
    // Map first 2MB for legacy regions (real mode IVT, BDA, etc.)
    // This is needed for some BIOS/UEFI interactions
    {
        UINT64 phys = 0;
        UINT64 pml4_i = (phys >> 39) & 0x1FF;
        UINT64 pdpt_i = (phys >> 30) & 0x1FF;
        UINT64 pd_i = (phys >> 21) & 0x1FF;

        NPT_ENTRY* pdpt = NptEnsureSubtable(pml4, pml4_i);
        if (pdpt)
        {
            NPT_ENTRY* pd = NptEnsureSubtable(pdpt, pdpt_i);
            if (pd)
            {
                NPT_ENTRY* pde = &pd[pd_i];
                if (!pde->Present)
                {
                    pde->Present = 1;
                    pde->Write = 1;
                    pde->User = 1;
                    pde->LargePage = 1;
                    pde->PageFrame = phys >> 12;
                    DbgPrint("SVM-HV: Mapped legacy region 0x%llX\n", phys);
                }
            }
        }
    }
    
    // Map APIC region (0xFEE00000) - typically 4KB but we use 2MB page containing it
    {
        UINT64 apicBase = 0xFEC00000ULL;  // 2MB-aligned base containing APIC
        UINT64 pml4_i = (apicBase >> 39) & 0x1FF;
        UINT64 pdpt_i = (apicBase >> 30) & 0x1FF;
        UINT64 pd_i = (apicBase >> 21) & 0x1FF;

        NPT_ENTRY* pdpt = NptEnsureSubtable(pml4, pml4_i);
        if (pdpt)
        {
            NPT_ENTRY* pd = NptEnsureSubtable(pdpt, pdpt_i);
            if (pd)
            {
                NPT_ENTRY* pde = &pd[pd_i];
                if (!pde->Present)
                {
                    pde->Present = 1;
                    pde->Write = 1;
                    pde->User = 1;
                    pde->LargePage = 1;
                    pde->CacheDisable = 1;  // Critical for MMIO!
                    pde->PageFrame = apicBase >> 12;
                    DbgPrint("SVM-HV: Mapped APIC region 0x%llX\n", apicBase);
                }
            }
        }
    }
    
    // Map PCI MMIO range (0xE0000000 - 0xF0000000) as 2MB pages
    for (UINT64 addr = 0xE0000000ULL; addr < 0xF0000000ULL; addr += 0x200000ULL)
    {
        UINT64 pml4_i = (addr >> 39) & 0x1FF;
        UINT64 pdpt_i = (addr >> 30) & 0x1FF;
        UINT64 pd_i = (addr >> 21) & 0x1FF;

        NPT_ENTRY* pdpt = NptEnsureSubtable(pml4, pml4_i);
        if (!pdpt) continue;

        NPT_ENTRY* pd = NptEnsureSubtable(pdpt, pdpt_i);
        if (!pd) continue;

        NPT_ENTRY* pde = &pd[pd_i];
        if (!pde->Present)
        {
            pde->Present = 1;
            pde->Write = 1;
            pde->User = 1;
            pde->LargePage = 1;
            pde->CacheDisable = 1;  // Important for MMIO!
            pde->PageFrame = addr >> 12;
        }
    }
    DbgPrint("SVM-HV: Mapped PCI MMIO region 0xE0000000-0xF0000000\n");

    DbgPrint("SVM-HV: NPT initialization complete\n");
    return STATUS_SUCCESS;
}




VOID NptDestroy(NPT_STATE* State)
{
    if (!State)
        return;

    for (ULONG i = 0; i < 2; i++)
    {
        if (State->FakePageVa[i])
            MmFreeContiguousMemory(State->FakePageVa[i]);
    }

    if (State->Pml4)
    {
        for (UINT64 pml4_i = 0; pml4_i < 512; pml4_i++)
        {
            if (!State->Pml4[pml4_i].Present)
                continue;

            NPT_ENTRY* pdpt = NptResolveTableFromEntry(&State->Pml4[pml4_i]);
            if (!pdpt || !MmIsAddressValid(pdpt))
                continue;

            for (UINT64 pdpt_i = 0; pdpt_i < 512; pdpt_i++)
            {
                if (!pdpt[pdpt_i].Present || pdpt[pdpt_i].LargePage)
                    continue;

                NPT_ENTRY* pd = NptResolveTableFromEntry(&pdpt[pdpt_i]);
                if (pd && MmIsAddressValid(pd))
                    MmFreeContiguousMemory(pd);
            }

            MmFreeContiguousMemory(pdpt);
        }

        MmFreeContiguousMemory(State->Pml4);
    }
}

