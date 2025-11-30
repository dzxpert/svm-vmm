#include <ntifs.h>
#include <intrin.h>
#include "svm.h"
#include "msr.h"
#include "vmcb.h"
#include "npt.h"
#include "layers.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

extern VOID VmrunAsm(UINT64 VmcbPa);
extern VOID GuestEntry();

#define MSRPM_SIZE      0x6000
#define IOPM_SIZE       0x2000
#define MSR_NESTED_CR3  0xC0010111
#define MSR_VM_HSAVE    0xC0010117





typedef struct _DESCRIPTOR_TABLE {
    USHORT Limit;
    ULONG64 Base;
} DESCRIPTOR_TABLE;





static NTSTATUS SvmCheckSupport()
{
    int info[4];

    __cpuid(info, 0x80000001);
    if (!(info[2] & (1 << 2)))
        return STATUS_NOT_SUPPORTED;

    __cpuid(info, 1);
    if (info[2] & (1 << 31))
        return STATUS_HV_FEATURE_UNAVAILABLE;

    if (MsrRead(MSR_VM_CR) & VM_CR_SVMDIS)
        return STATUS_NOT_SUPPORTED;

    return STATUS_SUCCESS;
}


//======================================================================
//                    ENABLE SVM
//======================================================================
static VOID SvmEnable()
{
    UINT64 efer = MsrRead(MSR_EFER);
    if (!(efer & EFER_SVME))
        MsrWrite(MSR_EFER, efer | EFER_SVME);
}


//======================================================================
//                CONTIGUOUS ALLOCATOR
//======================================================================
static PVOID AllocAligned(SIZE_T size, PHYSICAL_ADDRESS* pa)
{
    PHYSICAL_ADDRESS low = { 0 };
    PHYSICAL_ADDRESS high = { .QuadPart = ~0ULL };
    PHYSICAL_ADDRESS skip = { 0 };

    PVOID mem = MmAllocateContiguousMemorySpecifyCache(size, low, high, skip, MmCached);
    if (!mem) return NULL;

    RtlZeroMemory(mem, size);
    *pa = MmGetPhysicalAddress(mem);
    return mem;
}


//======================================================================
//                  ALLOC COMPONENTS
//======================================================================
static NTSTATUS AllocHostSave(VCPU* V)
{
    V->HostSave = AllocAligned(PAGE_SIZE, &V->HostSavePa);
    if (!V->HostSave) return STATUS_INSUFFICIENT_RESOURCES;

    MsrWrite(MSR_VM_HSAVE, V->HostSavePa.QuadPart);
    return STATUS_SUCCESS;
}

static NTSTATUS AllocVmcb(VCPU* V)
{
    V->Vmcb = AllocAligned(PAGE_SIZE, &V->VmcbPa);
    return V->Vmcb ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

static NTSTATUS AllocGuestStack(VCPU* V)
{
    V->GuestStackSize = PAGE_SIZE;
    V->GuestStack = ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, 'GSTK');
    if (!V->GuestStack) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(V->GuestStack, PAGE_SIZE);
    return STATUS_SUCCESS;
}

static NTSTATUS AllocMsrpm(VCPU* V)
{
    V->Msrpm = AllocAligned(MSRPM_SIZE, &V->MsrpmPa);
    if (!V->Msrpm) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(V->Msrpm, MSRPM_SIZE);
    return STATUS_SUCCESS;
}

static NTSTATUS AllocIopm(VCPU* V)
{
    V->Iopm = AllocAligned(IOPM_SIZE, &V->IopmPa);
    if (!V->Iopm) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(V->Iopm, IOPM_SIZE);
    return STATUS_SUCCESS;
}


//======================================================================
//                     SETUP GUEST STATE
//======================================================================
static VOID SetupGuest(VCPU* V)
{
    VMCB_STATE_SAVE_AREA* s = VmcbState(V->Vmcb);

    // RIP/RSP
    s->Rip = (UINT64)GuestEntry;
    s->Rsp = (UINT64)V->GuestStack + V->GuestStackSize - 0x20;
    s->Rflags = 0x2;

    //
    // VALID AMD LONG MODE SEGMENTS (ACCEPTED ON VM-ENTRY)
    //
    s->CsSelector = 0x10;
    s->CsAttributes = 0xA09B;
    s->CsLimit = 0xFFFFFFFF;
    s->CsBase = 0;

    s->SsSelector = 0x18;
    s->SsAttributes = 0xC093;
    s->SsLimit = 0xFFFFFFFF;
    s->SsBase = 0;

    s->DsSelector = 0x18;
    s->DsAttributes = 0xC093;
    s->DsLimit = 0xFFFFFFFF;
    s->DsBase = 0;

    s->EsSelector = 0x18;
    s->EsAttributes = 0xC093;
    s->EsLimit = 0xFFFFFFFF;
    s->EsBase = 0;


    // IDT / GDT CAN BE ZERO — AMD ALLOWS IT IN 64-BIT FLAT MODE
    s->GdtrBase = 0;
    s->GdtrLimit = 0;
    s->IdtrBase = 0;
    s->IdtrLimit = 0;

    //
    // CR registers
    //
    s->Cr0 = __readcr0() | 0x80000001ULL; // PE + PG
    s->Cr4 = __readcr4();
    s->Efer = MsrRead(MSR_EFER);
    s->Cr3 = __readcr3();

    //
    // NPT shadow CR3
    //
    NptUpdateShadowCr3(&V->Npt, s->Cr3);
}



//======================================================================
//                     SETUP CONTROLS
//======================================================================
static VOID SetupControls(VCPU* V)
{
    VMCB_CONTROL_AREA* c = VmcbControl(V->Vmcb);

    c->VmcbCleanBits = 0;
    c->GuestAsid = 1;

    c->InterceptInstruction1 =
        (1 << 0) |  // CPUID
        (1 << 1) |  // HLT
        (1 << 2);   // VMMCALL

    c->InterceptInstruction2 = 0;

    c->MsrpmBasePa = V->MsrpmPa.QuadPart;
    c->IopmBasePa = V->IopmPa.QuadPart;

    c->NptControl = 1;

    //
    // Correct root for nested paging
    //
    MsrWrite(MSR_NESTED_CR3, V->Npt.Pml4Pa.QuadPart);
}



//======================================================================
//                     SvmInit
//======================================================================
NTSTATUS SvmInit(VCPU** Out)
{
    NTSTATUS st = SvmCheckSupport();
    if (!NT_SUCCESS(st)) return st;

    SvmEnable();

    VCPU* V = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(VCPU), 'VCPU');
    RtlZeroMemory(V, sizeof(*V));

    if (!NT_SUCCESS(st = AllocHostSave(V))) goto fail;
    if (!NT_SUCCESS(st = AllocVmcb(V))) goto fail;
    if (!NT_SUCCESS(st = AllocGuestStack(V))) goto fail;
    if (!NT_SUCCESS(st = AllocMsrpm(V))) goto fail;
    if (!NT_SUCCESS(st = AllocIopm(V))) goto fail;
    if (!NT_SUCCESS(st = NptInitialize(&V->Npt))) goto fail;

    SetupGuest(V);
    SetupControls(V);

    HvActivateLayeredPipeline(V);

    *Out = V;
    return STATUS_SUCCESS;

fail:
    SvmShutdown(V);
    return st;
}


//======================================================================
//                      SvmLaunch
//======================================================================
NTSTATUS SvmLaunch(VCPU* V)
{
    __try {
        VmrunAsm(V->VmcbPa.QuadPart);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return HypervisorHandleExit(V);
}


//======================================================================
//                      Cleanup
//======================================================================
VOID SvmShutdown(VCPU* V)
{
    if (!V) return;

    if (V->GuestStack) ExFreePoolWithTag(V->GuestStack, 'GSTK');
    if (V->Vmcb) MmFreeContiguousMemory(V->Vmcb);
    if (V->HostSave) MmFreeContiguousMemory(V->HostSave);
    if (V->Msrpm) MmFreeContiguousMemory(V->Msrpm);
    if (V->Iopm) MmFreeContiguousMemory(V->Iopm);

    NptDestroy(&V->Npt);
    ExFreePoolWithTag(V, 'VCPU');
}
