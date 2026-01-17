#include <ntifs.h>
#include <intrin.h>
#include "svm.h"
#include "msr.h"
#include "vmcb.h"
#include "npt.h"
#include "layers.h"
#include "vcpu.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

// Assembly function - never returns to caller
extern VOID LaunchVm(PVOID HostRsp);

#define MSRPM_SIZE      0x6000
#define IOPM_SIZE       0x2000
#define MSR_VM_HSAVE    0xC0010117

typedef struct _DESCRIPTOR_TABLE_REG {
    USHORT Limit;
    ULONG64 Base;
} DESCRIPTOR_TABLE_REG;

#include <pshpack1.h>
typedef struct _DESCRIPTOR_TABLE_REG_PACKED {
    UINT16 Limit;
    ULONG_PTR Base;
} DESCRIPTOR_TABLE_REG_PACKED;
#include <poppack.h>

//
// Check if AMD SVM is supported
//
static NTSTATUS SvmCheckSupport(VOID)
{
    int info[4];

    __cpuid(info, 0x80000001);
    if (!(info[2] & (1 << 2)))
        return STATUS_NOT_SUPPORTED;

    // Disabled for nested virtualization testing in VM
    //__cpuid(info, 1);
    //if (info[2] & (1 << 31))
    //    return STATUS_HV_FEATURE_UNAVAILABLE;

    if (MsrRead(MSR_VM_CR) & VM_CR_SVMDIS)
        return STATUS_NOT_SUPPORTED;

    return STATUS_SUCCESS;
}

//
// Enable SVM in EFER MSR
//
static VOID SvmEnable(VOID)
{
    UINT64 efer = MsrRead(MSR_EFER);
    if (!(efer & EFER_SVME))
        MsrWrite(MSR_EFER, efer | EFER_SVME);
}

//
// Allocate page-aligned contiguous memory
//
static PVOID AllocAligned(SIZE_T size, PHYSICAL_ADDRESS* pa)
{
    PHYSICAL_ADDRESS low = { 0 };
    PHYSICAL_ADDRESS high = { .QuadPart = ~0ULL };
    PHYSICAL_ADDRESS skip = { 0 };

    PVOID mem = MmAllocateContiguousMemorySpecifyCache(size, low, high, skip, MmCached);
    if (!mem)
    {
        DbgPrint("SVM-HV: MmAllocateContiguousMemorySpecifyCache(%llu) failed\n", (UINT64)size);
        return NULL;
    }

    RtlZeroMemory(mem, size);
    if (pa)
        *pa = MmGetPhysicalAddress(mem);
    return mem;
}

//
// Get segment access rights from GDT
//
static UINT16 GetSegmentAccessRights(UINT16 SegmentSelector, ULONG_PTR GdtBase)
{
    typedef struct _SEGMENT_DESCRIPTOR {
        UINT16 LimitLow;
        UINT16 BaseLow;
        UINT8 BaseMiddle;
        UINT8 Type : 4;
        UINT8 System : 1;
        UINT8 Dpl : 2;
        UINT8 Present : 1;
        UINT8 LimitHigh : 4;
        UINT8 Avl : 1;
        UINT8 LongMode : 1;
        UINT8 DefaultBit : 1;
        UINT8 Granularity : 1;
        UINT8 BaseHigh;
    } SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;

    PSEGMENT_DESCRIPTOR desc = (PSEGMENT_DESCRIPTOR)(GdtBase + (SegmentSelector & ~0x7));
    
    UINT16 attr = 0;
    attr |= (desc->Type & 0xF);
    attr |= (desc->System & 0x1) << 4;
    attr |= (desc->Dpl & 0x3) << 5;
    attr |= (desc->Present & 0x1) << 7;
    attr |= (desc->Avl & 0x1) << 8;
    attr |= (desc->LongMode & 0x1) << 9;
    attr |= (desc->DefaultBit & 0x1) << 10;
    attr |= (desc->Granularity & 0x1) << 11;
    
    return attr;
}

//
// Allocate MSRPM
//
static NTSTATUS AllocMsrpm(VCPU* V)
{
    V->Msrpm = AllocAligned(MSRPM_SIZE, &V->MsrpmPa);
    return V->Msrpm ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

//
// Allocate IOPM
//
static NTSTATUS AllocIopm(VCPU* V)
{
    V->Iopm = AllocAligned(IOPM_SIZE, &V->IopmPa);
    return V->Iopm ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

//
// Setup VMCB for guest using the captured context
//
static VOID SetupVmcbFromContext(VCPU* V, PCONTEXT Ctx)
{
    VMCB_STATE_SAVE_AREA* s = VmcbState(&V->GuestVmcb);
    VMCB_CONTROL_AREA* c = VmcbControl(&V->GuestVmcb);
    
    // Must use packed structure for SGDT/SIDT (exactly 10 bytes)
    DESCRIPTOR_TABLE_REG_PACKED gdtr, idtr;
    _sgdt(&gdtr);
    __sidt(&idtr);
    
    // Zero out VMCB
    RtlZeroMemory(&V->GuestVmcb, sizeof(V->GuestVmcb));
    
    // Setup control area
    c->GuestAsid = 1;
    c->VmcbClean = 0;
    
    // Intercepts - use Intercepts array
    // Word 3: CPUID (bit 18), optionally RDTSC (bit 1) for timing attack mitigation
    c->Intercepts[3] = SVM_INTERCEPT_CPUID;
    
    // Word 4: VMRUN (bit 0), VMMCALL (bit 1), optionally RDTSCP (bit 3)
    c->Intercepts[4] = SVM_INTERCEPT_VMRUN | SVM_INTERCEPT_VMMCALL;
    
    // RDTSC/RDTSCP interception DISABLED by default
    // WARNING: Enabling causes VM freeze due to extremely high VMEXIT frequency
    // Windows calls RDTSC thousands of times per second
    // TODO: Implement smarter timing hiding (TSC scaling, selective interception)
    // c->Intercepts[3] |= SVM_INTERCEPT_RDTSC;
    // c->Intercepts[4] |= SVM_INTERCEPT_RDTSCP;
    
    c->MsrpmBasePa = V->MsrpmPa.QuadPart;
    c->IopmBasePa = V->IopmPa.QuadPart;
    // Enable NPT (Nested Page Tables) for memory virtualization
    // This enables hardware-assisted address translation: GVA -> GPA -> HPA
    // NPT tables are identity-mapped (GPA == HPA) by NptInitialize()
    c->NestedControl = SVM_NESTED_CTL_NP_ENABLE;
    c->NestedCr3 = V->Npt.Pml4Pa.QuadPart;
    
    // TSC offset - used to compensate for VMEXIT overhead
    c->TscOffset = V->CloakedTscOffset;
    
    // Setup state save area from captured context
    s->Gdtr.Base = gdtr.Base;
    s->Gdtr.Limit = gdtr.Limit;
    s->Idtr.Base = idtr.Base;
    s->Idtr.Limit = idtr.Limit;
    
    s->Cs.Limit = (UINT32)__segmentlimit(Ctx->SegCs);
    s->Ds.Limit = (UINT32)__segmentlimit(Ctx->SegDs);
    s->Es.Limit = (UINT32)__segmentlimit(Ctx->SegEs);
    s->Ss.Limit = (UINT32)__segmentlimit(Ctx->SegSs);
    
    s->Cs.Selector = Ctx->SegCs;
    s->Ds.Selector = Ctx->SegDs;
    s->Es.Selector = Ctx->SegEs;
    s->Ss.Selector = Ctx->SegSs;
    
    s->Cs.Attributes = GetSegmentAccessRights(Ctx->SegCs, gdtr.Base);
    s->Ds.Attributes = GetSegmentAccessRights(Ctx->SegDs, gdtr.Base);
    s->Es.Attributes = GetSegmentAccessRights(Ctx->SegEs, gdtr.Base);
    s->Ss.Attributes = GetSegmentAccessRights(Ctx->SegSs, gdtr.Base);
    
    s->Efer = MsrRead(MSR_EFER);
    s->Cr0 = __readcr0();
    s->Cr2 = __readcr2();
    s->Cr3 = __readcr3();
    s->Cr4 = __readcr4();
    s->Rflags = Ctx->EFlags;
    s->Rsp = Ctx->Rsp;
    s->Rip = Ctx->Rip;
    s->Rax = Ctx->Rax;
    s->Pat = MsrRead(0x277);  // IA32_MSR_PAT
    
    // Update shadow CR3 for NPT
    NptUpdateShadowCr3(&V->Npt, s->Cr3);
}

//
// Initialize a VCPU structure
//
NTSTATUS SvmInit(VCPU** Out)
{
    NTSTATUS st = SvmCheckSupport();
    if (!NT_SUCCESS(st)) 
        return st;

    // Allocate VCPU with page alignment (it contains page-aligned VMCBs)
    PHYSICAL_ADDRESS low = { 0 };
    PHYSICAL_ADDRESS high = { .QuadPart = ~0ULL };
    PHYSICAL_ADDRESS skip = { 0 };
    
    VCPU* V = MmAllocateContiguousMemorySpecifyCache(sizeof(VCPU), low, high, skip, MmCached);
    if (!V)
        return HV_STATUS_ALLOC_VCPU;

    RtlZeroMemory(V, sizeof(*V));
    
    DbgPrint("SVM-HV: VCPU allocated at %p, size=0x%llX\n", V, (UINT64)sizeof(VCPU));

    // Allocate MSRPM
    if (!NT_SUCCESS(st = AllocMsrpm(V)))
    {
        DbgPrint("SVM-HV: AllocMsrpm failed: 0x%X\n", st);
        st = HV_STATUS_ALLOC_MSRPM;
        goto fail;
    }
    
    // Allocate IOPM
    if (!NT_SUCCESS(st = AllocIopm(V)))
    {
        DbgPrint("SVM-HV: AllocIopm failed: 0x%X\n", st);
        st = HV_STATUS_ALLOC_IOPM;
        goto fail;
    }
    
    // Initialize NPT
    if (!NT_SUCCESS(st = NptInitialize(&V->Npt)))
    {
        DbgPrint("SVM-HV: NptInitialize failed: 0x%X\n", st);
        goto fail;
    }

    *Out = V;
    return STATUS_SUCCESS;

fail:
    SvmShutdown(V);
    return st;
}

//
// Launch the hypervisor on the current CPU
// Uses RtlCaptureContext trick to "return" from the infinite VMRUN loop
//
NTSTATUS SvmLaunch(VCPU* V)
{
    ULONG cpuIndex = KeGetCurrentProcessorNumber();
    
    DbgPrint("SVM-HV: [CPU %lu] Starting virtualization...\n", cpuIndex);
    
    // Enable SVM on this CPU
    SvmEnable();
    
    // Allocate context on stack
    CONTEXT ctx;
    RtlCaptureContext(&ctx);
    
    // Check if we've "returned" from virtualization
    // After LaunchVm, the guest will eventually execute this code
    // with Rax == MAXUINT64, signaling successful virtualization
    if (ctx.Rax == MAXUINT64)
    {
        DbgPrint("SVM-HV: [CPU %lu] Virtualization successful!\n", cpuIndex);
        V->Active = TRUE;
        return STATUS_SUCCESS;
    }
    
    DbgPrint("SVM-HV: [CPU %lu] Preparing VMCB...\n", cpuIndex);
    
    // Setup the VMCB from the captured context
    SetupVmcbFromContext(V, &ctx);
    
    // Get physical addresses
    PHYSICAL_ADDRESS guestVmcbPa = MmGetPhysicalAddress(&V->GuestVmcb);
    PHYSICAL_ADDRESS hostVmcbPa = MmGetPhysicalAddress(&V->HostVmcb);
    PHYSICAL_ADDRESS hostStateAreaPa = MmGetPhysicalAddress(&V->HostStateArea);
    
    // Setup host stack layout (at top of host stack)
    V->HostStackLayout.GuestVmcbPa = guestVmcbPa.QuadPart;
    V->HostStackLayout.HostVmcbPa = hostVmcbPa.QuadPart;
    V->HostStackLayout.Self = V;
    V->HostStackLayout.ProcessorIndex = cpuIndex;
    V->HostStackLayout.Reserved1 = MAXUINT64;
    
    // Save guest VMCB state
    __svm_vmsave(guestVmcbPa.QuadPart);
    
    // Set host save area
    __writemsr(MSR_VM_HSAVE, hostStateAreaPa.QuadPart);
    
    // Save host VMCB state
    __svm_vmsave(hostVmcbPa.QuadPart);
    
    // CRITICAL FIX: The check `if (ctx.Rax == MAXUINT64)` reads from the 
    // CONTEXT structure in MEMORY, not from the RAX register!
    // We must set BOTH:
    // 1. ctx.Rax in memory - so the if check passes
    // 2. VMCB's Rax - so the guest register is correct
    ctx.Rax = MAXUINT64;
    VmcbState(&V->GuestVmcb)->Rax = MAXUINT64;
    
    // Disable the layered pipeline for now (debugging)
    // HvActivateLayeredPipeline(V);
    
    DbgPrint("SVM-HV: [CPU %lu] Launching VM (this should not return)...\n", cpuIndex);
    
    // Launch the VM - this NEVER returns to here!
    // Instead, the guest will execute the RtlCaptureContext code above
    // with Rax = MAXUINT64
    LaunchVm(&V->HostStackLayout.GuestVmcbPa);
    
    // If we get here, something went wrong
    DbgPrint("SVM-HV: [CPU %lu] ERROR: LaunchVm returned unexpectedly!\n", cpuIndex);
    return STATUS_UNSUCCESSFUL;
}

//
// Shutdown and free VCPU resources
//
VOID SvmShutdown(VCPU* V)
{
    if (!V) 
        return;

    if (V->Msrpm) 
        MmFreeContiguousMemory(V->Msrpm);
    if (V->Iopm) 
        MmFreeContiguousMemory(V->Iopm);

    NptDestroy(&V->Npt);
    MmFreeContiguousMemory(V);
}
