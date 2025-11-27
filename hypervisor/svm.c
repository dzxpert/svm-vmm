#include <ntifs.h>
#include <intrin.h>
#include "svm.h"
#include "msr.h"
#include "vmcb.h"
#include "npt.h"

extern VOID VmrunAsm(UINT64 VmcbPa);
extern VOID GuestEntry(VOID);

static NTSTATUS SvmCheckSupport()
{
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0x80000001);

    if (!(cpuInfo[2] & (1 << 2)))
        return STATUS_NOT_SUPPORTED;

    UINT64 vmcr = MsrRead(MSR_VM_CR);
    if (vmcr & VM_CR_SVMDIS)
        return STATUS_NOT_SUPPORTED;

    return STATUS_SUCCESS;
}

static NTSTATUS SvmEnable()
{
    UINT64 efer = MsrRead(MSR_EFER);
    if (!(efer & EFER_SVME))
    {
        efer |= EFER_SVME;
        MsrWrite(MSR_EFER, efer);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS SvmAllocateHostSaveArea(VCPU* Vcpu)
{
    Vcpu->HostSaveArea = ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, 'hsvm');
    if (!Vcpu->HostSaveArea)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(Vcpu->HostSaveArea, PAGE_SIZE);

    Vcpu->HostSaveAreaPa = MmGetPhysicalAddress(Vcpu->HostSaveArea);
    MsrWrite(MSR_VM_HSAVE_PA, Vcpu->HostSaveAreaPa.QuadPart);

    return STATUS_SUCCESS;
}

static NTSTATUS SvmAllocateVmcb(VCPU* Vcpu)
{
    Vcpu->Vmcb = (VMCB*)ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, 'bmcv');
    if (!Vcpu->Vmcb)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(Vcpu->Vmcb, PAGE_SIZE);
    Vcpu->VmcbPa = MmGetPhysicalAddress(Vcpu->Vmcb);

    return STATUS_SUCCESS;
}

static NTSTATUS SvmAllocateGuestStack(VCPU* Vcpu)
{
    Vcpu->GuestStackSize = PAGE_SIZE;
    Vcpu->GuestStack = ExAllocatePoolWithTag(NonPagedPoolNx, Vcpu->GuestStackSize, 'stgv');
    if (!Vcpu->GuestStack)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(Vcpu->GuestStack, Vcpu->GuestStackSize);
    return STATUS_SUCCESS;
}

static VOID SvmSetupGuestState(VCPU* Vcpu)
{
    VMCB_STATE_SAVE_AREA* state = VmcbState(Vcpu->Vmcb);

    state->CsSelector = 0x10;
    state->CsAttributes = 0xA09B;
    state->CsLimit = 0xFFFFF;
    state->CsBase = 0;

    state->SsSelector = 0x18;
    state->SsAttributes = 0xC093;
    state->SsLimit = 0xFFFFF;
    state->SsBase = 0;

    state->DsSelector = 0x18;
    state->DsAttributes = 0xC093;
    state->DsLimit = 0xFFFFF;
    state->DsBase = 0;

    state->EsSelector = 0x18;
    state->EsAttributes = 0xC093;
    state->EsLimit = 0xFFFFF;
    state->EsBase = 0;

    state->FsSelector = 0;
    state->FsAttributes = 0;
    state->FsLimit = 0;
    state->FsBase = 0;

    state->GsSelector = 0;
    state->GsAttributes = 0;
    state->GsLimit = 0;
    state->GsBase = 0;

    state->GdtrLimit = 0;
    state->GdtrBase = 0;
    state->IdtrLimit = 0;
    state->IdtrBase = 0;

    UINT64 cr0 = __readcr0();
    UINT64 cr3 = __readcr3();
    UINT64 cr4 = __readcr4();
    UINT64 efer = MsrRead(MSR_EFER);

    state->Cr0 = cr0;
    state->Cr3 = cr3;
    state->Cr4 = cr4;
    state->Efer = efer;

    state->Rflags = 0x2;

    state->Rip = (UINT64)(ULONG_PTR)GuestEntry;
    state->Rsp = (UINT64)(ULONG_PTR)((PUCHAR)Vcpu->GuestStack + Vcpu->GuestStackSize - 0x20);
}

static VOID SvmSetupControlArea(VCPU* Vcpu)
{
    VMCB_CONTROL_AREA* control = VmcbControl(Vcpu->Vmcb);

    control->GuestAsid = 1;
    control->VmcbCleanBits = 0;
}

NTSTATUS SvmInit(VCPU** OutVcpu)
{
    if (!OutVcpu)
        return STATUS_INVALID_PARAMETER;

    *OutVcpu = NULL;

    NTSTATUS status = SvmCheckSupport();
    if (!NT_SUCCESS(status))
        return status;

    status = SvmEnable();
    if (!NT_SUCCESS(status))
        return status;

    VCPU* vcpu = (VCPU*)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(VCPU), 'pcvv');
    if (!vcpu)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(vcpu, sizeof(VCPU));

    status = SvmAllocateHostSaveArea(vcpu);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(vcpu, 'pcvv');
        return status;
    }

    status = SvmAllocateVmcb(vcpu);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(vcpu->HostSaveArea, 'hsvm');
        ExFreePoolWithTag(vcpu, 'pcvv');
        return status;
    }

    status = SvmAllocateGuestStack(vcpu);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(vcpu->Vmcb, 'bmcv');
        ExFreePoolWithTag(vcpu->HostSaveArea, 'hsvm');
        ExFreePoolWithTag(vcpu, 'pcvv');
        return status;
    }

    NptInitialize(&vcpu->NptState);

    SvmSetupGuestState(vcpu);
    SvmSetupControlArea(vcpu);

    *OutVcpu = vcpu;

    return STATUS_SUCCESS;
}

VOID SvmShutdown(VCPU* Vcpu)
{
    if (!Vcpu)
        return;

    UINT64 efer = MsrRead(MSR_EFER);
    if (efer & EFER_SVME)
    {
        efer &= ~EFER_SVME;
        MsrWrite(MSR_EFER, efer);
    }

    if (Vcpu->GuestStack)
        ExFreePoolWithTag(Vcpu->GuestStack, 'stgv');

    if (Vcpu->Vmcb)
        ExFreePoolWithTag(Vcpu->Vmcb, 'bmcv');

    if (Vcpu->HostSaveArea)
        ExFreePoolWithTag(Vcpu->HostSaveArea, 'hsvm');

    NptDestroy(&Vcpu->NptState);

    ExFreePoolWithTag(Vcpu, 'pcvv');
}

NTSTATUS SvmLaunch(VCPU* Vcpu)
{
    if (!Vcpu || !Vcpu->Vmcb)
        return STATUS_INVALID_PARAMETER;

    VmrunAsm(Vcpu->VmcbPa.QuadPart);

    return HypervisorHandleExit(Vcpu);
}
