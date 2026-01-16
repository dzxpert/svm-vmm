#include <ntifs.h>
#include "svm.h"
#include "vcpu.h"
#include "vmcb.h"
#include "guest_mem.h"
#include "npt.h"
#include "hooks.h"
#include "stealth.h"
#include "shadow_idt.h"
#include "layers.h"

//
// Advance RIP to next instruction
//
static VOID HvAdvanceRIP(VCPU* V, UINT8 len)
{
    VMCB_CONTROL_AREA* c = VmcbControl(&V->GuestVmcb);
    VMCB_STATE_SAVE_AREA* s = VmcbState(&V->GuestVmcb);

    if (c->NextRip)
        s->Rip = c->NextRip;
    else
        s->Rip += len;
}

//
// Handle CPUID exit
//
static VOID HvHandleCpuid(VCPU* V, PGUEST_REGISTERS GuestRegs)
{
    VMCB_STATE_SAVE_AREA* s = VmcbState(&V->GuestVmcb);

    UINT64 leaf = GuestRegs->Rax;
    UINT64 sub = GuestRegs->Rcx;

    UINT32 eax, ebx, ecx, edx;
    __cpuidex((int*)&eax, (int)leaf, (int)sub);

    // Hide hypervisor presence
    if (leaf == 1)
        ecx &= ~(1 << 31);

    if (leaf == 0x80000001)
        edx &= ~(1 << 2);

    // Apply stealth masks and hook emulation
    StealthMaskCpuid((UINT32)leaf, &ecx, &edx);
    HookCpuidEmulate(leaf, sub, &eax, &ebx, &ecx, &edx);

    GuestRegs->Rax = eax;
    GuestRegs->Rbx = ebx;
    GuestRegs->Rcx = ecx;
    GuestRegs->Rdx = edx;

    HvAdvanceRIP(V, 2);
}

//
// Handle MSR exit
//
static VOID HvHandleMsr(VCPU* V, PGUEST_REGISTERS GuestRegs)
{
    VMCB_STATE_SAVE_AREA* s = VmcbState(&V->GuestVmcb);

    UINT64 rcx = GuestRegs->Rcx;
    BOOLEAN write = (rcx >> 63) & 1;
    UINT64 msr = rcx & ~0x8000000000000000ULL;

    if (write)
    {
        UINT64 value = GuestRegs->Rax;
        HookHandleMsrWrite(V, msr, value);
    }
    else
    {
        UINT64 value = HookHandleMsrRead(V, msr);
        GuestRegs->Rax = value;
    }

    HvAdvanceRIP(V, 2);
}

//
// Handle VMMCALL exit
//
static VOID HvHandleVmmcall(VCPU* V, PGUEST_REGISTERS GuestRegs)
{
    UINT64 code = GuestRegs->Rax;
    UINT64 arg1 = GuestRegs->Rbx;
    UINT64 arg2 = GuestRegs->Rcx;
    UINT64 arg3 = GuestRegs->Rdx;

    UINT64 result = HookVmmcallDispatch(V, code, arg1, arg2, arg3);

    GuestRegs->Rax = result;

    HvAdvanceRIP(V, 3);
}

//
// Handle NPF (Nested Page Fault) exit
//
static VOID HvHandleNpf(VCPU* V)
{
    VMCB_CONTROL_AREA* c = VmcbControl(&V->GuestVmcb);

    UINT64 fault_gpa = c->ExitInfo2;

    // Try layered NPF handler first
    if (HvHandleLayeredNpf(V, fault_gpa))
    {
        return;
    }

    HookNptHandleFault(V, fault_gpa);
}

//
// Handle HLT exit
//
static VOID HvHandleHlt(VCPU* V)
{
    HvAdvanceRIP(V, 1);
}

//
// Handle I/O exit
//
static VOID HvHandleIo(VCPU* V)
{
    HookIoIntercept(V);
    HvAdvanceRIP(V, 2);
}

//
// Main VMEXIT handler - called from assembly
// Returns FALSE to continue running guest, TRUE to exit hypervisor
//
EXTERN_C BOOLEAN HandleVmExit(VCPU* V, PGUEST_REGISTERS GuestRegs)
{
    VMCB_CONTROL_AREA* c = VmcbControl(&V->GuestVmcb);
    VMCB_STATE_SAVE_AREA* s = VmcbState(&V->GuestVmcb);
    UINT64 exitCode = c->ExitCode;

    V->Exec.ExitCount++;
    V->Exec.LastExitCode = exitCode;

    // Load host state
    PHYSICAL_ADDRESS hostVmcbPa = MmGetPhysicalAddress(&V->HostVmcb);
    __svm_vmload(hostVmcbPa.QuadPart);

    // Copy RAX from VMCB to guest registers (RAX is saved in VMCB, not stack)
    GuestRegs->Rax = s->Rax;

    switch (exitCode)
    {
    case SVM_EXIT_CPUID:
        HvHandleCpuid(V, GuestRegs);
        break;

    case SVM_EXIT_MSR:
        HvHandleMsr(V, GuestRegs);
        break;

    case SVM_EXIT_VMMCALL:
        HvHandleVmmcall(V, GuestRegs);
        break;

    case SVM_EXIT_NPF:
        if (!HvHandleLayeredNpf(V, c->ExitInfo1))
            HvHandleNpf(V);
        break;

    case SVM_EXIT_HLT:
        HvHandleHlt(V);
        break;

    case SVM_EXIT_IOIO:
        HvHandleIo(V);
        break;

    default:
        // Unknown exit - just advance RIP
        HvAdvanceRIP(V, 1);
        break;
    }

    // Copy RAX back to VMCB
    s->Rax = GuestRegs->Rax;

    // Return FALSE to continue running guest
    return FALSE;
}

//
// Legacy function for compatibility - redirects to new handler
//
NTSTATUS HypervisorHandleExit(VCPU* V)
{
    // This function is no longer used in the new architecture
    // The assembly calls HandleVmExit directly
    UNREFERENCED_PARAMETER(V);
    return STATUS_SUCCESS;
}
