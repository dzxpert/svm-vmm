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
    UNREFERENCED_PARAMETER(s);

    UINT64 leaf = GuestRegs->Rax;
    UINT64 sub = GuestRegs->Rcx;

    UINT32 eax = 0, ebx = 0, ecx = 0, edx = 0;
    
    // Handle hypervisor presence leaves (0x40000000-0x400000FF)
    // Anti-cheat checks these - return zeros to pretend no hypervisor
    if (leaf >= 0x40000000 && leaf <= 0x400000FF)
    {
        eax = 0;
        ebx = 0;
        ecx = 0;
        edx = 0;
    }
    else
    {
        __cpuidex((int*)&eax, (int)leaf, (int)sub);

        // Hide hypervisor presence in standard leaves
        if (leaf == 1)
            ecx &= ~(1 << 31);  // Clear hypervisor present bit

        if (leaf == 0x80000001)
            edx &= ~(1 << 2);   // Clear SVM bit
            
        // Apply stealth masks
        StealthMaskCpuid((UINT32)leaf, &ecx, &edx);
    }

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
// Handle RDTSC exit - compensate for VMEXIT overhead to prevent timing detection
//
static VOID HvHandleRdtsc(VCPU* V, PGUEST_REGISTERS GuestRegs)
{
    VMCB_CONTROL_AREA* c = VmcbControl(&V->GuestVmcb);
    
    // Read actual TSC
    UINT64 tsc = __rdtsc();
    
    // Apply TSC offset from VMCB
    tsc += c->TscOffset;
    
    // Subtract approximate VMEXIT overhead to hide timing anomaly
    // This is an approximation - real overhead varies by CPU
    tsc -= 500;
    
    // Split into EDX:EAX
    GuestRegs->Rax = (UINT32)tsc;
    GuestRegs->Rdx = (UINT32)(tsc >> 32);
    
    HvAdvanceRIP(V, 2);
}

//
// Handle RDTSCP exit - same as RDTSC but also returns IA32_TSC_AUX in ECX
//
static VOID HvHandleRdtscp(VCPU* V, PGUEST_REGISTERS GuestRegs)
{
    VMCB_CONTROL_AREA* c = VmcbControl(&V->GuestVmcb);
    
    // Read actual TSC with processor ID
    UINT32 aux;
    UINT64 tsc = __rdtscp(&aux);
    
    // Apply TSC offset
    tsc += c->TscOffset;
    
    // Subtract VMEXIT overhead
    tsc -= 500;
    
    // Split into EDX:EAX, ECX = aux
    GuestRegs->Rax = (UINT32)tsc;
    GuestRegs->Rdx = (UINT32)(tsc >> 32);
    GuestRegs->Rcx = aux;
    
    HvAdvanceRIP(V, 3);
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

    case SVM_EXIT_RDTSC:
        HvHandleRdtsc(V, GuestRegs);
        break;

    case SVM_EXIT_RDTSCP:
        HvHandleRdtscp(V, GuestRegs);
        break;

    case SVM_EXIT_VINTR:
        // Virtual interrupt pending - clear V_IRQ to acknowledge
        // The interrupt will be delivered to guest on next VMRUN
        c->InterruptControl &= ~(1UL << 8);  // Clear V_IRQ bit
        break;

    default:
        // Unknown exit - log and inject #UD exception to guest
        // This is safer than blindly advancing RIP by 1 byte
        DbgPrint("SVM-HV: [CPU %llu] Unhandled VMEXIT 0x%llX at RIP 0x%llX\n",
                 V->HostStackLayout.ProcessorIndex, exitCode, s->Rip);
        
        // Inject #UD (Invalid Opcode) exception
        // EventInjection format: [31]=Valid, [10:8]=Type (3=Exception), [7:0]=Vector (6=#UD)
        c->EventInjection = (1UL << 31) | (3UL << 8) | 6;
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
