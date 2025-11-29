#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Raw VMMCALL entry point implemented in hypercall.asm.
uint64_t HvVmCall(uint64_t code, uint64_t arg1, uint64_t arg2, uint64_t arg3);

// VMMCALL dispatch codes mirrored from HookVmmcallDispatch in the hypervisor.
typedef enum _HV_VMCALL_CODE
{
    HV_VMCALL_READ_GVA = 0x100,
    HV_VMCALL_WRITE_GVA = 0x101,
    HV_VMCALL_ENABLE_CR3_XOR = 0x102,
    HV_VMCALL_DISABLE_CR3_XOR = 0x103,
    HV_VMCALL_INSTALL_SHADOW_HOOK = 0x110,
    HV_VMCALL_CLEAR_SHADOW_HOOK = 0x111,
    HV_VMCALL_STEALTH_ENABLE = 0x200,
    HV_VMCALL_STEALTH_DISABLE = 0x201,
    HV_VMCALL_LAST_MAILBOX = 0x210,
    HV_VMCALL_SEND_MAILBOX = 0x211,
    HV_VMCALL_TRANSLATE_GVA_TO_GPA = 0x220,
    HV_VMCALL_TRANSLATE_GVA_TO_HPA = 0x221,
    HV_VMCALL_TRANSLATE_GPA_TO_HPA = 0x222,
    HV_VMCALL_QUERY_CURRENT_PROCESS_BASE = 0x320,
    HV_VMCALL_QUERY_PROCESS_BASE = 0x321,
    HV_VMCALL_QUERY_PROCESS_DIRBASE = 0x322,
    HV_VMCALL_ENABLE_SYSCALL_HOOK = 0x300,
    HV_VMCALL_DISABLE_SYSCALL_HOOK = 0x301,
} HV_VMCALL_CODE;

static inline uint64_t HvQueryCurrentProcessBase(void)
{
    return HvVmCall(HV_VMCALL_QUERY_CURRENT_PROCESS_BASE, 0, 0, 0);
}

static inline uint64_t HvQueryProcessBase(uint64_t pid)
{
    return HvVmCall(HV_VMCALL_QUERY_PROCESS_BASE, pid, 0, 0);
}

static inline uint64_t HvQueryProcessDirbase(uint64_t pid)
{
    return HvVmCall(HV_VMCALL_QUERY_PROCESS_DIRBASE, pid, 0, 0);
}

static inline uint64_t HvTranslateGvaToHpa(uint64_t gva)
{
    return HvVmCall(HV_VMCALL_TRANSLATE_GVA_TO_HPA, gva, 0, 0);
}

#ifdef __cplusplus
}
#endif

