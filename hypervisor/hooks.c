#include <ntifs.h>
#include "hooks.h"
#include "vcpu.h"
#include "vmcb.h"
#include "guest_mem.h"
#include "npt.h"
#include "stealth.h"

//
// ================================
//     ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
// ================================
//

static UINT64 g_OriginalLstar = 0;         // Syscall entry
static UINT64 g_OriginalStar = 0;
static UINT64 g_OriginalSfMask = 0;

static UINT64 g_HvSyscallHandler = 0;      // Наш syscall hook (на asm)
static BOOLEAN g_SyscallHookEnabled = FALSE;

static BOOLEAN g_Cr3EncryptionEnabled = FALSE;
static UINT64 g_Cr3XorKey = 0xCAFEBABE1337ULL;

//
// ================================
//     CPUID EMULATION HOOK
// ================================
//

VOID HookCpuidEmulate(UINT32 leaf, UINT32 subleaf,
    UINT32* eax, UINT32* ebx, UINT32* ecx, UINT32* edx)
{
    //
    // Пример: кастомный vendor-string
    //
    if (leaf == 0)
    {
        *ebx = 'V', 'M', 'S', 'V';  // 'VMSV'
        *ecx = 'H', 'V', 'A', 'M';  // 'HVAM'
        *edx = 'S', 'T', 'E', 'L';  // 'STEL'
    }

    //
    // Убираем признаки виртуализации
    //
    *ecx &= ~(1 << 31);  // hypervisor-present
}

//
// ================================
//       MSR READ/WRITE HOOK
// ================================
//

UINT64 HookHandleMsrRead(VCPU* V, UINT64 msr)
{
    switch (msr)
    {
    case MSR_LSTAR:
        if (g_SyscallHookEnabled)
            return g_HvSyscallHandler;
        return g_OriginalLstar;

    case MSR_STAR:
        return g_OriginalStar;

    case MSR_SFMASK:
        return g_OriginalSfMask;

    default:
        return __readmsr(msr);
    }
}

VOID HookInstallSyscall(VCPU* V)
{
    if (g_SyscallHookEnabled) return;

    g_OriginalLstar = __readmsr(MSR_LSTAR);
    g_OriginalStar = __readmsr(MSR_STAR);
    g_OriginalSfMask = __readmsr(MSR_SFMASK);

    //
    // Перезаписать syscall entry на наш обработчик (ASM)
    //
    if (g_HvSyscallHandler != 0)
    {
        __writemsr(MSR_LSTAR, g_HvSyscallHandler);
        g_SyscallHookEnabled = TRUE;
    }
}

VOID HookRemoveSyscall()
{
    if (!g_SyscallHookEnabled) return;

    __writemsr(MSR_LSTAR, g_OriginalLstar);
    __writemsr(MSR_STAR, g_OriginalStar);
    __writemsr(MSR_SFMASK, g_OriginalSfMask);

    g_SyscallHookEnabled = FALSE;
}

VOID HookHandleMsrWrite(VCPU* V, UINT64 msr, UINT64 value)
{
    switch (msr)
    {
    case MSR_LSTAR:
    {
        g_OriginalLstar = value;
        return;
    }
    case MSR_STAR:
    {
        g_OriginalStar = value;
        return;
    }
    case MSR_SFMASK:
    {
        g_OriginalSfMask = value;
        return;
    }
    default:
        __writemsr(msr, value);
        return;
    }
}

//
// ================================
//        CR3 ENCRYPT/DECRYPT
// ================================
//

UINT64 HookEncryptCr3(UINT64 cr3)
{
    if (!g_Cr3EncryptionEnabled)
        return cr3;

    return cr3 ^ g_Cr3XorKey;
}

UINT64 HookDecryptCr3(UINT64 cr3_enc)
{
    if (!g_Cr3EncryptionEnabled)
        return cr3_enc;

    return cr3_enc ^ g_Cr3XorKey;
}

//
// ================================
//     NPT / GPA HOOK INTERFACE
// ================================
//

BOOLEAN HookNptHandleFault(VCPU* V, UINT64 faultingGpa)
{
    //
    // Пример: ловим страницу guest code и подменяем на свою
    //
    UINT64 targetPage = 0x1000;      // GPA guest shellcode
    UINT64 hookPage = 0x90000000;  // HPA with our code

    if ((faultingGpa & ~0xFFFULL) == targetPage)
    {
        NptHookPage(&V->Npt, targetPage, hookPage);
        return TRUE;
    }

    return FALSE;
}

//
// ================================
//       RING-3 VMMCALL API
// ================================
//
// VMMCALL convention:
//   RAX = hypercall code
//   RBX, RCX, RDX = args
//
// Возврат RAX
//

UINT64 HookVmmcallDispatch(VCPU* V, UINT64 code, UINT64 a1, UINT64 a2, UINT64 a3)
{
    switch (code)
    {
    case 0x100:   // read guest virtual mem
    {
        BYTE buf[8];
        if (GuestReadGva(V, a1, buf, sizeof(buf)))
            return *(UINT64*)buf;
        return 0;
    }

    case 0x101:   // write guest memory
    {
        UINT64 value = a2;
        GuestWriteGva(V, a1, &value, sizeof(value));
        return TRUE;
    }

    case 0x200:  // stealth mode enable
        StealthEnable();
        return TRUE;

    case 0x201:
        StealthDisable();
        return TRUE;

    case 0x300: // enable syscall hook
        HookInstallSyscall(V);
        return TRUE;

    case 0x301:
        HookRemoveSyscall();
        return TRUE;

    default:
        return 0xDEADBEEF;
    }
}

//
// ================================
//     IO PORT INTERCEPT
// ================================
//

VOID HookIoIntercept(VCPU* V)
{
    // Ты можешь логировать или эмулировать IO здесь
}

