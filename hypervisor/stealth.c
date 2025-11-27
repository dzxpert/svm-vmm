#include <ntifs.h>
#include "stealth.h"
#include "vcpu.h"
#include "vmcb.h"
#include "msr.h"

//
// Глобальные флаги режима стелс
//

static BOOLEAN g_StealthEnabled = FALSE;
static BOOLEAN g_HideSvmMsr = TRUE;
static BOOLEAN g_HideVmcbMemory = TRUE;
static BOOLEAN g_HideHostSave = TRUE;
static BOOLEAN g_HideCr3Xor = TRUE;

//
// XOR-ключ для маскировки CR3
//
static UINT64 g_Cr3XorKey = 0xA5A5A5A5CAFEBABEULL;

//
// Убираем SVM-биты из CPUID (зеркально с hooks.c)
//
VOID StealthMaskCpuid(UINT32 leaf, UINT32* ecx, UINT32* edx)
{
    if (!g_StealthEnabled)
        return;

    if (leaf == 1)
    {
        // Hypervisor present bit
        *ecx &= ~(1 << 31);
    }

    if (leaf == 0x80000001)
    {
        // SVM bit
        *edx &= ~(1 << 2);
    }
}

//
// Маскируем MSR_EFER.SVME
//
UINT64 StealthMaskMsrRead(UINT32 msr, UINT64 value)
{
    if (!g_StealthEnabled)
        return value;

    if (g_HideSvmMsr)
    {
        if (msr == MSR_EFER)
        {
            //
            // просто скрываем SVME бит (бит 12)
            //
            return value & ~((UINT64)1 << 12);
        }
    }

    return value;
}

//
// Применение CR3 XOR
//
UINT64 StealthEncryptCr3(UINT64 cr3)
{
    if (!g_StealthEnabled || !g_HideCr3Xor)
        return cr3;

    return cr3 ^ g_Cr3XorKey;
}

UINT64 StealthDecryptCr3(UINT64 cr3_enc)
{
    if (!g_StealthEnabled || !g_HideCr3Xor)
        return cr3_enc;

    return cr3_enc ^ g_Cr3XorKey;
}

//
// Маскировка памяти гипервизора
//
VOID StealthHideHypervisorMemory(VCPU* V)
{
    if (!g_StealthEnabled)
        return;

    //
    // Маскируем VMCB
    //
    if (g_HideVmcbMemory && V->Vmcb)
    {
        RtlSecureZeroMemory(V->Vmcb, PAGE_SIZE);
    }

    //
    // Маскируем HostSave
    //
    if (g_HideHostSave && V->HostSave)
    {
        RtlSecureZeroMemory(V->HostSave, PAGE_SIZE);
    }
}

//
// ===== Анти-анализ =====
//

// Скрытие использование VMRUN (низкоуровневое)
BOOLEAN StealthPreventVmrunDetection()
{
    if (!g_StealthEnabled)
        return TRUE;

    //
    // Basic anti-analysis (можно расширить)
    //
    // Скрытие бита VMX/SVM в CPUID
    // Скрытие следов в MSR
    //
    return TRUE;
}

// Скрытие VMCB clean bits (делаем вид, что нет изменений)
VOID StealthCleanVmcb(VCPU* V)
{
    if (!g_StealthEnabled)
        return;

    VMCB_CONTROL_AREA* c = VmcbControl(V->Vmcb);

    c->VmcbCleanBits = 0xFFFFFFFFFFFFFFFFULL;
}

//
// ===== API =====
//

VOID StealthEnable()
{
    g_StealthEnabled = TRUE;
}

VOID StealthDisable()
{
    g_StealthEnabled = FALSE;
}

BOOLEAN StealthIsEnabled()
{
    return g_StealthEnabled;
}

