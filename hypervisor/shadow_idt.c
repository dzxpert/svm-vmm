#include <ntifs.h>
#include "shadow_idt.h"
#include "vcpu.h"
#include "vmcb.h"
#include "guest_mem.h"
#include "stealth.h"

#pragma pack(push, 1)

typedef struct _IDT_ENTRY
{
    UINT16 OffsetLow;
    UINT16 Selector;
    UINT8  Ist;
    UINT8  TypeAttr;
    UINT16 OffsetMid;
    UINT32 OffsetHigh;
    UINT32 Zero;
} IDT_ENTRY;

typedef struct _IDTR
{
    UINT16 Limit;
    UINT64 Base;
} IDTR;

#pragma pack(pop)

//
// Shadow IDT buffer
//
static IDT_ENTRY g_ShadowIdt[256];
static IDTR      g_ShadowIdtr;

//
// Сюда можно подгрузить свои обработчики
//
static VOID ShadowHandleException(VCPU* V, UINT32 vector, UINT64 errorCode)
{
    switch (vector)
    {
    case 1:   // #DB
    case 3:   // #BP
        DbgPrint("HV: Guest breakpoint / debug interrupt\n");
        break;

    case 13:  // #GP
        DbgPrint("HV: Guest GP fault. error = 0x%llx\n", errorCode);
        break;

    case 14:  // #PF
    {
        VMCB_STATE_SAVE_AREA* s = VmcbState(V->Vmcb);
        UINT64 faultingAddr = s->Cr2;

        DbgPrint("HV: Guest PF at GPA=0x%llx\n", faultingAddr);
        break;
    }

    default:
        DbgPrint("HV: Exception %u occurred\n", vector);
        break;
    }
}

//
// Build IDT gate
//
static VOID ShadowBuildGate(
    IDT_ENTRY* Entry,
    UINT64 Handler)
{
    Entry->OffsetLow = (UINT16)(Handler & 0xFFFF);
    Entry->Selector = 0x10; // Kernel CS
    Entry->Ist = 0;
    Entry->TypeAttr = 0x8E; // Interrupt gate
    Entry->OffsetMid = (UINT16)((Handler >> 16) & 0xFFFF);
    Entry->OffsetHigh = (UINT32)((Handler >> 32) & 0xFFFFFFFF);
    Entry->Zero = 0;
}

//
// Универсальный обработчик для всех исключений (ASM → C bridge)
//
VOID ShadowIdtCommonHandler(VCPU* V, UINT64 vector, UINT64 errorCode)
{
    ShadowHandleException(V, (UINT32)vector, errorCode);

    //
    // Продолжаем выполнение гостя
    //
    VMCB_CONTROL_AREA* c = VmcbControl(V->Vmcb);
    VMCB_STATE_SAVE_AREA* s = VmcbState(V->Vmcb);

    if (c->Nrip)
        s->Rip = c->Nrip;
    else
        s->Rip += 2;
}

//
// Создание Shadow IDT
//
VOID ShadowIdtInitialize(VCPU* V)
{
    RtlZeroMemory(g_ShadowIdt, sizeof(g_ShadowIdt));
    RtlZeroMemory(&g_ShadowIdtr, sizeof(g_ShadowIdtr));

    //
    // Адрес единого обработчика (ASM → C)
    // Ты впишешь сюда свой ASM-хендлер, позже дам файл.
    //
    extern VOID ShadowIdtAsmHandler(void);
    UINT64 handler = (UINT64)ShadowIdtAsmHandler;

    //
    // Заполняем все 256 векторов одним хендлером
    //
    for (UINT32 i = 0; i < 256; i++)
        ShadowBuildGate(&g_ShadowIdt[i], handler);

    g_ShadowIdtr.Base = (UINT64)g_ShadowIdt;
    g_ShadowIdtr.Limit = sizeof(g_ShadowIdt) - 1;

    //
    // Меняем гостевой IDTR
    //
    VMCB_STATE_SAVE_AREA* s = VmcbState(V->Vmcb);

    s->IdtrBase = g_ShadowIdtr.Base;
    s->IdtrLimit = g_ShadowIdtr.Limit;

    DbgPrint("HV: Shadow IDT installed at 0x%llx\n", g_ShadowIdtr.Base);
}

//
// Полное отключение Shadow IDT
//
VOID ShadowIdtDisable(VCPU* V)
{
    VMCB_STATE_SAVE_AREA* s = VmcbState(V->Vmcb);

    s->IdtrBase = 0;
    s->IdtrLimit = 0;

    DbgPrint("HV: Shadow IDT disabled\n");
}
