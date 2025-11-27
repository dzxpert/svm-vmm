#pragma once
#include <ntifs.h>
#include "vmcb.h"
#include "npt.h"

typedef struct _VCPU
{
    VMCB* Vmcb;
    PHYSICAL_ADDRESS VmcbPa;

    PVOID HostSave;
    PHYSICAL_ADDRESS HostSavePa;

    PVOID GuestStack;
    SIZE_T GuestStackSize;

    NPT_STATE Npt;

    UINT64 HostCr3;

    BOOLEAN Active;
} VCPU;
