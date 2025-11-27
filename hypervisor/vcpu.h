#pragma once
#include <ntifs.h>
#include "vmcb.h"
#include "npt.h"

typedef struct _VCPU
{
    VMCB* Vmcb;
    PHYSICAL_ADDRESS VmcbPa;

    PVOID HostSaveArea;
    PHYSICAL_ADDRESS HostSaveAreaPa;

    PVOID GuestStack;
    SIZE_T GuestStackSize;

    NPT_STATE NptState;
} VCPU;
