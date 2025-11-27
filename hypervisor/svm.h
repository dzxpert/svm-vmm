#pragma once
#include <ntifs.h>
#include "vcpu.h"

NTSTATUS SvmInit(VCPU** OutVcpu);
VOID SvmShutdown(VCPU* Vcpu);
NTSTATUS SvmLaunch(VCPU* Vcpu);
NTSTATUS HypervisorHandleExit(VCPU* Vcpu);
