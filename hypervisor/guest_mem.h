#pragma once
#include <ntifs.h>
#include "vcpu.h"

BOOLEAN GuestReadGva(VCPU* Vcpu, UINT64 GuestVirtualAddress, PVOID Buffer, SIZE_T Size);
BOOLEAN GuestWriteGva(VCPU* Vcpu, UINT64 GuestVirtualAddress, PVOID Buffer, SIZE_T Size);

PHYSICAL_ADDRESS GuestTranslateGvaToGpa(VCPU* Vcpu, UINT64 Gva);
PHYSICAL_ADDRESS GuestTranslateGpaToHpa(VCPU* Vcpu, UINT64 Gpa);
