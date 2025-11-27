#include <ntifs.h>
#include "svm.h"
#include "vcpu.h"
#include "vmcb.h"

#define SVM_EXIT_VMMCALL 0x81

NTSTATUS HypervisorHandleExit(VCPU* Vcpu)
{
    if (!Vcpu || !Vcpu->Vmcb)
        return STATUS_INVALID_PARAMETER;

    VMCB_CONTROL_AREA* control = VmcbControl(Vcpu->Vmcb);

    UINT64 exitCode = control->ExitCode;
    UINT64 exitInfo1 = control->ExitInfo1;
    UINT64 exitInfo2 = control->ExitInfo2;
    UINT64 nrip = control->Nrip;

    DbgPrint("vmm: vmexit code=0x%llx info1=0x%llx info2=0x%llx nrip=0x%llx\n", exitCode, exitInfo1, exitInfo2, nrip);

    if (exitCode == SVM_EXIT_VMMCALL)
        return STATUS_SUCCESS;

    return STATUS_UNSUCCESSFUL;
}
