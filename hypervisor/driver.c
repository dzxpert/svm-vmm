#include <ntifs.h>
#include "svm.h"

PDRIVER_OBJECT g_DriverObject;
VCPU* g_Vcpu;

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_Vcpu)
    {
        SvmShutdown(g_Vcpu);
        g_Vcpu = NULL;
    }

    DbgPrint("vmm: unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    g_DriverObject = DriverObject;
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("vmm: loading\n");

    NTSTATUS status = SvmInit(&g_Vcpu);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("vmm: SvmInit failed 0x%08X\n", status);
        return status;
    }

    status = SvmLaunch(g_Vcpu);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("vmm: SvmLaunch failed 0x%08X\n", status);
        SvmShutdown(g_Vcpu);
        g_Vcpu = NULL;
        return status;
    }

    DbgPrint("vmm: vmrun finished\n");

    return STATUS_SUCCESS;
}
