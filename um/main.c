#include <Windows.h>
#include <intrin.h>
#include <stdint.h>
#include <stdio.h>

#include "hypercall.h"

static uint64_t SafeVmCall(uint64_t code, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    __try
    {
        return HvVmCall(code, arg1, arg2, arg3);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        printf("[!] VMMCALL 0x%llx faulted with 0x%08X\n", code, GetExceptionCode());
        return 0;
    }
}

static void PrintVendorString(void)
{
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);

    char vendor[13] = { 0 };
    memcpy(vendor + 0, &cpuInfo[1], 4); // ebx
    memcpy(vendor + 4, &cpuInfo[3], 4); // edx
    memcpy(vendor + 8, &cpuInfo[2], 4); // ecx

    printf("[+] CPUID vendor: %s\n", vendor);
}

static void DumpProcessInfo(void)
{
    uint64_t currentBase = SafeVmCall(HV_VMCALL_QUERY_CURRENT_PROCESS_BASE, 0, 0, 0);
    uint64_t systemBase = SafeVmCall(HV_VMCALL_QUERY_PROCESS_BASE, 4, 0, 0);
    uint64_t systemCr3 = SafeVmCall(HV_VMCALL_QUERY_PROCESS_DIRBASE, 4, 0, 0);

    printf("[+] Current process base : 0x%llx\n", currentBase);
    printf("[+] ntoskrnl.exe base    : 0x%llx\n", systemBase);
    printf("[+] System process CR3   : 0x%llx\n", systemCr3);
}

static void DumpAddressTranslations(void)
{
    uint64_t selfAddress = (uint64_t)GetModuleHandleW(NULL);
    uint64_t selfHpa = SafeVmCall(HV_VMCALL_TRANSLATE_GVA_TO_HPA, selfAddress, 0, 0);

    printf("[+] Image base GVA: 0x%llx -> HPA: 0x%llx\n", selfAddress, selfHpa);
}

int main(void)
{
    printf("[+] Simple usermode hypervisor demo\n");
    printf("    Ensure the SVM hypervisor driver is loaded before running.\n\n");

    PrintVendorString();
    DumpProcessInfo();
    DumpAddressTranslations();

    printf("\n[+] Done.\n");
    return 0;
}

