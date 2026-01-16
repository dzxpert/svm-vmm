#pragma once
#include <ntifs.h>
#include "vmcb.h"
#include "npt.h"

//
// Size of the VCPU host stack (must match KERNEL_STACK_SIZE = 0x6000)
//
#define VCPU_HOST_STACK_SIZE    0x6000

//
// Guest registers structure - order MUST match assembly PUSHAQ/POPAQ
// This is pushed onto the stack by assembly after VMEXIT
//
typedef struct _GUEST_REGISTERS
{
    UINT64 R15;
    UINT64 R14;
    UINT64 R13;
    UINT64 R12;
    UINT64 R11;
    UINT64 R10;
    UINT64 R9;
    UINT64 R8;
    UINT64 Rdi;
    UINT64 Rsi;
    UINT64 Rbp;
    UINT64 Rsp;     // Placeholder (not actual RSP)
    UINT64 Rbx;
    UINT64 Rdx;
    UINT64 Rcx;
    UINT64 Rax;
} GUEST_REGISTERS, *PGUEST_REGISTERS;

//
// Forward declaration
//
struct _VCPU;

//
// Host stack layout - placed at TOP of the host stack
// Assembly refers to fields relative to RSP after setup
//
typedef struct _HOST_STACK_LAYOUT
{
    KTRAP_FRAME TrapFrame;          // For RtlCaptureContext restoration
    UINT64 GuestVmcbPa;             // VMCB physical address at [RSP]
    UINT64 HostVmcbPa;              // Host VMCB PA
    struct _VCPU* Self;             // Pointer back to VCPU
    UINT64 ProcessorIndex;          // CPU index
    UINT64 Reserved1;               // Padding for alignment
} HOST_STACK_LAYOUT, *PHOST_STACK_LAYOUT;

//
// Main VCPU structure - redesigned for infinite VMRUN loop
//
typedef struct _VCPU
{
    //
    // Host stack region - LaunchVm assembly switches to this stack
    // The HOST_STACK_LAYOUT is placed at the TOP of this stack
    //
    union
    {
        DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStackLimit[VCPU_HOST_STACK_SIZE];
        struct
        {
            UINT8 StackContents[VCPU_HOST_STACK_SIZE - sizeof(HOST_STACK_LAYOUT)];
            HOST_STACK_LAYOUT HostStackLayout;
        };
    };

    //
    // VMCB regions (page-aligned)
    //
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB GuestVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB HostVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStateArea[PAGE_SIZE];

    //
    // Nested Page Tables
    //
    NPT_STATE Npt;

    //
    // MSR Permission Map (3 pages = 0x6000)
    //
    PVOID Msrpm;
    PHYSICAL_ADDRESS MsrpmPa;

    //
    // I/O Permission Map (0x2000)
    //
    PVOID Iopm;
    PHYSICAL_ADDRESS IopmPa;

    //
    // Runtime statistics
    //
    struct
    {
        UINT64 ExitCount;
        UINT64 LastExitCode;
        UINT64 ExitBudget;
    } Exec;

    //
    // IPC / Mailbox subsystem (optional)
    //
    struct
    {
        UINT64 MailboxGpa;
        UINT64 LastMessage;
        BOOLEAN Active;
    } Ipc;

    //
    // Extra metadata
    //
    UINT64 CloakedTscOffset;

    //
    // Legacy guest regs (kept for compatibility with existing code)
    //
    struct
    {
        UINT64 Rbx;
        UINT64 Rcx;
        UINT64 Rdx;
        UINT64 Rsi;
        UINT64 Rdi;
        UINT64 Rbp;
        UINT64 R8;
        UINT64 R9;
        UINT64 R10;
        UINT64 R11;
        UINT64 R12;
        UINT64 R13;
        UINT64 R14;
        UINT64 R15;
    } GuestRegs;

    BOOLEAN Active;

} VCPU, *PVCPU;

