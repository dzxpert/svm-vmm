# User-mode hypercall sample

A minimal Windows user-mode program that exercises the VMMCALL interface
implemented by `HookVmmcallDispatch` in the SVM hypervisor. The sample shows
how to query the ntoskrnl.exe base address and CR3 (directory table base) for
the System process using hypercalls.

## Building

From a Visual Studio x64 Native Tools command prompt, run:

```cmd
ml64 /c hypercall.asm
cl /nologo /W4 /EHsc main.c hypercall.obj /link /out:um_demo.exe
```

Run the resulting `um_demo.exe` after the hypervisor driver has been loaded so
that the `VMMCALL` instruction is intercepted by the hypervisor.

## What it does

The demo performs the following hypercalls:

- Fetches the CPUID vendor string for a quick sanity check.
- Queries the current process image base (0x320).
- Queries the System (PID 4) process image base, which corresponds to
  `ntoskrnl.exe` in typical Windows builds (0x321).
- Queries the System process directory-table base/CR3 value (0x322).
- Translates the module base of the current process from guest virtual to host
  physical address (0x221).

Each request uses the same `HvVmCall` entry point defined in `hypercall.asm` to
map the Windows x64 calling convention to the register layout the hypervisor
expects.
