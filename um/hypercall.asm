option casemap:none

.code

; uint64_t HvVmCall(uint64_t code, uint64_t arg1, uint64_t arg2, uint64_t arg3)
HvVmCall PROC
    push rbx

    ; Map Windows x64 calling convention arguments to the registers
    ; expected by HookVmmcallDispatch inside the hypervisor.
    mov rax, rcx ; code
    mov rbx, rdx ; arg1
    mov rcx, r8  ; arg2
    mov rdx, r9  ; arg3

    ; VMMCALL (0F 01 D9) transfers control to the hypervisor when
    ; the SVM VMMCALL intercept is enabled.
    db 0fh, 01h, 0d9h

    pop rbx
    ret
HvVmCall ENDP

END
