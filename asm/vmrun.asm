option casemap:none

PUBLIC VmrunAsm
PUBLIC GuestEntry

_TEXT SEGMENT ALIGN(16)

VmrunAsm PROC
    mov     rax, rcx
    vmrun   rax
    ret
VmrunAsm ENDP

GuestEntry PROC
guest_loop:
    hlt
    jmp guest_loop
GuestEntry ENDP

_TEXT ENDS
END
