OPTION DOTNAME

.text

PUBLIC VmrunAsm
PUBLIC GuestEntry

VmrunAsm PROC
    mov rax, rcx
    vmrun rax
    ret
VmrunAsm ENDP

GuestEntry PROC
    vmmcall
    hlt
    jmp GuestEntry
GuestEntry ENDP

END
