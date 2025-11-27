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
GuestLoop:
    mov rax, 1337h
    vmmcall
    hlt
    jmp GuestLoop
GuestEntry ENDP

END
