; vmrun.asm - Infinite VMRUN loop for AMD SVM hypervisor
; Based on the working reference implementation

option casemap:none

.const

KTRAP_FRAME_SIZE            equ     190h
MACHINE_FRAME_SIZE          equ     28h

.code

extern HandleVmExit : proc

;------------------------------------------------------------------------------
; UINT16 ReadTr(VOID)
; Returns the Task Register selector
;------------------------------------------------------------------------------
PUBLIC ReadTr
ReadTr PROC
        xor     rax, rax
        str     ax
        ret
ReadTr ENDP

;------------------------------------------------------------------------------
; UINT16 ReadLdtr(VOID)
; Returns the LDTR selector  
;------------------------------------------------------------------------------
PUBLIC ReadLdtr
ReadLdtr PROC
        xor     rax, rax
        sldt    ax
        ret
ReadLdtr ENDP

PUSHAQ macro
        push    rax
        push    rcx
        push    rdx
        push    rbx
        push    -1
        push    rbp
        push    rsi
        push    rdi
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15
        endm

POPAQ macro
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx
        pop     rbx
        pop     rdx
        pop     rcx
        pop     rax
        endm

;------------------------------------------------------------------------------
; void LaunchVm(PVOID hostRsp)
;
; This function NEVER RETURNS to its caller.
; Parameters:
;   rcx = Pointer to the GuestVmcbPa field at top of host stack
;------------------------------------------------------------------------------
PUBLIC LaunchVm
LaunchVm PROC FRAME
        ; Switch to the host stack
        mov     rsp, rcx

VmRunLoop:
        ; Load VMCB PA and execute VMRUN cycle
        mov     rax, [rsp]
        vmload  rax
        vmrun   rax
        vmsave  rax

        ; VMEXIT occurred - set up stack frame
        .pushframe
        sub     rsp, KTRAP_FRAME_SIZE
        .allocstack KTRAP_FRAME_SIZE - MACHINE_FRAME_SIZE + 100h

        ; Save all guest registers
        PUSHAQ

        ; Prepare arguments for exit handler
        ; rdx = GUEST_REGISTERS pointer (current stack)
        ; rcx = VCPU pointer (Self field at offset +16 from original rsp)
        ; 
        ; Stack layout after PUSHAQ:
        ;   [rsp]                              = GUEST_REGISTERS (16 regs * 8 = 128 bytes)
        ;   [rsp + 128]                        = start of KTRAP_FRAME space
        ;   [rsp + 128 + KTRAP_FRAME_SIZE]     = original rsp (GuestVmcbPa)
        ;   [rsp + 128 + 0x190 + 16]           = Self pointer
        ;
        ; Reference uses: [rsp + 8 * 18 + KTRAP_FRAME_SIZE] = [rsp + 144 + 0x190]
        ; The extra 16 bytes (144 vs 128) might be from frame setup
        mov     rdx, rsp
        mov     rcx, [rsp + 8 * 18 + KTRAP_FRAME_SIZE]

        ; Allocate shadow space and save XMM registers
        sub     rsp, 80h
        movaps  xmmword ptr [rsp + 20h], xmm0
        movaps  xmmword ptr [rsp + 30h], xmm1
        movaps  xmmword ptr [rsp + 40h], xmm2
        movaps  xmmword ptr [rsp + 50h], xmm3
        movaps  xmmword ptr [rsp + 60h], xmm4
        movaps  xmmword ptr [rsp + 70h], xmm5
        .endprolog

        ; Call the C exit handler
        call    HandleVmExit

        ; Restore XMM registers
        movaps  xmm5, xmmword ptr [rsp + 70h]
        movaps  xmm4, xmmword ptr [rsp + 60h]
        movaps  xmm3, xmmword ptr [rsp + 50h]
        movaps  xmm2, xmmword ptr [rsp + 40h]
        movaps  xmm1, xmmword ptr [rsp + 30h]
        movaps  xmm0, xmmword ptr [rsp + 20h]
        add     rsp, 80h

        ; Restore guest registers
        POPAQ

        ; Restore stack
        add     rsp, KTRAP_FRAME_SIZE

        ; Loop back
        jmp     VmRunLoop

LaunchVm ENDP

END
