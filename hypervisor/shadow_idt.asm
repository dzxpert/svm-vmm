; ===============================================================
; shadow_idt.asm — универсальный обработчик Shadow IDT
;
; Этот stub делает следующее:
;  1. Сохраняет гостевой контекст
;  2. Определяет номер вектора и error_code
;  3. Зовёт C-функцию:
;         ShadowIdtCommonHandler(VCPU* V, UINT64 vector, UINT64 errorCode)
;  4. Возвращает управление обратно в гостя
;
;  Совместимо с Windows x64 ABI + AMD SVM VMCB
; ===============================================================

OPTION DOTNAME
.text

EXTERN ShadowIdtCommonHandler:PROC
EXTERN g_CurrentVcpu:QWORD ; если используешь глобальный указатель на VCPU*

PUBLIC ShadowIdtAsmHandler

ShadowIdtAsmHandler PROC

    ; ---------------------------------------------------------
    ; Сохранение всех регистров гостя
    ; ---------------------------------------------------------
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; ---------------------------------------------------------
    ; Вектор и error code поступают по стеку гостя
    ;     Вектор    = [rsp + 0x78]   (после push всех регистров)
    ;     ErrorCode = [rsp + 0x80]   (если исключение с ошибкой)
    ; ---------------------------------------------------------
    mov rax, [rsp + 0x78]     ; vector
    mov rbx, [rsp + 0x80]     ; error_code

    ; ---------------------------------------------------------
    ; Windows x64 ABI:
    ;   RCX = 1-й аргумент
    ;   RDX = 2-й аргумент
    ;   R8  = 3-й аргумент
    ; ---------------------------------------------------------

    mov rcx, g_CurrentVcpu     ; RCX = VCPU*
    mov rdx, rax               ; RDX = vector
    mov r8,  rbx               ; R8  = error_code

    sub rsp, 0x20              ; shadow space for ABI

    call ShadowIdtCommonHandler

    add rsp, 0x20

    ; ---------------------------------------------------------
    ; Восстановление регистров
    ; ---------------------------------------------------------
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax

    ; ---------------------------------------------------------
    ; Возврат — AMD SVM возврат через гостевой контекст, RIP
    ; уже обновлён внутри ShadowIdtCommonHandler()
    ; ---------------------------------------------------------
    iretq

ShadowIdtAsmHandler ENDP

END
