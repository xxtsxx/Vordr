; =============================================================================
; preview.asm - host the system preview handler for a file (built-in COM).
;   For files whose type registers an IPreviewHandler (e.g. PDF via the default
;   PDF app), this renders the actual page content into a window we provide.
;   The bytes are fed from an in-memory IStream, so no plaintext temp file is
;   needed.  A preview handle is { IPreviewHandler*, IStream* }.
; =============================================================================

include macros.inc

extern CoInitializeEx:proc
extern CoCreateInstance:proc
extern CLSIDFromString:proc
extern RegGetValueW:proc
extern SHCreateMemStream:proc
extern write_file:proc
extern DeleteFileW:proc
extern mem_alloc:proc
extern mem_free:proc

CLSCTX_LOCAL   equ 15h              ; INPROC_SERVER | INPROC_HANDLER | LOCAL_SERVER
RRF_RT_REG_SZ  equ 2h

.data?
align 8
pv_clsid   db 16 dup (?)
pv_guidstr dw 80 dup (?)
pv_subkey  dw 220 dup (?)
pv_cb      dd ?
public g_pv_stage
g_pv_stage dd ?                     ; how far preview_open got (diagnostics)

.const
align 8
hkcr        dq 0FFFFFFFF80000000h    ; HKEY_CLASSES_ROOT (sign-extended)
; "\ShellEx\{8895b1c6-b41f-4c1c-a562-0d564250836f}"  (IPreviewHandler assoc key)
pv_shellex  dw '\','S','h','e','l','l','E','x','\'
            dw '{','8','8','9','5','b','1','c','6','-','b','4','1','f','-'
            dw '4','c','1','c','-','a','5','6','2','-'
            dw '0','d','5','6','4','2','5','0','8','3','6','f','}',0
; IID_IPreviewHandler {8895b1c6-b41f-4c1c-a562-0d564250836f}
IID_IPvH    db 0C6h,0B1h,095h,088h, 1Fh,0B4h, 1Ch,4Ch, 0A5h,62h,0Dh,56h,42h,50h,83h,6Fh
; IID_IInitializeWithStream {b824b49d-22ac-4161-ac8a-9916e8fa3f7f}
IID_IIWS    db 09Dh,0B4h,024h,0B8h, 0ACh,22h, 61h,41h, 0ACh,8Ah,99h,16h,0E8h,0FAh,3Fh,7Fh
; IID_IInitializeWithFile {b7d14566-0509-4cce-a71f-0a554233bd9b}
IID_IIWF    db 066h,45h,0D1h,0B7h, 09h,05h, 0CEh,4Ch, 0A7h,1Fh,0Ah,55h,42h,33h,0BDh,9Bh

.code

; preview_clsid(rcx = ext wide, e.g. ".pdf") -> eax = 1 (pv_clsid filled) / 0.
preview_clsid proc frame
    FRAME_PROLOG 48
    mov     r10, rcx
    lea     r11, [pv_subkey]
    xor     r8d, r8d
pc_ecp:
    mov     ax, word ptr [r10+r8*2]
    mov     word ptr [r11+r8*2], ax
    test    ax, ax
    jz      pc_edone
    inc     r8d
    cmp     r8d, 24
    jb      pc_ecp
pc_edone:
    lea     r10, [pv_shellex]
    xor     r9d, r9d
pc_scp:
    mov     ax, word ptr [r10+r9*2]
    mov     word ptr [r11+r8*2], ax
    test    ax, ax
    jz      pc_sdone
    inc     r8d
    inc     r9d
    jmp     pc_scp
pc_sdone:
    mov     dword ptr [pv_cb], 160              ; bytes cap for the GUID string
    WINCALL RegGetValueW, qword ptr [hkcr], addr pv_subkey, 0, RRF_RT_REG_SZ, 0, \
            addr pv_guidstr, addr pv_cb
    test    eax, eax
    jnz     pc_fail
    WINCALL CLSIDFromString, addr pv_guidstr, addr pv_clsid
    test    eax, eax
    jnz     pc_fail
    mov     eax, 1
    FRAME_EPILOG
    ret
pc_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
preview_clsid endp

; preview_open(rcx=ext wide, rdx=bytes, r8=len, r9=temp path wide) -> rax = handle
;   (or 0).  handle = { IPreviewHandler*, IStream*, tempPathToDelete }.  Tries
;   IInitializeWithStream (in-memory, no temp); if the handler doesn't support it
;   (e.g. the PDF handler), writes the bytes to `temp path` and uses
;   IInitializeWithFile.  preview_close deletes the temp.
; -----------------------------------------------------------------------------
; qword locals used with vtable calls (manual sub rsp,32); FRAME clears the
; 5-arg CoCreateInstance outgoing area.
public preview_open
preview_open proc frame
    FRAME_PROLOG 112
    ; [rbp-24]=ext [rbp-32]=bytes [rbp-40]=len [rbp-48]=temp
    ; [rbp-56]=ph [rbp-64]=stream [rbp-72]=iface [rbp-80]=hr
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     qword ptr [rbp-48], r9
    mov     qword ptr [rbp-56], 0
    mov     qword ptr [rbp-64], 0
    mov     qword ptr [rbp-72], 0
    mov     dword ptr [g_pv_stage], 0
    WINCALL CoInitializeEx, 0, 2
    mov     rcx, qword ptr [rbp-24]
    call    preview_clsid
    test    eax, eax
    jz      po_fail
    mov     dword ptr [g_pv_stage], 1
    WINCALL CoCreateInstance, addr pv_clsid, 0, CLSCTX_LOCAL, addr IID_IPvH, addr rbp-56
    test    eax, eax
    jnz     po_fail
    cmp     qword ptr [rbp-56], 0
    je      po_fail
    mov     dword ptr [g_pv_stage], 2
    ; ---- attempt IInitializeWithStream ----
    mov     rcx, qword ptr [rbp-32]
    mov     edx, dword ptr [rbp-40]
    call    SHCreateMemStream
    test    rax, rax
    jz      po_fileinit
    mov     qword ptr [rbp-64], rax
    mov     rcx, qword ptr [rbp-56]
    lea     rdx, [IID_IIWS]
    lea     r8, [rbp-72]
    mov     rax, qword ptr [rcx]
    mov     rax, qword ptr [rax]
    sub     rsp, 32
    call    rax
    add     rsp, 32
    test    eax, eax
    jnz     po_streamfail
    cmp     qword ptr [rbp-72], 0
    je      po_streamfail
    mov     rcx, qword ptr [rbp-72]                  ; iface->Initialize(stream, 0)
    mov     rdx, qword ptr [rbp-64]
    xor     r8d, r8d
    mov     rax, qword ptr [rcx]
    mov     rax, qword ptr [rax+24]
    sub     rsp, 32
    call    rax
    add     rsp, 32
    mov     qword ptr [rbp-80], rax
    call    pv_relface
    cmp     qword ptr [rbp-80], 0
    jne     po_streamfail
    mov     dword ptr [g_pv_stage], 5               ; stream-initialized
    jmp     po_alloc                                ; handle {ph, stream, 0}
po_streamfail:
    call    pv_relface
    mov     rcx, qword ptr [rbp-64]                  ; release + clear the stream
    test    rcx, rcx
    jz      po_fileinit
    mov     rax, qword ptr [rcx]
    mov     rax, qword ptr [rax+16]
    sub     rsp, 32
    call    rax
    add     rsp, 32
    mov     qword ptr [rbp-64], 0
po_fileinit:
    ; ---- fall back to IInitializeWithFile via a temp file ----
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, qword ptr [rbp-32]
    mov     r8, qword ptr [rbp-40]
    call    write_file
    test    eax, eax
    jnz     po_deltemp
    mov     rcx, qword ptr [rbp-56]
    lea     rdx, [IID_IIWF]
    lea     r8, [rbp-72]
    mov     rax, qword ptr [rcx]
    mov     rax, qword ptr [rax]
    sub     rsp, 32
    call    rax
    add     rsp, 32
    test    eax, eax
    jnz     po_deltemp
    cmp     qword ptr [rbp-72], 0
    je      po_deltemp
    mov     rcx, qword ptr [rbp-72]                  ; iface->Initialize(temp, 0)
    mov     rdx, qword ptr [rbp-48]
    xor     r8d, r8d
    mov     rax, qword ptr [rcx]
    mov     rax, qword ptr [rax+24]
    sub     rsp, 32
    call    rax
    add     rsp, 32
    mov     qword ptr [rbp-80], rax
    call    pv_relface
    cmp     qword ptr [rbp-80], 0
    jne     po_deltemp
    mov     dword ptr [g_pv_stage], 6               ; file-initialized
    mov     rcx, 24                                 ; handle {ph, 0, temp}
    call    mem_alloc
    test    rax, rax
    jz      po_deltemp
    mov     r10, qword ptr [rbp-56]
    mov     qword ptr [rax], r10
    mov     qword ptr [rax+8], 0
    mov     r10, qword ptr [rbp-48]
    mov     qword ptr [rax+16], r10
    FRAME_EPILOG
    ret
po_alloc:
    mov     rcx, 24
    call    mem_alloc
    test    rax, rax
    jz      po_relall
    mov     r10, qword ptr [rbp-56]
    mov     qword ptr [rax], r10
    mov     r10, qword ptr [rbp-64]
    mov     qword ptr [rax+8], r10
    mov     qword ptr [rax+16], 0
    FRAME_EPILOG
    ret
po_deltemp:
    WINCALL DeleteFileW, qword ptr [rbp-48]
po_relall:
    mov     rcx, qword ptr [rbp-64]
    test    rcx, rcx
    jz      po_relph
    mov     rax, qword ptr [rcx]
    mov     rax, qword ptr [rax+16]
    sub     rsp, 32
    call    rax
    add     rsp, 32
po_relph:
    mov     rcx, qword ptr [rbp-56]
    test    rcx, rcx
    jz      po_fail
    mov     rax, qword ptr [rcx]
    mov     rax, qword ptr [rax+16]
    sub     rsp, 32
    call    rax
    add     rsp, 32
po_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
preview_open endp

; pv_relface - Release the iface in [rbp-72] of the CALLER's frame and zero it.
;   (helper used only by preview_open; relies on rbp being preview_open's.)
pv_relface proc
    mov     rcx, qword ptr [rbp-72]
    test    rcx, rcx
    jz      prf_done
    mov     rax, qword ptr [rcx]
    mov     rax, qword ptr [rax+16]
    sub     rsp, 40
    call    rax
    add     rsp, 40
    mov     qword ptr [rbp-72], 0
prf_done:
    ret
pv_relface endp

; preview_show(rcx = handle, rdx = hwnd, r8 = *rect) - SetWindow + DoPreview.
public preview_show
preview_show proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    test    rcx, rcx
    jz      ps_done
    mov     r10, qword ptr [rcx]                ; ph
    mov     qword ptr [rbp-32], r10
    mov     qword ptr [rbp-40], rdx             ; hwnd
    mov     qword ptr [rbp-48], r8              ; rect
    ; ph->SetWindow(hwnd, rect)  vtable[3]
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [rbp-40]
    mov     r8, qword ptr [rbp-48]
    mov     rax, qword ptr [rcx]
    mov     rax, qword ptr [rax+24]
    sub     rsp, 32
    call    rax
    add     rsp, 32
    ; ph->DoPreview()  vtable[5]
    mov     rcx, qword ptr [rbp-32]
    mov     rax, qword ptr [rcx]
    mov     rax, qword ptr [rax+40]
    sub     rsp, 32
    call    rax
    add     rsp, 32
ps_done:
    FRAME_EPILOG
    ret
preview_show endp

; preview_setrect(rcx = handle, rdx = *rect) - IPreviewHandler::SetRect (vtable[4]).
public preview_setrect
preview_setrect proc frame
    FRAME_PROLOG 32
    test    rcx, rcx
    jz      pr_done
    mov     r10, qword ptr [rcx]                ; ph
    mov     rcx, r10
    mov     rax, qword ptr [rcx]
    mov     rax, qword ptr [rax+32]
    sub     rsp, 32
    call    rax
    add     rsp, 32
pr_done:
    FRAME_EPILOG
    ret
preview_setrect endp

; preview_close(rcx = handle) - Unload + Release the handler and the stream, free.
public preview_close
preview_close proc frame
    FRAME_PROLOG 48
    test    rcx, rcx
    jz      px_done
    mov     qword ptr [rbp-24], rcx
    mov     rcx, qword ptr [rcx]                ; ph
    test    rcx, rcx
    jz      px_stream
    mov     qword ptr [rbp-32], rcx
    mov     rax, qword ptr [rcx]                ; ph->Unload() vtable[6]
    mov     rax, qword ptr [rax+48]
    sub     rsp, 32
    call    rax
    add     rsp, 32
    mov     rcx, qword ptr [rbp-32]             ; ph->Release() vtable[2]
    mov     rax, qword ptr [rcx]
    mov     rax, qword ptr [rax+16]
    sub     rsp, 32
    call    rax
    add     rsp, 32
px_stream:
    mov     r10, qword ptr [rbp-24]
    mov     rcx, qword ptr [r10+8]              ; stream
    test    rcx, rcx
    jz      px_free
    mov     rax, qword ptr [rcx]
    mov     rax, qword ptr [rax+16]
    sub     rsp, 32
    call    rax
    add     rsp, 32
px_free:
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, 16
    call    mem_free
px_done:
    FRAME_EPILOG
    ret
preview_close endp

end
