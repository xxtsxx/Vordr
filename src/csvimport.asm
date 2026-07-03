; =============================================================================
; csvimport.asm - import password entries from a CSV file into the open vault.
;
;   csv_to_wide(rcx=raw, edx=rawlen, r8=*outwptr, r9=*outwcount) -> eax 0/err
;   csv_import_buffer(rcx=wide ptr, edx=wchar count) -> eax = entries imported
;   gui_import_csv(rcx=hdlg) -> eax = entries imported (drives dialog + reseal)
;
; The parser is RFC-4180-ish: comma-separated, optional double-quoting with ""
; escaping, CR/CRLF/LF row breaks, embedded newlines inside quotes.  The header
; row maps columns to fields by keyword (Chrome / Firefox / Bitwarden / LastPass
; / KeePass exports all work).  Values are compacted and NUL-terminated in place
; in the wide working buffer, then handed to vault_build_entry which copies them.
; =============================================================================

include macros.inc

extern MultiByteToWideChar:proc
extern mem_alloc:proc
extern mem_free:proc
extern vault_build_entry:proc

externdef g_field_list:qword
externdef g_field_n:dword

CP_UTF8_ equ 65001
MAX_FIELDS equ 32               ; matches main.asm g_field_list capacity

.const
; header keywords (lowercase); checked in order, first substring hit wins
kw_username     db "username",0
kw_password     db "password",0
kw_totp         db "totp",0
kw_uri          db "uri",0
kw_url          db "url",0
kw_website      db "website",0
kw_title        db "title",0
kw_login        db "login",0
kw_email        db "email",0
kw_notes        db "notes",0
kw_note         db "note",0
kw_comment      db "comment",0
kw_extra        db "extra",0
kw_otp          db "otp",0
kw_authr        db "authenticator",0
kw_name         db "name",0
kw_account      db "account",0
kw_user         db "user",0
kw_pass         db "pass",0
kw_site         db "site",0
kw_web          db "web",0

.data?
align 8
g_csv_cur       dq ?                     ; parse cursor (wide ptr)
g_csv_end       dq ?                     ; end of the wide buffer
g_csv_eol       dd ?                     ; last cell ended a row (1) / not (0)
g_csv_ncol      dd ?                     ; columns seen in the header
CSV_MAXCOL      equ 64
g_csv_coltype   dd CSV_MAXCOL dup (?)    ; column index -> VF_* (0 = ignore)
g_csv_cells     dq CSV_MAXCOL dup (?)    ; current row's cell pointers

.code

; =============================================================================
; csv_wcontains(rcx = wide haystack, rdx = ascii-lowercase needle) -> eax 1/0
;   case-insensitive substring test.  Leaf.
; =============================================================================
csv_wcontains proc
    mov     r10, rcx
cw_outer:
    movzx   eax, word ptr [r10]
    test    eax, eax
    jz      cw_no
    mov     r8, r10
    mov     r9, rdx
cw_inner:
    movzx   ecx, byte ptr [r9]
    test    ecx, ecx
    jz      cw_yes                              ; needle exhausted -> match
    movzx   eax, word ptr [r8]
    test    eax, eax
    jz      cw_step                             ; haystack ran out here
    cmp     eax, 'A'
    jb      @F
    cmp     eax, 'Z'
    ja      @F
    add     eax, 20h
@@: cmp     eax, ecx
    jne     cw_step
    add     r8, 2
    inc     r9
    jmp     cw_inner
cw_step:
    add     r10, 2
    jmp     cw_outer
cw_yes:
    mov     eax, 1
    ret
cw_no:
    xor     eax, eax
    ret
csv_wcontains endp

; =============================================================================
; csv_hdr_type(rcx = wide header cell) -> eax = VF_* or 0 (ignore)
; =============================================================================
HDRK macro kw, ty
    LOCAL skip
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [kw]
    call    csv_wcontains
    test    eax, eax
    jz      skip
    mov     eax, ty
    FRAME_EPILOG
    ret
skip:
endm

public csv_hdr_type
csv_hdr_type proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-24], rcx
    HDRK kw_username, VF_USERNAME
    HDRK kw_password, VF_SECRET
    HDRK kw_totp,     VF_TOTP
    HDRK kw_uri,      VF_URL
    HDRK kw_url,      VF_URL
    HDRK kw_website,  VF_URL
    HDRK kw_title,    VF_TITLE
    HDRK kw_login,    VF_USERNAME
    HDRK kw_email,    VF_USERNAME
    HDRK kw_notes,    VF_NOTES
    HDRK kw_note,     VF_NOTES
    HDRK kw_comment,  VF_NOTES
    HDRK kw_extra,    VF_NOTES
    HDRK kw_otp,      VF_TOTP
    HDRK kw_authr,    VF_TOTP
    HDRK kw_name,     VF_TITLE
    HDRK kw_account,  VF_TITLE
    HDRK kw_user,     VF_USERNAME
    HDRK kw_pass,     VF_SECRET
    HDRK kw_site,     VF_URL
    HDRK kw_web,      VF_URL
    xor     eax, eax
    FRAME_EPILOG
    ret
csv_hdr_type endp

; =============================================================================
; csv_cell() -> rax = ptr to the NUL-terminated (compacted) cell value.
;   Advances g_csv_cur past the delimiter and sets g_csv_eol (1 if the cell
;   ended the row or the buffer).  Uses g_csv_cur / g_csv_end.  Leaf.
; =============================================================================
csv_cell proc
    mov     r10, qword ptr [g_csv_cur]          ; read ptr
    mov     r11, qword ptr [g_csv_end]
    mov     rax, r10                            ; cell start (default)
    xor     r8d, r8d                            ; quoted?
    cmp     r10, r11
    jae     cc_eol_file
    cmp     word ptr [r10], '"'
    jne     cc_wp
    mov     r8d, 1
    add     r10, 2
    mov     rax, r10                            ; cell starts after the quote
cc_wp:
    mov     r9, rax                             ; write ptr (in-place compaction)
cc_loop:
    cmp     r10, r11
    jae     cc_end                              ; buffer end
    movzx   ecx, word ptr [r10]
    test    r8d, r8d
    jz      cc_plain
    ; inside quotes
    cmp     ecx, '"'
    jne     cc_qcopy
    add     r10, 2                              ; saw a quote
    cmp     r10, r11
    jae     cc_endq                             ; trailing quote at EOF -> close
    cmp     word ptr [r10], '"'
    jne     cc_closeq
    mov     word ptr [r9], '"'                  ; "" -> literal quote
    add     r9, 2
    add     r10, 2
    jmp     cc_loop
cc_closeq:
    xor     r8d, r8d                            ; closing quote; tail is unquoted
    jmp     cc_loop
cc_endq:
    xor     r8d, r8d
    jmp     cc_end
cc_qcopy:
    mov     word ptr [r9], cx
    add     r9, 2
    add     r10, 2
    jmp     cc_loop
cc_plain:
    cmp     ecx, ','
    je      cc_comma
    cmp     ecx, 0Dh
    je      cc_cr
    cmp     ecx, 0Ah
    je      cc_lf
    mov     word ptr [r9], cx
    add     r9, 2
    add     r10, 2
    jmp     cc_loop
cc_comma:
    add     r10, 2
    mov     dword ptr [g_csv_eol], 0
    jmp     cc_fin
cc_cr:
    add     r10, 2
    cmp     r10, r11
    jae     cc_eol_set
    cmp     word ptr [r10], 0Ah
    jne     cc_eol_set
    add     r10, 2                              ; consume the LF of CRLF
    jmp     cc_eol_set
cc_lf:
    add     r10, 2
cc_eol_set:
    mov     dword ptr [g_csv_eol], 1
    jmp     cc_fin
cc_end:
cc_eol_file:
    mov     dword ptr [g_csv_eol], 1
cc_fin:
    mov     word ptr [r9], 0                    ; NUL-terminate the compacted cell
    mov     qword ptr [g_csv_cur], r10
    ret
csv_cell endp

; =============================================================================
; csv_import_buffer(rcx = wide ptr, edx = wchar count) -> eax = imported count
; =============================================================================
public csv_import_buffer
csv_import_buffer proc frame
    FRAME_PROLOG 96
    mov     qword ptr [g_csv_cur], rcx
    mov     eax, edx
    shl     rax, 1
    add     rax, rcx
    mov     qword ptr [g_csv_end], rax
    mov     dword ptr [rbp-24], 0               ; imported count
    ; ---- header row -> coltype[] ----
    mov     dword ptr [rbp-28], 0               ; col
cib_hdr:
    mov     rax, qword ptr [g_csv_cur]
    cmp     rax, qword ptr [g_csv_end]
    jae     cib_hdrdone
    call    csv_cell
    mov     rcx, rax
    call    csv_hdr_type
    mov     ecx, dword ptr [rbp-28]
    cmp     ecx, CSV_MAXCOL
    jae     cib_hdrnext
    lea     r10, [g_csv_coltype]
    mov     dword ptr [r10+rcx*4], eax
cib_hdrnext:
    inc     dword ptr [rbp-28]
    cmp     dword ptr [g_csv_eol], 0
    je      cib_hdr
cib_hdrdone:
    mov     eax, dword ptr [rbp-28]
    mov     dword ptr [g_csv_ncol], eax
    ; ensure at least one TITLE column; else force column 0 to TITLE
    xor     ecx, ecx
    lea     r10, [g_csv_coltype]
cib_ttl:
    cmp     ecx, dword ptr [g_csv_ncol]
    jae     cib_notitle
    cmp     dword ptr [r10+rcx*4], VF_TITLE
    je      cib_rows
    inc     ecx
    jmp     cib_ttl
cib_notitle:
    lea     r10, [g_csv_coltype]
    mov     dword ptr [r10], VF_TITLE
    ; ---- data rows ----
cib_rows:
    mov     rax, qword ptr [g_csv_cur]
    cmp     rax, qword ptr [g_csv_end]
    jae     cib_done
    mov     dword ptr [rbp-28], 0               ; col
    mov     dword ptr [rbp-32], 0               ; rowempty flag (0 = has content)
cib_row:
    call    csv_cell
    mov     ecx, dword ptr [rbp-28]
    cmp     ecx, CSV_MAXCOL
    jae     cib_rowskip
    lea     r10, [g_csv_cells]
    mov     qword ptr [r10+rcx*8], rax
    cmp     word ptr [rax], 0                   ; non-empty cell -> row has content
    je      cib_rowskip
    mov     dword ptr [rbp-32], 1
cib_rowskip:
    inc     dword ptr [rbp-28]
    cmp     dword ptr [g_csv_eol], 0
    je      cib_row
    ; skip blank rows
    cmp     dword ptr [rbp-32], 0
    je      cib_rows
    ; build g_field_list: TITLE first, then other mapped non-empty columns
    mov     dword ptr [rbp-40], 0               ; n (fields)
    ; --- title ---
    mov     dword ptr [rbp-44], -1              ; title column index
    xor     ecx, ecx
cib_findt:
    cmp     ecx, dword ptr [rbp-28]
    jae     cib_haveti
    cmp     ecx, dword ptr [g_csv_ncol]
    jae     cib_haveti
    lea     r10, [g_csv_coltype]
    cmp     dword ptr [r10+rcx*4], VF_TITLE
    jne     cib_findt_n
    lea     r10, [g_csv_cells]
    mov     rax, qword ptr [r10+rcx*8]
    cmp     word ptr [rax], 0
    je      cib_findt_n
    mov     dword ptr [rbp-44], ecx
    jmp     cib_haveti
cib_findt_n:
    inc     ecx
    jmp     cib_findt
cib_haveti:
    cmp     dword ptr [rbp-44], 0
    jl      cib_fallbackt
    ; add the title field
    mov     ecx, dword ptr [rbp-44]
    lea     r10, [g_csv_cells]
    mov     rax, qword ptr [r10+rcx*8]
    lea     r11, [g_field_list]
    mov     qword ptr [r11+0], VF_TITLE
    mov     qword ptr [r11+8], 0
    mov     qword ptr [r11+16], rax
    mov     dword ptr [rbp-40], 1
    jmp     cib_addrest
cib_fallbackt:
    ; no title-mapped value: use the first non-empty cell as the title
    xor     ecx, ecx
cib_fbt:
    cmp     ecx, dword ptr [rbp-28]
    jae     cib_rows                            ; nothing usable -> skip the row
    lea     r10, [g_csv_cells]
    mov     rax, qword ptr [r10+rcx*8]
    cmp     word ptr [rax], 0
    jne     cib_fbt_use
    inc     ecx
    jmp     cib_fbt
cib_fbt_use:
    mov     dword ptr [rbp-44], ecx             ; treat this column as the title
    lea     r11, [g_field_list]
    mov     qword ptr [r11+0], VF_TITLE
    mov     qword ptr [r11+8], 0
    mov     qword ptr [r11+16], rax
    mov     dword ptr [rbp-40], 1
cib_addrest:
    ; add the remaining mapped, non-empty columns (skip the title column)
    xor     ecx, ecx
cib_ar:
    cmp     ecx, dword ptr [rbp-28]
    jae     cib_build
    cmp     ecx, dword ptr [g_csv_ncol]
    jae     cib_build
    cmp     ecx, dword ptr [rbp-44]
    je      cib_ar_n
    lea     r10, [g_csv_coltype]
    mov     r8d, dword ptr [r10+rcx*4]
    test    r8d, r8d
    jz      cib_ar_n
    cmp     r8d, VF_TITLE                        ; only one title
    je      cib_ar_n
    lea     r10, [g_csv_cells]
    mov     rax, qword ptr [r10+rcx*8]
    cmp     word ptr [rax], 0
    je      cib_ar_n
    mov     r9d, dword ptr [rbp-40]
    cmp     r9d, MAX_FIELDS
    jae     cib_build
    imul    r9d, r9d, 24
    lea     r11, [g_field_list]
    add     r11, r9
    mov     qword ptr [r11+0], r8
    mov     qword ptr [r11+8], 0
    mov     qword ptr [r11+16], rax
    inc     dword ptr [rbp-40]
cib_ar_n:
    inc     ecx
    jmp     cib_ar
cib_build:
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [g_field_n], eax
    call    vault_build_entry
    test    eax, eax
    jnz     cib_rows                            ; build failed -> skip, keep going
    inc     dword ptr [rbp-24]
    jmp     cib_rows
cib_done:
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
csv_import_buffer endp

; =============================================================================
; csv_to_wide(rcx=raw, edx=rawlen, r8=*outwptr, r9=*outwcount) -> eax 0/1(err)
;   Detects a UTF-16LE BOM (uses the buffer in place) or decodes UTF-8 (with or
;   without BOM) into a freshly allocated wide buffer.  Caller frees *outwptr
;   with mem_free((rawlen+1)*2) for the UTF-8 case, or leaves it (points into
;   raw) for UTF-16 - so callers should just free the raw buffer and, if a new
;   wide buffer was allocated, free that too.  g_csv_alloc holds the alloc size
;   (0 = no separate allocation).
; =============================================================================
public g_csv_alloc
.data?
g_csv_alloc     dq ?
.code
public csv_to_wide
csv_to_wide proc frame
    FRAME_PROLOG 112                            ; locals (incl. rbp-64 dst) above the
                                                ; callee shadow region
    mov     qword ptr [rbp-24], rcx             ; raw
    mov     dword ptr [rbp-32], edx             ; rawlen
    mov     qword ptr [rbp-40], r8              ; *outwptr
    mov     qword ptr [rbp-48], r9              ; *outwcount
    mov     qword ptr [g_csv_alloc], 0
    ; UTF-16LE BOM?  FF FE
    cmp     dword ptr [rbp-32], 2
    jb      c2w_utf8
    mov     r10, qword ptr [rbp-24]
    cmp     byte ptr [r10], 0FFh
    jne     c2w_utf8
    cmp     byte ptr [r10+1], 0FEh
    jne     c2w_utf8
    ; already wide: point past the BOM
    mov     rax, qword ptr [rbp-24]
    add     rax, 2
    mov     r11, qword ptr [rbp-40]
    mov     qword ptr [r11], rax
    mov     eax, dword ptr [rbp-32]
    sub     eax, 2
    shr     eax, 1                              ; wchar count
    mov     r11, qword ptr [rbp-48]
    mov     dword ptr [r11], eax
    xor     eax, eax
    FRAME_EPILOG
    ret
c2w_utf8:
    ; skip a UTF-8 BOM (EF BB BF) if present
    mov     r10, qword ptr [rbp-24]
    mov     qword ptr [rbp-56], 0               ; src offset (full qword; read as qword below)
    cmp     dword ptr [rbp-32], 3
    jb      c2w_alloc
    cmp     byte ptr [r10], 0EFh
    jne     c2w_alloc
    cmp     byte ptr [r10+1], 0BBh
    jne     c2w_alloc
    cmp     byte ptr [r10+2], 0BFh
    jne     c2w_alloc
    mov     qword ptr [rbp-56], 3
c2w_alloc:
    mov     eax, dword ptr [rbp-32]
    add     eax, 1
    shl     eax, 1                              ; (rawlen+1)*2 bytes
    mov     ecx, eax
    mov     qword ptr [g_csv_alloc], rcx
    call    mem_alloc
    test    rax, rax
    jz      c2w_err
    mov     qword ptr [rbp-64], rax             ; wide dst
    mov     eax, dword ptr [rbp-32]
    sub     eax, dword ptr [rbp-56]             ; cbMultiByte
    mov     r10, qword ptr [rbp-24]
    add     r10, qword ptr [rbp-56]             ; src + offset
    ; MultiByteToWideChar(CP_UTF8, 0, src, cb, dst, cap)
    mov     r11d, dword ptr [rbp-32]
    add     r11d, 1
    WINCALL MultiByteToWideChar, CP_UTF8_, 0, r10, eax, qword ptr [rbp-64], r11d
    test    eax, eax
    jz      c2w_err2
    mov     r11, qword ptr [rbp-40]
    mov     rcx, qword ptr [rbp-64]
    mov     qword ptr [r11], rcx
    mov     r11, qword ptr [rbp-48]
    mov     dword ptr [r11], eax
    xor     eax, eax
    FRAME_EPILOG
    ret
c2w_err2:
    mov     rcx, qword ptr [rbp-64]
    mov     rdx, qword ptr [g_csv_alloc]
    call    mem_free
    mov     qword ptr [g_csv_alloc], 0
c2w_err:
    mov     eax, 1
    FRAME_EPILOG
    ret
csv_to_wide endp

end
