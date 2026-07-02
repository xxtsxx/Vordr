; =============================================================================
; xlexport.asm - build a plaintext OOXML .xlsx (STORE-method ZIP) from the
;   currently-unlocked vault.  Stage 1 of the encrypted-Excel export: this
;   produces the raw spreadsheet package; agile encryption wraps it later.
;
;   xl_build_xlsx() -> eax = 0 ok / 1 error; on success g_xlsx_ptr/g_xlsx_len
;                      point at the finished ZIP in a locked buffer.
;   xl_free()        - wipe + release the export buffers.
;
; Columns: Title | Username | Password | URL | Notes | TOTP, one row per entry,
; emitted as inline strings (no shared-string table).  Values are the vault's
; UTF-8 bytes, XML-escaped.
; =============================================================================

include macros.inc

extern secmem_alloc:proc
extern secmem_free:proc
extern vault_count:proc
extern vault_field_at:proc

XL_BUFCAP equ 16*1024*1024          ; 16 MiB each for part + zip scratch
XL_ZIP_MIN equ 4224                  ; pad tiny packages past the 4096 OLE
                                    ; mini-stream cutoff (keep EncryptedPackage
                                    ; a regular stream); see zip_finish

.data?
align 8
g_partbuf   dq 3 dup (?)            ; {ptr, len, cap} - current XML part being built
g_zipbuf    dq 3 dup (?)            ; {ptr, len, cap} - the growing ZIP output
g_xl_flen   dq ?                    ; scratch: a field value length
g_cd        db 8*24 dup (?)         ; central-directory records (crc,len,off,namelen,nameptr)
public g_xlsx_ptr, g_xlsx_len
g_xlsx_ptr  dq ?
g_xlsx_len  dq ?
g_cd_n      dd ?
g_xl_row    dd ?
g_xl_cnt    dd ?
g_xl_err    db ?

.const
; ---- fixed OOXML parts (single-quote delimiters so the XML's " are literal) --
ct_xml  db '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        db '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        db '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        db '<Default Extension="xml" ContentType="application/xml"/>'
        db '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        db '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        db '</Types>',0
rels_xml db '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        db '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        db '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        db '</Relationships>',0
wb_xml  db '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        db '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        db '<sheets><sheet name="Secrets" sheetId="1" r:id="rId1"/></sheets></workbook>',0
wbr_xml db '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        db '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        db '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        db '</Relationships>',0
sheet_hdr db '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        db '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>',0
sheet_ftr db '</sheetData></worksheet>',0
row_pre  db '<row r="',0
row_pre2 db '">',0
row_post db '</row>',0
cell_pre1 db '<c r="',0
cell_pre2 db '" t="inlineStr"><is><t xml:space="preserve">',0
cell_post db '</t></is></c>',0
xml_amp  db '&amp;',0
xml_lt   db '&lt;',0
xml_gt   db '&gt;',0
colletters db 'ABCDEF'
coltypes db VF_TITLE, VF_USERNAME, VF_SECRET, VF_URL, VF_NOTES, VF_TOTP
hdr_title db 'Title',0
hdr_user  db 'Username',0
hdr_pass  db 'Password',0
hdr_url   db 'URL',0
hdr_notes db 'Notes',0
hdr_totp  db 'TOTP',0
name_ct   db '[Content_Types].xml'
name_rels db '_rels/.rels'
name_wb   db 'xl/workbook.xml'
name_wbr  db 'xl/_rels/workbook.xml.rels'
name_sheet db 'xl/worksheets/sheet1.xml'

.code

public buf_putb, buf_putn, buf_pu16, buf_pu32, buf_pu64, buf_putcstr, buf_pu32dec
public buf_zero, xl_crc32, g_xl_err

; ---- buffer append primitives (descriptor = {qword ptr, qword len, qword cap}) --
; buf_putb(rcx=desc, dl=byte)                                                  leaf
buf_putb proc
    mov     rax, qword ptr [rcx+8]
    cmp     rax, qword ptr [rcx+16]
    jae     bpb_over
    mov     r10, qword ptr [rcx]
    mov     byte ptr [r10+rax], dl
    inc     qword ptr [rcx+8]
    ret
bpb_over:
    mov     byte ptr [g_xl_err], 1
    ret
buf_putb endp

; buf_putn(rcx=desc, rdx=src, r8=len)                                          leaf
buf_putn proc
    test    r8, r8
    jz      bpn_ret
    mov     rax, qword ptr [rcx+8]
    mov     r9, rax
    add     r9, r8
    cmp     r9, qword ptr [rcx+16]
    ja      bpn_over
    mov     r10, qword ptr [rcx]
    add     r10, rax
    xor     r11, r11
bpn_lp:
    mov     r9b, byte ptr [rdx+r11]
    mov     byte ptr [r10+r11], r9b
    inc     r11
    cmp     r11, r8
    jb      bpn_lp
    add     qword ptr [rcx+8], r8
bpn_ret:
    ret
bpn_over:
    mov     byte ptr [g_xl_err], 1
    ret
buf_putn endp

; buf_pu16(rcx=desc, edx=val)                                                  leaf
buf_pu16 proc
    mov     rax, qword ptr [rcx+8]
    mov     r9, rax
    add     r9, 2
    cmp     r9, qword ptr [rcx+16]
    ja      bp16_over
    mov     r10, qword ptr [rcx]
    mov     byte ptr [r10+rax], dl
    shr     edx, 8
    mov     byte ptr [r10+rax+1], dl
    add     qword ptr [rcx+8], 2
    ret
bp16_over:
    mov     byte ptr [g_xl_err], 1
    ret
buf_pu16 endp

; buf_pu32(rcx=desc, edx=val)                                                  leaf
buf_pu32 proc
    mov     rax, qword ptr [rcx+8]
    mov     r9, rax
    add     r9, 4
    cmp     r9, qword ptr [rcx+16]
    ja      bp32_over
    mov     r10, qword ptr [rcx]
    mov     byte ptr [r10+rax], dl
    shr     edx, 8
    mov     byte ptr [r10+rax+1], dl
    shr     edx, 8
    mov     byte ptr [r10+rax+2], dl
    shr     edx, 8
    mov     byte ptr [r10+rax+3], dl
    add     qword ptr [rcx+8], 4
    ret
bp32_over:
    mov     byte ptr [g_xl_err], 1
    ret
buf_pu32 endp

; buf_pu64(rcx=desc, rdx=val)                                                  leaf
buf_pu64 proc
    mov     rax, qword ptr [rcx+8]
    mov     r9, rax
    add     r9, 8
    cmp     r9, qword ptr [rcx+16]
    ja      bp64_over
    mov     r10, qword ptr [rcx]
    mov     qword ptr [r10+rax], rdx
    add     qword ptr [rcx+8], 8
    ret
bp64_over:
    mov     byte ptr [g_xl_err], 1
    ret
buf_pu64 endp

; buf_zero(rcx=desc, rdx=count) - append count zero bytes                      leaf
buf_zero proc
    test    rdx, rdx
    jz      bz_ret
    mov     rax, qword ptr [rcx+8]
    mov     r9, rax
    add     r9, rdx
    cmp     r9, qword ptr [rcx+16]
    ja      bz_over
    mov     r10, qword ptr [rcx]
    add     r10, rax
    xor     r11, r11
bz_lp:
    mov     byte ptr [r10+r11], 0
    inc     r11
    cmp     r11, rdx
    jb      bz_lp
    add     qword ptr [rcx+8], rdx
bz_ret:
    ret
bz_over:
    mov     byte ptr [g_xl_err], 1
    ret
buf_zero endp

; buf_putcstr(rcx=desc, rdx=cstr)                                              leaf
buf_putcstr proc
bpc_lp:
    mov     r8b, byte ptr [rdx]
    test    r8b, r8b
    jz      bpc_ret
    mov     rax, qword ptr [rcx+8]
    cmp     rax, qword ptr [rcx+16]
    jae     bpc_over
    mov     r10, qword ptr [rcx]
    mov     byte ptr [r10+rax], r8b
    inc     qword ptr [rcx+8]
    inc     rdx
    jmp     bpc_lp
bpc_ret:
    ret
bpc_over:
    mov     byte ptr [g_xl_err], 1
    ret
buf_putcstr endp

; buf_pu32dec(rcx=desc, edx=val) - append value in decimal
buf_pu32dec proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     eax, edx                         ; value
    lea     r9, [rbp-32]                     ; one past a 16-byte digit scratch
    mov     r8d, 10
    test    eax, eax
    jnz     bpd_lp
    dec     r9
    mov     byte ptr [r9], '0'
    jmp     bpd_emit
bpd_lp:
    xor     edx, edx
    div     r8d
    add     dl, '0'
    dec     r9
    mov     byte ptr [r9], dl
    test    eax, eax
    jnz     bpd_lp
bpd_emit:
    lea     rax, [rbp-32]
    sub     rax, r9                          ; length
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, r9
    mov     r8, rax
    call    buf_putn
    FRAME_EPILOG
    ret
buf_pu32dec endp

; buf_putxml(rcx=desc, rdx=src, r8=len) - append with &,<,> escaped; drop illegal
;   control chars (< 0x20 except tab/lf/cr)
buf_putxml proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     qword ptr [rbp-48], 0            ; i
bx_lp:
    mov     rax, qword ptr [rbp-48]
    cmp     rax, qword ptr [rbp-40]
    jae     bx_done
    mov     r10, qword ptr [rbp-32]
    movzx   edx, byte ptr [r10+rax]
    cmp     dl, '&'
    je      bx_amp
    cmp     dl, '<'
    je      bx_lt
    cmp     dl, '>'
    je      bx_gt
    cmp     dl, 20h
    jae     bx_normal
    cmp     dl, 9
    je      bx_normal
    cmp     dl, 10
    je      bx_normal
    cmp     dl, 13
    je      bx_normal
    jmp     bx_next                          ; illegal control char -> drop
bx_normal:
    mov     rcx, qword ptr [rbp-24]
    call    buf_putb
    jmp     bx_next
bx_amp:
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [xml_amp]
    call    buf_putcstr
    jmp     bx_next
bx_lt:
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [xml_lt]
    call    buf_putcstr
    jmp     bx_next
bx_gt:
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [xml_gt]
    call    buf_putcstr
bx_next:
    inc     qword ptr [rbp-48]
    jmp     bx_lp
bx_done:
    FRAME_EPILOG
    ret
buf_putxml endp

; ---- CRC-32 (IEEE, reflected) -----------------------------------------------
; xl_crc32(rcx=data, edx=len) -> eax  (name avoids the SSE4.2 crc32 mnemonic)  leaf
xl_crc32 proc
    mov     r8d, 0FFFFFFFFh
    mov     r11d, edx
    test    r11d, r11d
    jz      crc_done
    xor     r9, r9
crc_byte:
    movzx   eax, byte ptr [rcx+r9]
    xor     r8d, eax
    mov     r10d, 8
crc_bit:
    test    r8d, 1
    jz      crc_shr
    shr     r8d, 1
    xor     r8d, 0EDB88320h
    jmp     crc_bend
crc_shr:
    shr     r8d, 1
crc_bend:
    dec     r10d
    jnz     crc_bit
    inc     r9
    cmp     r9, r11
    jb      crc_byte
crc_done:
    mov     eax, r8d
    not     eax
    ret
xl_crc32 endp

; ---- ZIP (STORE) writer -----------------------------------------------------
; helper macros appending to the zip buffer
ZP16 macro v
    lea     rcx, [g_zipbuf]
    mov     edx, v
    call    buf_pu16
endm
ZP32 macro v
    lea     rcx, [g_zipbuf]
    mov     edx, v
    call    buf_pu32
endm

; zip_add(rcx=nameptr, rdx=namelen) - append the current g_partbuf as a stored entry
zip_add proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=nameptr [rbp-32]=namelen [rbp-40]=offset [rbp-48]=crc [rbp-56]=partlen
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    lea     r10, [g_zipbuf]
    mov     rax, qword ptr [r10+8]
    mov     qword ptr [rbp-40], rax              ; local-header offset
    lea     r10, [g_partbuf]
    mov     rax, qword ptr [r10+8]
    mov     qword ptr [rbp-56], rax              ; part length
    lea     r10, [g_partbuf]
    mov     rcx, qword ptr [r10]
    mov     edx, dword ptr [r10+8]
    call    xl_crc32
    mov     dword ptr [rbp-48], eax              ; crc
    ; local file header
    ZP32    04034b50h
    ZP16    20
    ZP16    0
    ZP16    0                                    ; method STORE
    ZP16    0                                    ; modtime
    ZP16    021h                                 ; moddate 1980-01-01
    ZP32    dword ptr [rbp-48]                   ; crc
    ZP32    dword ptr [rbp-56]                   ; comp size
    ZP32    dword ptr [rbp-56]                   ; uncomp size
    ZP16    dword ptr [rbp-32]                   ; name length
    ZP16    0                                    ; extra length
    lea     rcx, [g_zipbuf]
    mov     rdx, qword ptr [rbp-24]
    mov     r8, qword ptr [rbp-32]
    call    buf_putn                             ; name
    lea     rcx, [g_zipbuf]
    lea     r10, [g_partbuf]
    mov     rdx, qword ptr [r10]
    mov     r8, qword ptr [rbp-56]
    call    buf_putn                             ; stored data
    ; record the central-directory entry
    mov     eax, dword ptr [g_cd_n]
    imul    eax, eax, 24
    lea     r10, [g_cd]
    add     r10, rax
    mov     ecx, dword ptr [rbp-48]
    mov     dword ptr [r10+0], ecx               ; crc
    mov     ecx, dword ptr [rbp-56]
    mov     dword ptr [r10+4], ecx               ; size
    mov     ecx, dword ptr [rbp-40]
    mov     dword ptr [r10+8], ecx               ; offset
    mov     ecx, dword ptr [rbp-32]
    mov     dword ptr [r10+12], ecx              ; name length
    mov     rcx, qword ptr [rbp-24]
    mov     qword ptr [r10+16], rcx              ; name pointer
    inc     dword ptr [g_cd_n]
    FRAME_EPILOG
    ret
zip_add endp

; zip_finish() - write the central directory + end-of-central-directory record
zip_finish proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=cd_offset [rbp-32]=i [rbp-40]=recptr [rbp-48]=cd_size
    lea     r10, [g_zipbuf]
    mov     rax, qword ptr [r10+8]
    mov     qword ptr [rbp-24], rax              ; central-dir start offset
    mov     dword ptr [rbp-32], 0
zf_lp:
    mov     eax, dword ptr [rbp-32]
    cmp     eax, dword ptr [g_cd_n]
    jae     zf_eocd
    imul    eax, eax, 24
    lea     r10, [g_cd]
    add     r10, rax
    mov     qword ptr [rbp-40], r10
    ZP32    02014b50h
    ZP16    20                                   ; version made by
    ZP16    20                                   ; version needed
    ZP16    0
    ZP16    0                                    ; method STORE
    ZP16    0
    ZP16    021h
    mov     r10, qword ptr [rbp-40]
    ZP32    dword ptr [r10+0]                     ; crc
    mov     r10, qword ptr [rbp-40]
    ZP32    dword ptr [r10+4]                     ; comp size
    mov     r10, qword ptr [rbp-40]
    ZP32    dword ptr [r10+4]                     ; uncomp size
    mov     r10, qword ptr [rbp-40]
    ZP16    dword ptr [r10+12]                    ; name length
    ZP16    0                                    ; extra
    ZP16    0                                    ; comment
    ZP16    0                                    ; disk number
    ZP16    0                                    ; internal attrs
    ZP32    0                                    ; external attrs
    mov     r10, qword ptr [rbp-40]
    ZP32    dword ptr [r10+8]                     ; local-header offset
    lea     rcx, [g_zipbuf]
    mov     r10, qword ptr [rbp-40]
    mov     rdx, qword ptr [r10+16]              ; name ptr
    mov     r8d, dword ptr [r10+12]              ; name len
    call    buf_putn
    inc     dword ptr [rbp-32]
    jmp     zf_lp
zf_eocd:
    lea     r10, [g_zipbuf]
    mov     rax, qword ptr [r10+8]
    sub     rax, qword ptr [rbp-24]
    mov     qword ptr [rbp-48], rax              ; central-dir size
    ; Pad the package via the (ignored) EOCD comment so the encrypted stream
    ; stays >= 4096 bytes.  OLE streams smaller than the 4096 mini-stream cutoff
    ; must be stored in the mini stream, but EncryptedPackage is always written
    ; as a regular stream; a small vault would otherwise land under the cutoff
    ; and Excel would read the package from the wrong place -> "corrupt".
    lea     r10, [g_zipbuf]
    mov     rax, qword ptr [r10+8]               ; current length
    add     rax, 22                              ; + the fixed EOCD record
    xor     edx, edx                             ; padN = 0
    cmp     rax, XL_ZIP_MIN
    jae     zf_padset
    mov     edx, XL_ZIP_MIN
    sub     edx, eax                             ; padN = target - projected
zf_padset:
    mov     dword ptr [rbp-56], edx              ; padN (comment length)
    ZP32    06054b50h
    ZP16    0
    ZP16    0
    ZP16    dword ptr [g_cd_n]                    ; entries this disk
    ZP16    dword ptr [g_cd_n]                    ; entries total
    ZP32    dword ptr [rbp-48]                    ; cd size
    ZP32    dword ptr [rbp-24]                    ; cd offset
    ZP16    dword ptr [rbp-56]                    ; comment length = padN
    cmp     dword ptr [rbp-56], 0
    je      zf_done
    lea     rcx, [g_zipbuf]                       ; append padN zero bytes
    mov     edx, dword ptr [rbp-56]
    call    buf_zero
zf_done:
    FRAME_EPILOG
    ret
zip_finish endp

; ---- worksheet ---------------------------------------------------------------
; emit_cell_c(rcx=desc, edx=colidx, r8=cstr) - header cell (literal, no escape)
emit_cell_c proc frame
    FRAME_PROLOG 96                          ; keep locals above callees' shadow (FRAME procs called)
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     qword ptr [rbp-40], r8
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [cell_pre1]
    call    buf_putcstr
    mov     rcx, qword ptr [rbp-24]
    mov     eax, dword ptr [rbp-32]
    lea     r10, [colletters]
    mov     dl, byte ptr [r10+rax]
    call    buf_putb
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [g_xl_row]
    call    buf_pu32dec
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [cell_pre2]
    call    buf_putcstr
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-40]
    call    buf_putcstr
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [cell_post]
    call    buf_putcstr
    FRAME_EPILOG
    ret
emit_cell_c endp

; emit_cell(rcx=desc, edx=colidx, r8=valptr, r9=vallen) - data cell; skip if 0
emit_cell proc frame
    FRAME_PROLOG 96                          ; keep locals above callees' shadow (FRAME procs called)
    test    r8, r8
    jz      ec_ret
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     qword ptr [rbp-40], r8
    mov     qword ptr [rbp-48], r9
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [cell_pre1]
    call    buf_putcstr
    mov     rcx, qword ptr [rbp-24]
    mov     eax, dword ptr [rbp-32]
    lea     r10, [colletters]
    mov     dl, byte ptr [r10+rax]
    call    buf_putb
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [g_xl_row]
    call    buf_pu32dec
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [cell_pre2]
    call    buf_putcstr
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-40]
    mov     r8, qword ptr [rbp-48]
    call    buf_putxml
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [cell_post]
    call    buf_putcstr
ec_ret:
    FRAME_EPILOG
    ret
emit_cell endp

; xl_build_sheet() - build sheet1.xml into g_partbuf from the unlocked vault
xl_build_sheet proc frame
    FRAME_PROLOG 48
    lea     rcx, [g_partbuf]
    lea     rdx, [sheet_hdr]
    call    buf_putcstr
    ; header row 1
    mov     dword ptr [g_xl_row], 1
    lea     rcx, [g_partbuf]
    lea     rdx, [row_pre]
    call    buf_putcstr
    lea     rcx, [g_partbuf]
    mov     edx, 1
    call    buf_pu32dec
    lea     rcx, [g_partbuf]
    lea     rdx, [row_pre2]
    call    buf_putcstr
    lea     rcx, [g_partbuf]
    mov     edx, 0
    lea     r8, [hdr_title]
    call    emit_cell_c
    lea     rcx, [g_partbuf]
    mov     edx, 1
    lea     r8, [hdr_user]
    call    emit_cell_c
    lea     rcx, [g_partbuf]
    mov     edx, 2
    lea     r8, [hdr_pass]
    call    emit_cell_c
    lea     rcx, [g_partbuf]
    mov     edx, 3
    lea     r8, [hdr_url]
    call    emit_cell_c
    lea     rcx, [g_partbuf]
    mov     edx, 4
    lea     r8, [hdr_notes]
    call    emit_cell_c
    lea     rcx, [g_partbuf]
    mov     edx, 5
    lea     r8, [hdr_totp]
    call    emit_cell_c
    lea     rcx, [g_partbuf]
    lea     rdx, [row_post]
    call    buf_putcstr
    ; data rows
    call    vault_count
    mov     dword ptr [g_xl_cnt], eax
    mov     dword ptr [rbp-24], 0                ; i
bs_row:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_xl_cnt]
    jae     bs_done
    mov     eax, dword ptr [rbp-24]
    add     eax, 2
    mov     dword ptr [g_xl_row], eax
    lea     rcx, [g_partbuf]
    lea     rdx, [row_pre]
    call    buf_putcstr
    lea     rcx, [g_partbuf]
    mov     edx, dword ptr [g_xl_row]
    call    buf_pu32dec
    lea     rcx, [g_partbuf]
    lea     rdx, [row_pre2]
    call    buf_putcstr
    mov     dword ptr [rbp-32], 0                ; c
bs_col:
    mov     eax, dword ptr [rbp-32]
    cmp     eax, 6
    jae     bs_colend
    lea     r10, [coltypes]
    mov     eax, dword ptr [rbp-32]
    movzx   edx, byte ptr [r10+rax]              ; field type
    mov     ecx, dword ptr [rbp-24]              ; entry index
    lea     r8, [g_xl_flen]
    call    vault_field_at                       ; rax = valptr, [g_xl_flen] = len
    lea     rcx, [g_partbuf]
    mov     edx, dword ptr [rbp-32]
    mov     r8, rax
    mov     r9, qword ptr [g_xl_flen]
    call    emit_cell
    inc     dword ptr [rbp-32]
    jmp     bs_col
bs_colend:
    lea     rcx, [g_partbuf]
    lea     rdx, [row_post]
    call    buf_putcstr
    inc     dword ptr [rbp-24]
    jmp     bs_row
bs_done:
    lea     rcx, [g_partbuf]
    lea     rdx, [sheet_ftr]
    call    buf_putcstr
    FRAME_EPILOG
    ret
xl_build_sheet endp

; reset the part buffer to empty
XLRESET macro
    lea     r10, [g_partbuf]
    mov     qword ptr [r10+8], 0
endm

; =============================================================================
; xl_build_xlsx() -> eax = 0 ok / 1 error
; =============================================================================
public xl_build_xlsx
xl_build_xlsx proc frame
    FRAME_PROLOG 48
    mov     byte ptr [g_xl_err], 0
    mov     dword ptr [g_cd_n], 0
    ; allocate the two locked scratch buffers
    mov     rcx, XL_BUFCAP
    call    secmem_alloc
    test    rax, rax
    jz      xb_fail
    lea     r10, [g_zipbuf]
    mov     qword ptr [r10], rax
    mov     qword ptr [r10+8], 0
    mov     qword ptr [r10+16], XL_BUFCAP
    mov     rcx, XL_BUFCAP
    call    secmem_alloc
    test    rax, rax
    jz      xb_fail
    lea     r10, [g_partbuf]
    mov     qword ptr [r10], rax
    mov     qword ptr [r10+8], 0
    mov     qword ptr [r10+16], XL_BUFCAP
    ; part 1: [Content_Types].xml
    XLRESET
    lea     rcx, [g_partbuf]
    lea     rdx, [ct_xml]
    call    buf_putcstr
    lea     rcx, [name_ct]
    mov     rdx, 19
    call    zip_add
    ; part 2: _rels/.rels
    XLRESET
    lea     rcx, [g_partbuf]
    lea     rdx, [rels_xml]
    call    buf_putcstr
    lea     rcx, [name_rels]
    mov     rdx, 11
    call    zip_add
    ; part 3: xl/workbook.xml
    XLRESET
    lea     rcx, [g_partbuf]
    lea     rdx, [wb_xml]
    call    buf_putcstr
    lea     rcx, [name_wb]
    mov     rdx, 15
    call    zip_add
    ; part 4: xl/_rels/workbook.xml.rels
    XLRESET
    lea     rcx, [g_partbuf]
    lea     rdx, [wbr_xml]
    call    buf_putcstr
    lea     rcx, [name_wbr]
    mov     rdx, 26
    call    zip_add
    ; part 5: xl/worksheets/sheet1.xml
    XLRESET
    call    xl_build_sheet
    lea     rcx, [name_sheet]
    mov     rdx, 24
    call    zip_add
    ; finish
    call    zip_finish
    cmp     byte ptr [g_xl_err], 0
    jnz     xb_fail
    lea     r10, [g_zipbuf]
    mov     rax, qword ptr [r10]
    mov     qword ptr [g_xlsx_ptr], rax
    mov     rax, qword ptr [r10+8]
    mov     qword ptr [g_xlsx_len], rax
    xor     eax, eax
    FRAME_EPILOG
    ret
xb_fail:
    call    xl_free
    mov     eax, 1
    FRAME_EPILOG
    ret
xl_build_xlsx endp

; xl_free() - wipe + release the export buffers
public xl_free
xl_free proc frame
    FRAME_PROLOG 48
    lea     r10, [g_partbuf]
    mov     rcx, qword ptr [r10]
    test    rcx, rcx
    jz      xf_zip
    mov     rdx, XL_BUFCAP
    call    secmem_free
    lea     r10, [g_partbuf]
    mov     qword ptr [r10], 0
xf_zip:
    lea     r10, [g_zipbuf]
    mov     rcx, qword ptr [r10]
    test    rcx, rcx
    jz      xf_done
    mov     rdx, XL_BUFCAP
    call    secmem_free
    lea     r10, [g_zipbuf]
    mov     qword ptr [r10], 0
xf_done:
    mov     qword ptr [g_xlsx_ptr], 0
    mov     qword ptr [g_xlsx_len], 0
    FRAME_EPILOG
    ret
xl_free endp

end
