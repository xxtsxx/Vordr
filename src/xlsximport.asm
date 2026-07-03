; =============================================================================
; xlsximport.asm - import entries from an unencrypted .xlsx workbook.
;
; STATUS: WORK IN PROGRESS - deliberately NOT in build.cmd yet.  The zip reader
; + inflate + first-cell parse are validated working (extraction is byte-exact
; vs. the real sheet1.xml; the first cell resolves to column 0 correctly), but
; full row/column parsing has a bug (a header row yields an inflated column
; count) still to be root-caused before this is wired into the GUI.  The
; encrypted-.xlsx path (agile decrypt) is also still to be written.
;
;   xlsx_import(rcx=raw, edx=rawlen) -> eax = entries imported,
;                                       -1 error, -2 encrypted (unsupported here)
;
; Reads the .xlsx (a zip): inflates xl/sharedStrings.xml + the first worksheet,
; parses rows/cells (shared / inline / value strings, XML-unescaped), maps the
; header columns to fields via csv_hdr_type, and appends entries.
; =============================================================================

include macros.inc

extern inflate:proc
extern mem_alloc:proc
extern mem_free:proc
extern MultiByteToWideChar:proc
extern csv_hdr_type:proc
extern vault_build_entry:proc
externdef g_field_list:qword
externdef g_field_n:dword

CP_UTF8_    equ 65001
XI_MAXCOL   equ 64
XI_MAXSS    equ 65536
VF_TITLE_   equ 1

.const
xi_ss_name    db "xl/sharedStrings.xml"
xi_ss_name_n  equ 20
xi_sheet_name db "xl/worksheets/sheet1.xml"
xi_sheet_n    equ 24
t_open        db "<t"
t_close       db "</t>"
v_open        db "<v>"
v_close       db "</v>"
si_open       db "<si"
c_open        db "<c"
c_close       db "</c>"
row_open      db "<r","o","w"
is_tag        db "<is"

.data?
align 8
g_ss_buf      dq 3 dup (?)             ; inflated sharedStrings {ptr,len,cap}
g_sheet_buf   dq 3 dup (?)             ; inflated worksheet     {ptr,len,cap}
g_ss_txt      dq ?                     ; unescaped shared-string storage
g_ss_txt_len  dq ?
g_ss_arr      dq 2*XI_MAXSS dup (?)    ; per-si {ptr(8), len(8)}
g_ss_n        dd ?
g_xl_coltype  dd XI_MAXCOL dup (?)
g_xl_ncol     dd ?
g_xl_cellp    dq XI_MAXCOL dup (?)     ; current row cell ptr
g_xl_celll    dd XI_MAXCOL dup (?)     ; current row cell len
g_xl_rowtxt   db 65536 dup (?)         ; per-row unescaped cell text
g_xl_hdrw     dw 512 dup (?)           ; header cell -> wide (for csv_hdr_type)
g_xl_wide     db XI_MAXCOL*2048 dup (?); per-column wide value buffers

.code

; xi_find(rcx=hay, rdx=hayend, r8=needle, r9d=nlen) -> rax = ptr / 0.  Leaf.
xi_find proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     dword ptr [rbp-44], r9d
xf_lp:
    mov     rax, qword ptr [rbp-32]
    mov     ecx, dword ptr [rbp-44]
    sub     rax, rcx                            ; hayend - nlen
    cmp     qword ptr [rbp-24], rax
    ja      xf_no
    mov     r10, qword ptr [rbp-24]
    mov     r11, qword ptr [rbp-40]
    xor     r8d, r8d
xf_cmp:
    cmp     r8d, dword ptr [rbp-44]
    jae     xf_hit
    mov     al, byte ptr [r10+r8]
    cmp     al, byte ptr [r11+r8]
    jne     xf_next
    inc     r8d
    jmp     xf_cmp
xf_next:
    inc     qword ptr [rbp-24]
    jmp     xf_lp
xf_hit:
    mov     rax, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
xf_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
xi_find endp

; xi_int(rcx=ptr, rdx=end) -> eax = non-negative decimal value (stops at non-digit).
xi_int proc
    xor     eax, eax
xii_lp:
    cmp     rcx, rdx
    jae     xii_d
    movzx   r8d, byte ptr [rcx]
    cmp     r8d, '0'
    jb      xii_d
    cmp     r8d, '9'
    ja      xii_d
    imul    eax, eax, 10
    sub     r8d, '0'
    add     eax, r8d
    inc     rcx
    jmp     xii_lp
xii_d:
    ret
xi_int endp

; xi_col(rcx=ptr, rdx=end) -> eax = 0-based column from the leading A-Z letters.
xi_col proc
    xor     eax, eax
xic_lp:
    cmp     rcx, rdx
    jae     xic_d
    movzx   r8d, byte ptr [rcx]
    cmp     r8d, 'A'
    jb      xic_d
    cmp     r8d, 'Z'
    ja      xic_d
    imul    eax, eax, 26
    sub     r8d, 'A'-1
    add     eax, r8d
    inc     rcx
    jmp     xic_lp
xic_d:
    dec     eax                                 ; make 0-based
    ret
xi_col endp

; xi_unesc(rcx=src, rdx=srcend, r8=dst, r9d=dstcap) -> eax = bytes written.  Leaf.
xi_unesc proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx             ; src
    mov     qword ptr [rbp-32], rdx             ; srcend
    mov     qword ptr [rbp-40], r8              ; dst
    mov     dword ptr [rbp-44], r9d             ; cap
    xor     r10d, r10d                          ; out count
xu_lp:
    mov     rcx, qword ptr [rbp-24]
    cmp     rcx, qword ptr [rbp-32]
    jae     xu_done
    cmp     r10d, dword ptr [rbp-44]
    jae     xu_done
    movzx   eax, byte ptr [rcx]
    cmp     eax, '&'
    jne     xu_plain
    ; entity: read up to ';'
    lea     r11, [rcx+1]
    ; &amp;
    cmp     byte ptr [rcx+1], 'a'
    jne     xu_e_lt
    cmp     byte ptr [rcx+2], 'm'
    jne     xu_e_apos
    mov     al, '&'
    add     qword ptr [rbp-24], 5
    jmp     xu_emit
xu_e_apos:
    ; &apos;
    cmp     byte ptr [rcx+2], 'p'
    jne     xu_plain
    mov     al, 27h
    add     qword ptr [rbp-24], 6
    jmp     xu_emit
xu_e_lt:
    cmp     byte ptr [rcx+1], 'l'
    jne     xu_e_gt
    mov     al, '<'
    add     qword ptr [rbp-24], 4
    jmp     xu_emit
xu_e_gt:
    cmp     byte ptr [rcx+1], 'g'
    jne     xu_e_quot
    mov     al, '>'
    add     qword ptr [rbp-24], 4
    jmp     xu_emit
xu_e_quot:
    cmp     byte ptr [rcx+1], 'q'
    jne     xu_e_num
    mov     al, '"'
    add     qword ptr [rbp-24], 6
    jmp     xu_emit
xu_e_num:
    cmp     byte ptr [rcx+1], '#'
    jne     xu_plain
    ; numeric char ref &#NN; or &#xNN; -> low byte only (best effort)
    lea     rcx, [rcx+2]
    xor     r9d, r9d                            ; value
    cmp     byte ptr [rcx], 'x'
    jne     xu_ndec
    inc     rcx
xu_nhex:
    movzx   eax, byte ptr [rcx]
    cmp     eax, ';'
    je      xu_nend
    ; hex digit
    cmp     eax, '0'
    jb      xu_nend
    cmp     eax, '9'
    jbe     xu_hd
    or      eax, 20h
    sub     eax, 'a'-10
    jmp     xu_hadd
xu_hd:
    sub     eax, '0'
xu_hadd:
    shl     r9d, 4
    add     r9d, eax
    inc     rcx
    jmp     xu_nhex
xu_ndec:
    movzx   eax, byte ptr [rcx]
    cmp     eax, ';'
    je      xu_nend
    cmp     eax, '0'
    jb      xu_nend
    cmp     eax, '9'
    ja      xu_nend
    imul    r9d, r9d, 10
    sub     eax, '0'
    add     r9d, eax
    inc     rcx
    jmp     xu_ndec
xu_nend:
    inc     rcx                                 ; past ';'
    mov     qword ptr [rbp-24], rcx
    mov     eax, r9d                            ; low byte
    jmp     xu_emit
xu_plain:
    inc     qword ptr [rbp-24]
xu_emit:
    mov     r11, qword ptr [rbp-40]
    mov     ecx, r10d
    mov     byte ptr [r11+rcx], al
    inc     r10d
    jmp     xu_lp
xu_done:
    mov     eax, r10d
    FRAME_EPILOG
    ret
xi_unesc endp

; xi_ttext(rcx=from, rdx=to, r8=dst, r9d=dstcap) -> eax = len.  Concatenate the
;   unescaped text of every <t>...</t> in [from,to].
xi_ttext proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx             ; cur
    mov     qword ptr [rbp-32], rdx             ; to
    mov     qword ptr [rbp-40], r8              ; dst
    mov     dword ptr [rbp-48], r9d             ; cap
    mov     dword ptr [rbp-52], 0               ; total
xt_lp:
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [t_open]
    mov     r9d, 2
    call    xi_find
    test    rax, rax
    jz      xt_done
    ; after "<t" the next char must be '>' or ' ' (a real <t> element)
    movzx   ecx, byte ptr [rax+2]
    cmp     ecx, '>'
    je      xt_isopen
    cmp     ecx, ' '
    je      xt_isopen
    lea     rcx, [rax+2]                        ; not a <t> tag - skip past
    mov     qword ptr [rbp-24], rcx
    jmp     xt_lp
xt_isopen:
    ; find '>' then "</t>"
    mov     r10, rax
xt_gt:
    cmp     r10, qword ptr [rbp-32]
    jae     xt_done
    cmp     byte ptr [r10], '>'
    je      xt_gtf
    inc     r10
    jmp     xt_gt
xt_gtf:
    lea     rcx, [r10+1]                        ; text start
    mov     qword ptr [rbp-56], rcx
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [t_close]
    mov     r9d, 4
    call    xi_find
    test    rax, rax
    jz      xt_done
    ; unescape [textstart, rax) into dst+total
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, rax
    mov     r8, qword ptr [rbp-40]
    mov     r9d, dword ptr [rbp-48]
    mov     r11d, dword ptr [rbp-52]
    add     r8, r11
    sub     r9d, r11d
    mov     qword ptr [rbp-64], rax             ; save close ptr
    call    xi_unesc
    add     dword ptr [rbp-52], eax
    mov     rax, qword ptr [rbp-64]
    lea     rcx, [rax+4]                        ; past "</t>"
    mov     qword ptr [rbp-24], rcx
    jmp     xt_lp
xt_done:
    mov     eax, dword ptr [rbp-52]
    FRAME_EPILOG
    ret
xi_ttext endp

; xi_parse_shared() -> builds g_ss_arr / g_ss_n from g_ss_buf.
xi_parse_shared proc frame
    FRAME_PROLOG 64
    mov     dword ptr [g_ss_n], 0
    lea     r10, [g_ss_buf]
    mov     rax, qword ptr [r10]
    test    rax, rax
    jz      xps_done                            ; no sharedStrings part
    mov     qword ptr [rbp-24], rax             ; cur
    mov     rdx, qword ptr [r10+8]
    add     rdx, rax
    mov     qword ptr [rbp-32], rdx             ; end
    ; storage for unescaped strings
    mov     rcx, qword ptr [r10+8]
    add     rcx, 16
    call    mem_alloc
    test    rax, rax
    jz      xps_done
    mov     qword ptr [g_ss_txt], rax
    mov     qword ptr [rbp-40], rax             ; write ptr
xps_lp:
    mov     eax, dword ptr [g_ss_n]
    cmp     eax, XI_MAXSS
    jae     xps_done
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [si_open]
    mov     r9d, 3
    call    xi_find
    test    rax, rax
    jz      xps_done
    mov     qword ptr [rbp-24], rax             ; si start
    ; si end = next <si or end
    lea     rcx, [rax+3]
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [si_open]
    mov     r9d, 3
    call    xi_find
    test    rax, rax
    jnz     xps_haveend
    mov     rax, qword ptr [rbp-32]             ; last si -> end of buffer
xps_haveend:
    mov     qword ptr [rbp-48], rax             ; si end
    ; extract concatenated <t> text into g_ss_txt at write ptr
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-48]
    mov     r8, qword ptr [rbp-40]
    mov     r9d, 65535
    call    xi_ttext
    ; record {ptr, len}
    mov     ecx, dword ptr [g_ss_n]
    add     ecx, ecx                            ; 2*i (16-byte records via scale 8)
    lea     r11, [g_ss_arr]
    mov     r10, qword ptr [rbp-40]
    mov     qword ptr [r11+rcx*8], r10
    mov     dword ptr [r11+rcx*8+8], eax
    add     qword ptr [rbp-40], rax             ; advance write ptr
    inc     dword ptr [g_ss_n]
    mov     rcx, qword ptr [rbp-48]             ; continue after this si
    mov     qword ptr [rbp-24], rcx
    jmp     xps_lp
xps_done:
    FRAME_EPILOG
    ret
xi_parse_shared endp

; xi_cell(rcx=cstart, rdx=cend, r8=&outptr, r9=&outlen, [rbp+48]=rowdst offset ptr)
;   resolve a <c> element's text value.  rowdst is where inline/value text is
;   unescaped (g_xl_rowtxt + running offset, updated).
xi_cell proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx             ; cstart
    mov     qword ptr [rbp-32], rdx             ; cend
    mov     qword ptr [rbp-40], r8              ; &outptr
    mov     qword ptr [rbp-48], r9              ; &outlen
    mov     rax, qword ptr [rbp+48]
    mov     qword ptr [rbp-56], rax             ; &rowoff
    ; default: empty
    mov     r10, qword ptr [rbp-40]
    mov     qword ptr [r10], 0
    mov     r10, qword ptr [rbp-48]
    mov     dword ptr [r10], 0
    ; open tag end '>'
    mov     r10, qword ptr [rbp-24]
xc_gt:
    cmp     r10, qword ptr [rbp-32]
    jae     xc_done
    cmp     byte ptr [r10], '>'
    je      xc_gtf
    inc     r10
    jmp     xc_gt
xc_gtf:
    mov     qword ptr [rbp-64], r10             ; open-tag '>'
    ; type: search ' t="' within [cstart, gt]
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, r10
    lea     r8, [xc_tattr]
    mov     r9d, 4
    call    xi_find
    test    rax, rax
    jz      xc_novtype
    movzx   ecx, byte ptr [rax+4]               ; first char of the type value
    cmp     ecx, 's'
    jne     xc_notshared
    cmp     byte ptr [rax+5], '"'               ; exactly t="s"
    jne     xc_notshared
    ; shared string: <v>index</v>
    mov     rcx, qword ptr [rbp-64]
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [v_open]
    mov     r9d, 3
    call    xi_find
    test    rax, rax
    jz      xc_done
    lea     rcx, [rax+3]
    mov     rdx, qword ptr [rbp-32]
    call    xi_int                              ; eax = shared index
    cmp     eax, dword ptr [g_ss_n]
    jae     xc_done
    add     eax, eax                            ; 2*i (16-byte records via scale 8)
    lea     r11, [g_ss_arr]
    mov     r10, qword ptr [r11+rax*8]
    mov     r9d, dword ptr [r11+rax*8+8]
    mov     rcx, qword ptr [rbp-40]
    mov     qword ptr [rcx], r10
    mov     rcx, qword ptr [rbp-48]
    mov     dword ptr [rcx], r9d
    jmp     xc_done
xc_notshared:
    cmp     ecx, 'i'                            ; t="inlineStr"
    jne     xc_novtype
    ; inline: <t>..</t> unescaped into rowtxt
    mov     rcx, qword ptr [rbp-64]
    mov     rdx, qword ptr [rbp-32]
    jmp     xc_emit_t
xc_novtype:
    ; plain number / str: <v>..</v>
    mov     rcx, qword ptr [rbp-64]
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [v_open]
    mov     r9d, 3
    call    xi_find
    test    rax, rax
    jz      xc_done
    lea     rcx, [rax+3]
    mov     qword ptr [rbp-72], rcx             ; value start
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [v_close]
    mov     r9d, 4
    call    xi_find
    test    rax, rax
    jz      xc_done
    mov     rcx, qword ptr [rbp-72]
    mov     rdx, rax
    jmp     xc_unesc_into_row
xc_emit_t:
    ; xi_ttext from [gt, cend] into rowtxt
    mov     r10, qword ptr [rbp-56]
    mov     r11d, dword ptr [r10]               ; rowoff
    lea     r8, [g_xl_rowtxt]
    add     r8, r11
    mov     r9d, 60000
    mov     rcx, qword ptr [rbp-64]
    mov     rdx, qword ptr [rbp-32]
    call    xi_ttext
    jmp     xc_recordrow
xc_unesc_into_row:
    ; rcx=value start, rdx=value end already set
    mov     r10, qword ptr [rbp-56]
    mov     r11d, dword ptr [r10]
    lea     r8, [g_xl_rowtxt]
    add     r8, r11
    mov     r9d, 60000
    call    xi_unesc
xc_recordrow:
    ; outptr = g_xl_rowtxt + rowoff ; outlen = eax ; rowoff += eax
    mov     r10, qword ptr [rbp-56]
    mov     r11d, dword ptr [r10]
    lea     r8, [g_xl_rowtxt]
    add     r8, r11
    mov     rcx, qword ptr [rbp-40]
    mov     qword ptr [rcx], r8
    mov     rcx, qword ptr [rbp-48]
    mov     dword ptr [rcx], eax
    add     dword ptr [r10], eax
xc_done:
    FRAME_EPILOG
    ret
xi_cell endp

.const
xc_tattr db " t=",22h                            ; ' t="'

.code

; xlsx_import(rcx=raw, edx=rawlen) -> eax = count / -1 / -2(encrypted)
public xlsx_import
xlsx_import proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    ; encrypted (OLE2 compound file) ?
    cmp     byte ptr [rcx], 0D0h
    jne     xm_notole
    cmp     byte ptr [rcx+1], 0CFh
    jne     xm_notole
    cmp     byte ptr [rcx+2], 011h
    jne     xm_notole
    cmp     byte ptr [rcx+3], 0E0h
    jne     xm_notole
    mov     eax, -2
    FRAME_EPILOG
    ret
xm_notole:
    cmp     byte ptr [rcx], 'P'                  ; zip ?
    jne     xm_err
    cmp     byte ptr [rcx+1], 'K'
    jne     xm_err
    mov     qword ptr [g_xi_raw], rcx            ; publish for zip_extract
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [g_xi_rawlen], eax
    ; extract sharedStrings (optional) + first sheet
    lea     r10, [g_ss_buf]
    mov     qword ptr [r10], 0
    lea     rcx, [xi_ss_name]
    mov     edx, xi_ss_name_n
    lea     r8, [g_ss_buf]
    call    zip_extract
    lea     rcx, [xi_sheet_name]
    mov     edx, xi_sheet_n
    lea     r8, [g_sheet_buf]
    call    zip_extract
    test    eax, eax
    jz      xm_err
    call    xi_parse_shared
    call    xi_import_sheet
    mov     dword ptr [rbp-36], eax
    ; free buffers
    lea     r10, [g_ss_buf]
    mov     rcx, qword ptr [r10]
    test    rcx, rcx
    jz      xm_f2
    mov     rdx, qword ptr [r10+16]
    call    mem_free
xm_f2:
    lea     r10, [g_sheet_buf]
    mov     rcx, qword ptr [r10]
    mov     rdx, qword ptr [r10+16]
    call    mem_free
    mov     rcx, qword ptr [g_ss_txt]
    test    rcx, rcx
    jz      xm_ret
    mov     rdx, qword ptr [g_ss_buf+8]
    add     rdx, 16
    call    mem_free
xm_ret:
    mov     eax, dword ptr [rbp-36]
    FRAME_EPILOG
    ret
xm_err:
    mov     eax, -1
    FRAME_EPILOG
    ret
xlsx_import endp

; zip_extract(rcx=name, edx=namelen, r8=&outdesc{ptr,len,cap}) -> eax 0/1.
;   Uses g_xi_raw/g_xi_rawlen set by xlsx_import (via the outer frame).  To keep
;   it simple this reads the raw ptr/len from globals set below.
zip_extract proc frame
    FRAME_PROLOG 112
    mov     qword ptr [rbp-24], rcx             ; name
    mov     dword ptr [rbp-32], edx             ; namelen
    mov     qword ptr [rbp-40], r8              ; outdesc
    mov     qword ptr [r8], 0
    mov     rax, qword ptr [g_xi_raw]
    mov     qword ptr [rbp-48], rax             ; raw
    mov     eax, dword ptr [g_xi_rawlen]
    mov     dword ptr [rbp-52], eax             ; rawlen
    ; find EOCD: scan back for 06054b50
    mov     r10, qword ptr [rbp-48]
    mov     eax, dword ptr [rbp-52]
    lea     r11, [r10+rax]
    sub     r11, 22                             ; earliest EOCD start
ze_scan:
    cmp     r11, r10
    jb      ze_no
    cmp     dword ptr [r11], 06054b50h
    je      ze_eocd
    dec     r11
    jmp     ze_scan
ze_eocd:
    mov     eax, dword ptr [r11+16]             ; cd offset
    mov     r10, qword ptr [rbp-48]
    add     r10, rax
    mov     qword ptr [rbp-56], r10             ; cd cursor
    movzx   eax, word ptr [r11+10]              ; total entries
    mov     dword ptr [rbp-60], eax
ze_lp:
    cmp     dword ptr [rbp-60], 0
    je      ze_no
    mov     r10, qword ptr [rbp-56]
    cmp     dword ptr [r10], 02014b50h
    jne     ze_no
    movzx   r8d, word ptr [r10+28]              ; namelen
    movzx   r9d, word ptr [r10+30]              ; extralen
    movzx   r11d, word ptr [r10+32]             ; commentlen
    mov     dword ptr [rbp-64], r8d
    mov     dword ptr [rbp-68], r9d
    mov     dword ptr [rbp-72], r11d
    ; compare name
    cmp     r8d, dword ptr [rbp-32]
    jne     ze_next
    lea     rcx, [r10+46]                       ; cd name
    mov     rdx, qword ptr [rbp-24]             ; target
    mov     r9d, r8d
    xor     r8d, r8d
ze_cmp:
    cmp     r8d, r9d
    jae     ze_match
    mov     al, byte ptr [rcx+r8]
    cmp     al, byte ptr [rdx+r8]
    jne     ze_next
    inc     r8d
    jmp     ze_cmp
ze_match:
    mov     r10, qword ptr [rbp-56]
    movzx   eax, word ptr [r10+10]              ; method
    mov     dword ptr [rbp-76], eax
    mov     eax, dword ptr [r10+20]             ; comp size
    mov     dword ptr [rbp-80], eax
    mov     eax, dword ptr [r10+24]             ; uncomp size
    mov     dword ptr [rbp-84], eax
    mov     eax, dword ptr [r10+42]             ; local header offset
    mov     dword ptr [rbp-88], eax
    ; local header -> data
    mov     r11, qword ptr [rbp-48]
    add     r11, rax                            ; local hdr
    movzx   ecx, word ptr [r11+26]              ; local namelen
    movzx   edx, word ptr [r11+28]              ; local extralen
    add     r11, 30
    add     r11, rcx
    add     r11, rdx
    mov     qword ptr [rbp-96], r11             ; data ptr
    ; allocate output = uncomp size (+16)
    mov     ecx, dword ptr [rbp-84]
    add     ecx, 16
    call    mem_alloc
    test    rax, rax
    jz      ze_no
    mov     r10, qword ptr [rbp-40]
    mov     qword ptr [r10], rax                ; outdesc.ptr
    mov     ecx, dword ptr [rbp-84]
    mov     qword ptr [r10+16], rcx             ; cap (uncomp)
    mov     eax, dword ptr [rbp-76]
    test    eax, eax
    jnz     ze_inflate
    ; stored: copy comp size bytes
    mov     r10, qword ptr [rbp-40]
    mov     r11, qword ptr [r10]                ; dst
    mov     rcx, qword ptr [rbp-96]             ; src
    mov     r8d, dword ptr [rbp-80]             ; comp size
    xor     r9d, r9d
ze_cp:
    cmp     r9d, r8d
    jae     ze_cpd
    mov     al, byte ptr [rcx+r9]
    mov     byte ptr [r11+r9], al
    inc     r9d
    jmp     ze_cp
ze_cpd:
    mov     r10, qword ptr [rbp-40]
    mov     eax, dword ptr [rbp-80]
    mov     qword ptr [r10+8], rax              ; len
    mov     eax, 1
    FRAME_EPILOG
    ret
ze_inflate:
    mov     r10, qword ptr [rbp-40]
    mov     r8, qword ptr [r10]                 ; dst
    mov     rcx, qword ptr [rbp-96]             ; src
    mov     edx, dword ptr [rbp-80]             ; comp size
    mov     r9d, dword ptr [rbp-84]
    add     r9d, 16                             ; dst cap
    call    inflate
    cmp     eax, -1
    je      ze_no
    mov     r10, qword ptr [rbp-40]
    mov     ecx, eax
    mov     qword ptr [r10+8], rcx              ; len
    mov     eax, 1
    FRAME_EPILOG
    ret
ze_next:
    mov     r10, qword ptr [rbp-56]
    add     r10, 46
    add     r10d, dword ptr [rbp-64]
    add     r10d, dword ptr [rbp-68]
    add     r10d, dword ptr [rbp-72]
    ; careful: r10 is 64-bit; add dword adds to low 32 then zero-extends? use eax accum
    mov     rax, qword ptr [rbp-56]
    add     rax, 46
    mov     ecx, dword ptr [rbp-64]
    add     rax, rcx
    mov     ecx, dword ptr [rbp-68]
    add     rax, rcx
    mov     ecx, dword ptr [rbp-72]
    add     rax, rcx
    mov     qword ptr [rbp-56], rax
    dec     dword ptr [rbp-60]
    jmp     ze_lp
ze_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
zip_extract endp

.data?
g_xi_raw     dq ?
g_xi_rawlen  dd ?
.code

; xi_import_sheet() -> eax = imported count.  Parse rows: row 0 = header (map
;   columns), rows 1+ = entries.
xi_import_sheet proc frame
    FRAME_PROLOG 176                            ; locals above the 5/6-arg outgoing slots
    mov     dword ptr [rbp-24], 0               ; imported
    mov     dword ptr [rbp-28], 0               ; row index (0 = header)
    mov     dword ptr [g_xl_ncol], 0
    lea     r10, [g_sheet_buf]
    mov     rax, qword ptr [r10]
    mov     qword ptr [rbp-32], rax             ; cur
    mov     rdx, qword ptr [r10+8]
    add     rdx, rax
    mov     qword ptr [rbp-40], rdx             ; end
xis_rlp:
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [rbp-40]
    lea     r8, [row_open]
    mov     r9d, 4
    call    xi_find
    test    rax, rax
    jz      xis_done
    mov     qword ptr [rbp-48], rax             ; row start
    ; row end = next <row or end
    lea     rcx, [rax+4]
    mov     rdx, qword ptr [rbp-40]
    lea     r8, [row_open]
    mov     r9d, 4
    call    xi_find
    test    rax, rax
    jnz     xis_rend
    mov     rax, qword ptr [rbp-40]
xis_rend:
    mov     qword ptr [rbp-56], rax             ; row end
    mov     qword ptr [rbp-32], rax             ; advance for next row
    ; parse cells: clear per-row arrays
    lea     r11, [g_xl_cellp]
    lea     r10, [g_xl_celll]
    xor     ecx, ecx
xis_clr:
    cmp     ecx, XI_MAXCOL
    jae     xis_clrd
    mov     qword ptr [r11+rcx*8], 0
    mov     dword ptr [r10+rcx*4], 0
    inc     ecx
    jmp     xis_clr
xis_clrd:
    mov     dword ptr [rbp-60], 0               ; rowtxt offset
    mov     dword ptr [rbp-64], 0               ; rowempty (0 empty)
    mov     rax, qword ptr [rbp-48]
    mov     qword ptr [rbp-72], rax             ; cell cursor
xis_clp:
    mov     rcx, qword ptr [rbp-72]
    mov     rdx, qword ptr [rbp-56]
    lea     r8, [c_open]
    mov     r9d, 2
    call    xi_find
    test    rax, rax
    jz      xis_rowdone
    ; must be "<c " or "<c>" or "<c/" (a cell, not <col>)
    movzx   ecx, byte ptr [rax+2]
    cmp     ecx, ' '
    je      xis_iscell
    cmp     ecx, '>'
    je      xis_iscell
    cmp     ecx, '/'
    je      xis_iscell
    lea     rcx, [rax+2]
    mov     qword ptr [rbp-72], rcx
    jmp     xis_clp
xis_iscell:
    mov     qword ptr [rbp-80], rax             ; cell start
    ; cell end = "</c>" or (self-closed) - find "</c>" or next "<c"
    lea     rcx, [rax+2]
    mov     rdx, qword ptr [rbp-56]
    lea     r8, [c_close]
    mov     r9d, 4
    call    xi_find
    test    rax, rax
    jnz     xis_cend
    mov     rax, qword ptr [rbp-56]
    jmp     xis_cendp
xis_cend:
    add     rax, 4
xis_cendp:
    mov     qword ptr [rbp-88], rax             ; cell end
    mov     qword ptr [rbp-72], rax             ; advance
    ; column index from r="XX" in the cell open tag
    mov     rcx, qword ptr [rbp-80]
    mov     rdx, qword ptr [rbp-88]
    lea     r8, [xis_rattr]
    mov     r9d, 3
    call    xi_find
    test    rax, rax
    jz      xis_clp                             ; no ref -> skip cell
    lea     rcx, [rax+3]
    mov     rdx, qword ptr [rbp-88]
    call    xi_col
    mov     dword ptr [rbp-92], eax             ; col
    cmp     eax, XI_MAXCOL
    jae     xis_clp
    cmp     eax, 0
    jl      xis_clp
    ; resolve value
    lea     rax, [rbp-60]                       ; &rowoff
    mov     qword ptr [rsp+32], rax             ; 5th arg
    mov     rcx, qword ptr [rbp-80]
    mov     rdx, qword ptr [rbp-88]
    lea     r8, [rbp-104]                       ; &outptr
    lea     r9, [rbp-112]                       ; &outlen
    call    xi_cell
    ; store cell ptr/len at col
    mov     ecx, dword ptr [rbp-92]
    mov     rax, qword ptr [rbp-104]
    lea     r11, [g_xl_cellp]
    mov     qword ptr [r11+rcx*8], rax
    mov     eax, dword ptr [rbp-112]
    lea     r11, [g_xl_celll]
    mov     dword ptr [r11+rcx*4], eax
    test    eax, eax
    jz      xis_clp
    mov     dword ptr [rbp-64], 1               ; row not empty
    jmp     xis_clp
xis_rowdone:
    cmp     dword ptr [rbp-28], 0
    jne     xis_datarow
    ; header row: map each non-empty column via csv_hdr_type (wide)
    mov     dword ptr [rbp-116], 0
xis_hlp:
    mov     eax, dword ptr [rbp-116]
    cmp     eax, XI_MAXCOL
    jae     xis_hdone
    lea     r11, [g_xl_celll]
    mov     ecx, eax
    mov     edx, dword ptr [r11+rcx*4]
    test    edx, edx
    jz      xis_hnext
    ; widen the header cell
    lea     r11, [g_xl_cellp]
    mov     r8, qword ptr [r11+rcx*8]
    WINCALL MultiByteToWideChar, CP_UTF8_, 0, r8, edx, addr g_xl_hdrw, 500
    lea     r10, [g_xl_hdrw]
    mov     word ptr [r10+rax*2], 0             ; NUL-terminate (rax=result chars)
    lea     rcx, [g_xl_hdrw]
    call    csv_hdr_type
    mov     ecx, dword ptr [rbp-116]
    lea     r11, [g_xl_coltype]
    mov     dword ptr [r11+rcx*4], eax
    mov     eax, dword ptr [rbp-116]
    inc     eax
    mov     dword ptr [g_xl_ncol], eax
xis_hnext:
    inc     dword ptr [rbp-116]
    jmp     xis_hlp
xis_hdone:
    ; force a title column if none
    xor     ecx, ecx
    lea     r11, [g_xl_coltype]
xis_ht:
    cmp     ecx, dword ptr [g_xl_ncol]
    jae     xis_hnotitle
    cmp     dword ptr [r11+rcx*4], VF_TITLE_
    je      xis_advrow
    inc     ecx
    jmp     xis_ht
xis_hnotitle:
    lea     r11, [g_xl_coltype]
    mov     dword ptr [r11], VF_TITLE_
    jmp     xis_advrow
xis_datarow:
    cmp     dword ptr [rbp-64], 0
    je      xis_advrow                          ; skip blank row
    call    xi_build_entry
    test    eax, eax
    jz      xis_advrow
    inc     dword ptr [rbp-24]
xis_advrow:
    inc     dword ptr [rbp-28]
    jmp     xis_rlp
xis_done:
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
xi_import_sheet endp

.const
xis_rattr db "r=",22h                            ; 'r="'  (cell ref attribute)
.code

; xi_addf(ecx=col, edx=type, r8d=slot) - widen the row cell at col into the
;   per-slot wide buffer and store {type,0,wideptr} in g_field_list[slot].
xi_addf proc frame
    FRAME_PROLOG 96                             ; locals above the 6-arg outgoing slots
    mov     dword ptr [rbp-24], ecx             ; col
    mov     dword ptr [rbp-28], edx             ; type
    mov     dword ptr [rbp-32], r8d             ; slot
    mov     eax, r8d
    imul    eax, eax, 2048
    lea     r9, [g_xl_wide]
    add     r9, rax
    mov     qword ptr [rbp-40], r9              ; wide dst
    mov     ecx, dword ptr [rbp-24]
    lea     r11, [g_xl_cellp]
    mov     r8, qword ptr [r11+rcx*8]
    lea     r11, [g_xl_celll]
    mov     edx, dword ptr [r11+rcx*4]
    WINCALL MultiByteToWideChar, CP_UTF8_, 0, r8, edx, qword ptr [rbp-40], 1023
    mov     r9, qword ptr [rbp-40]
    mov     ecx, eax                            ; result chars
    mov     word ptr [r9+rcx*2], 0
    mov     eax, dword ptr [rbp-32]             ; field slot
    imul    eax, eax, 24
    lea     r11, [g_field_list]
    add     r11, rax
    mov     ecx, dword ptr [rbp-28]
    mov     qword ptr [r11+0], rcx              ; type
    mov     qword ptr [r11+8], 0
    mov     r9, qword ptr [rbp-40]
    mov     qword ptr [r11+16], r9              ; value ptr
    FRAME_EPILOG
    ret
xi_addf endp

; xi_build_entry() -> eax = 1 if built, 0 skipped.
xi_build_entry proc frame
    FRAME_PROLOG 64
    mov     dword ptr [rbp-24], 0               ; n fields
    mov     dword ptr [rbp-28], -1              ; title col
    xor     ecx, ecx
xbe_ft:
    cmp     ecx, dword ptr [g_xl_ncol]
    jae     xbe_ftdone
    lea     r11, [g_xl_coltype]
    cmp     dword ptr [r11+rcx*4], VF_TITLE_
    jne     xbe_ftn
    lea     r11, [g_xl_celll]
    cmp     dword ptr [r11+rcx*4], 0
    je      xbe_ftn
    mov     dword ptr [rbp-28], ecx
    jmp     xbe_ftdone
xbe_ftn:
    inc     ecx
    jmp     xbe_ft
xbe_ftdone:
    cmp     dword ptr [rbp-28], 0
    jge     xbe_addtitle
    xor     ecx, ecx                            ; fallback: first non-empty cell
xbe_fb:
    cmp     ecx, XI_MAXCOL
    jae     xbe_skip
    lea     r11, [g_xl_celll]
    cmp     dword ptr [r11+rcx*4], 0
    jne     xbe_fbuse
    inc     ecx
    jmp     xbe_fb
xbe_fbuse:
    mov     dword ptr [rbp-28], ecx
xbe_addtitle:
    mov     ecx, dword ptr [rbp-28]
    mov     edx, VF_TITLE_
    mov     r8d, 0
    call    xi_addf
    mov     dword ptr [rbp-24], 1
    xor     ecx, ecx                            ; other mapped columns
xbe_r:
    cmp     ecx, dword ptr [g_xl_ncol]
    jae     xbe_build
    cmp     ecx, dword ptr [rbp-28]
    je      xbe_rn
    lea     r11, [g_xl_coltype]
    mov     eax, dword ptr [r11+rcx*4]
    test    eax, eax
    jz      xbe_rn
    cmp     eax, VF_TITLE_
    je      xbe_rn
    lea     r11, [g_xl_celll]
    cmp     dword ptr [r11+rcx*4], 0
    je      xbe_rn
    cmp     dword ptr [rbp-24], XI_MAXCOL
    jae     xbe_build
    mov     edx, eax                            ; type
    mov     r8d, dword ptr [rbp-24]             ; slot
    mov     dword ptr [rbp-32], ecx             ; save col across the call
    call    xi_addf
    inc     dword ptr [rbp-24]
    mov     ecx, dword ptr [rbp-32]
xbe_rn:
    inc     ecx
    jmp     xbe_r
xbe_build:
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [g_field_n], eax
    call    vault_build_entry
    test    eax, eax
    jnz     xbe_skip
    mov     eax, 1
    FRAME_EPILOG
    ret
xbe_skip:
    xor     eax, eax
    FRAME_EPILOG
    ret
xi_build_entry endp

end
