; =============================================================================
; zipimport.asm - import a Vordr WinZip-AE-2 (AES-256) encrypted .zip produced by
; zipexport.asm: decrypt the members, parse the vordr.json data file, and rebuild
; every record (all fields + attachments) into the open vault.
;
;   zi_import(rcx=raw, edx=rawlen, r8=wide pw ptr, r9d=pw bytes) -> eax
;       >=0  entries imported
;       -3   wrong password
;       -1   not a readable Vordr zip / error
;
; The archive is: repeated local file headers, each STORE-inside-AES (method 99),
; body = salt(16) | pwverify(2) | AES-256-CTR ciphertext(usize) | HMAC-SHA1(10).
; Attachments are members named "<title>/<filename>"; the json references them by
; that path in image/file field values, so each is decrypted + re-staged.
; =============================================================================

include macros.inc

extern mem_alloc:proc
extern mem_free:proc
extern secure_zero:proc
extern pbkdf2_ae:proc                    ; PBKDF2-HMAC-SHA1 1000 iters -> g_ae_dk
extern aes_expand_key:proc
extern aes_ctr_xor:proc
extern hmac_sha1:proc
extern ct_memcmp:proc                    ; constant-time compare (hardening.asm)
extern MultiByteToWideChar:proc
extern WideCharToMultiByte:proc
extern attach_reset:proc
extern attach_stage:proc
extern vault_build_entry:proc
extern print_a:proc
extern print_u64:proc
extern fuzz_seed:proc                   ; G7: reproducible/logged fuzzer seed (main.asm)
externdef g_ae_dk:byte
externdef g_field_list:qword
externdef g_field_n:dword
externdef g_sel:byte                      ; per-entry import selection mask (from gui.asm)

ARF_SIZE    equ 68
CP_UTF8_    equ 65001
ZI_MAXMEM   equ 8192                      ; max archive members
ZI_MAXENT   equ 8192                      ; max stageable entries (matches MAX_SEL)
ZI_ARENA    equ 4*1024*1024              ; per-entry wide/blob scratch
ZI_SBUF     equ 256*1024                  ; one string's decoded UTF-8
ZI_TBUF     equ 1024*1024                 ; persistent staged-title wide storage
MAX_FIELDS  equ 56                        ; g_field_list capacity (matches main.asm)
MEMREC      equ 32                        ; {nameptr8, namelen4, _4, dataptr8, usize4, _4}

.data?
align 8
g_zfz_rng   dq ?                          ; fuzzzip xorshift64 state (dbg/test only)
g_zi_end    dq ?                          ; raw end
g_zi_pwptr  dq ?                          ; UTF-8 pw ptr (= g_zi_u8pw)
g_zi_pwlen  dd ?
ZI_PWCAP    equ 1024                      ; 254 wide chars can be 762 UTF-8 bytes; the
g_zi_u8pw   db ZI_PWCAP dup (?)           ;   old 512/500 truncated to an EMPTY password
g_zi_n      dd ?                          ; member count
g_zi_mem    db ZI_MAXMEM * MEMREC dup (?)
g_zi_rk     db 15*16 dup (?)
g_zi_ctr    db 16 dup (?)
g_zi_auth   db 20 dup (?)
g_zi_nr     dd ?
g_zi_arena  dq ?                          ; heap arena ptr
g_zi_ap     dd ?                          ; arena bump offset
g_zi_sbuf   db ZI_SBUF dup (?)            ; decoded-string scratch (UTF-8)
g_zi_ref    db ARF_SIZE dup (?)           ; attach_stage AttachRef out
g_zi_p      dq ?                          ; json parse cursor
g_zi_jend   dq ?
g_zi_count  dd ?
g_zi_slot   dd ?                          ; zi_addattach: field slot
g_zi_atype  dd ?                          ; zi_addattach: base type (9/10)
g_zi_alabel dq ?                          ; zi_addattach: label wide (0/none)
g_zi_mode   dd ?                          ; zi_walk: 0 = stage (titles), 1 = commit (build)
g_zi_e      dd ?                          ; zi_walk: running entry index
g_zi_build  dd ?                          ; zi_walk: current entry builds fields (1) or discards (0)
g_zi_jptr   dq ?                          ; decrypted vordr.json ptr (persists stage -> commit)
g_zi_jlen   dd ?
g_zi_tap    dd ?                          ; staged-title arena bump offset
align 8
public g_zi_stg_n
g_zi_stg_n  dd ?                          ; number of entries staged (titles ready)
public g_zi_titles
g_zi_titles dq ZI_MAXENT dup (?)          ; per-entry wide title ptr (into g_zi_tbuf)
public g_zi_tlens
g_zi_tlens  dd ZI_MAXENT dup (?)          ; per-entry wide title length (wchars)
g_zi_tbuf   db ZI_TBUF dup (?)            ; persistent staged-title text (wide)

.const
zi_jsonname db "vordr.json"
zi_empty_w  dw 0                          ; NUL wide string (title fallback on overflow)
zl_title    db '"title":'
zl_fields   db ',"fields":['
zl_type     db '"type":'
zl_label    db ',"label":'
zl_value    db ',"value":'

; --- fuzzzip fixture: a minimal WinZip-AES STORED local header for vordr.json
; (usize=4 so the whole member region {salt16, verify2, cipher4, hmac10} = 32B
; of data sits inside the buffer), then an EOCD signature to end the scan. -----
align 4
zfz_fix label byte
    dd  04034b50h                         ; local file header signature
    dw  20                                ; version needed
    dw  1                                 ; flags (bit0 = encrypted)
    dw  99                                ; method = AE-x
    dw  0, 0                              ; mod time, mod date
    dd  0                                 ; crc32
    dd  32                                ; csize = 18 hdr + 4 cipher + 10 hmac
    dd  4                                 ; usize (cipher length)
    dw  10                                ; namelen
    dw  0                                 ; extralen
    db  'v','o','r','d','r','.','j','s','o','n'
    db  32 dup (0AAh)                     ; member data (garbage salt/verify/cipher/hmac)
    dd  06054b50h                         ; EOCD signature -> stops zi_scan
    db  18 dup (0)                        ; EOCD remainder (pad)
zfz_fix_end label byte
ZFZ_FIX_LEN equ zfz_fix_end - zfz_fix
ZFZ_ITERS   equ 100000
CSTR zfz_m1, "fuzzzip: "
CSTR zfz_m2, " iters  "
CSTR zfz_m3, " scanned  "
CSTR zfz_m4, " rejected  0 crashes",13,10

.code

; =============================================================================
; zi_scan(rcx = raw, edx = rawlen) -> eax = member count.  Walk the local file
;   headers into g_zi_mem; stop at the central directory / EOCD.
; =============================================================================
zi_scan proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx             ; p (current header)
    mov     eax, edx
    add     rax, rcx
    mov     qword ptr [g_zi_end], rax           ; raw end
    xor     r10d, r10d                          ; n
zs_lp:
    mov     rcx, qword ptr [rbp-24]
    lea     rax, [rcx+30]
    cmp     rax, qword ptr [g_zi_end]
    ja      zs_done
    cmp     dword ptr [rcx], 04034b50h          ; local file header sig?
    jne     zs_done
    movzx   r8d, word ptr [rcx+26]              ; namelen
    movzx   r9d, word ptr [rcx+28]              ; extralen
    mov     eax, dword ptr [rcx+18]             ; csize
    mov     dword ptr [rbp-28], eax
    mov     eax, dword ptr [rcx+22]             ; usize
    mov     dword ptr [rbp-32], eax
    lea     r11, [rcx+30]                       ; nameptr
    ; dataptr = p + 30 + namelen + extralen
    lea     rax, [rcx+30]
    add     rax, r8
    add     rax, r9
    mov     qword ptr [rbp-40], rax             ; dataptr
    ; Bounds: the whole member region {salt16, verify2, cipher[usize], hmac10}
    ; must lie inside the raw buffer.  usize/dataptr come straight from the
    ; attacker's header - without this a hostile usize would drive zi_decrypt's
    ; HMAC read (pre-auth) and in-place CTR write past the end (OOB read/write).
    ; A malformed member ends the scan (like an unrecognised signature does).
    mov     rax, qword ptr [rbp-40]             ; dataptr
    mov     ecx, dword ptr [rbp-32]             ; usize (zero-extended into rcx)
    add     rax, rcx
    add     rax, 28                             ; 18-byte header + 10-byte HMAC tag
    cmp     rax, qword ptr [g_zi_end]
    ja      zs_done
    ; record
    mov     eax, r10d
    imul    eax, eax, MEMREC
    lea     rcx, [g_zi_mem]
    add     rcx, rax
    mov     qword ptr [rcx+0], r11              ; nameptr
    mov     dword ptr [rcx+8], r8d              ; namelen
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [rcx+16], rax             ; dataptr
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [rcx+24], eax             ; usize
    inc     r10d
    ; advance p = dataptr + csize
    mov     rcx, qword ptr [rbp-40]             ; dataptr
    mov     eax, dword ptr [rbp-28]             ; csize (zero-extended)
    add     rcx, rax
    mov     qword ptr [rbp-24], rcx
    cmp     r10d, ZI_MAXMEM
    jae     zs_done
    jmp     zs_lp
zs_done:
    mov     dword ptr [g_zi_n], r10d
    mov     eax, r10d
    FRAME_EPILOG
    ret
zi_scan endp

; =============================================================================
; zi_find(rcx = name UTF-8, edx = namelen) -> eax = member index or -1.
; =============================================================================
zi_find proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-28], edx
    xor     r10d, r10d                          ; i
zf_lp:
    cmp     r10d, dword ptr [g_zi_n]
    jae     zf_none
    mov     eax, r10d
    imul    eax, eax, MEMREC
    lea     r11, [g_zi_mem]
    add     r11, rax
    mov     eax, dword ptr [r11+8]              ; namelen
    cmp     eax, dword ptr [rbp-28]
    jne     zf_next
    ; memcmp
    mov     r8, qword ptr [r11+0]               ; member name
    mov     r9, qword ptr [rbp-24]              ; wanted
    xor     ecx, ecx
zf_cmp:
    cmp     ecx, dword ptr [rbp-28]
    jae     zf_hit
    mov     al, byte ptr [r8+rcx]
    cmp     al, byte ptr [r9+rcx]
    jne     zf_next
    inc     ecx
    jmp     zf_cmp
zf_hit:
    mov     eax, r10d
    FRAME_EPILOG
    ret
zf_next:
    inc     r10d
    jmp     zf_lp
zf_none:
    mov     eax, -1
    FRAME_EPILOG
    ret
zi_find endp

; =============================================================================
; zi_decrypt(ecx = member index) -> eax = 0 ok / -3 wrong pw / -1 corrupt.
;   Verifies the 2-byte password check + the HMAC, then AES-256-CTR decrypts the
;   ciphertext IN PLACE.  Plaintext = member.dataptr+18, length member.usize.
; =============================================================================
zi_decrypt proc frame
    FRAME_PROLOG 96                             ; room for 5-arg WINCALL arg spill
    mov     eax, ecx
    imul    eax, eax, MEMREC
    lea     r10, [g_zi_mem]
    add     r10, rax
    mov     rax, qword ptr [r10+16]             ; dataptr (salt)
    mov     qword ptr [rbp-24], rax             ; salt
    mov     eax, dword ptr [r10+24]             ; usize
    mov     dword ptr [rbp-32], eax
    ; cipher = salt+18 ; auth = cipher+usize
    mov     rax, qword ptr [rbp-24]
    add     rax, 18
    mov     qword ptr [rbp-40], rax             ; cipher ptr
    ; ---- PBKDF2(pw, salt, 16) -> g_ae_dk ----
    mov     rcx, qword ptr [g_zi_pwptr]
    mov     edx, dword ptr [g_zi_pwlen]
    mov     r8, qword ptr [rbp-24]              ; salt
    mov     r9d, 16
    call    pbkdf2_ae
    ; ---- 2-byte password verifier: g_ae_dk[64..66] vs salt[16..18] ----
    ; constant-time: the verifier bytes are derived from the password
    lea     rcx, [g_ae_dk+64]
    mov     rdx, qword ptr [rbp-24]
    add     rdx, 16
    mov     r8d, 2
    call    ct_memcmp
    test    eax, eax
    jnz     zd_wrongpw
    ; ---- HMAC-SHA1(dk[32..64], ciphertext)[:10] vs the stored 10-byte tag ----
    mov     rax, qword ptr [rbp-40]             ; auth tag = cipher + usize
    mov     ecx, dword ptr [rbp-32]             ; usize (zero-extended)
    add     rax, rcx
    mov     qword ptr [rbp-56], rax             ; auth tag ptr (into raw)
    WINCALL hmac_sha1, addr g_ae_dk+32, 32, qword ptr [rbp-40], dword ptr [rbp-32], addr g_zi_auth
    lea     rcx, [g_zi_auth]                    ; constant-time MAC check
    mov     rdx, qword ptr [rbp-56]
    mov     r8d, 10
    call    ct_memcmp
    test    eax, eax
    jnz     zd_corrupt
    ; ---- AES-256-CTR decrypt in place ----
    lea     rcx, [g_ae_dk]
    mov     rdx, 32
    lea     r8, [g_zi_rk]
    call    aes_expand_key
    mov     dword ptr [g_zi_nr], eax
    lea     rcx, [g_zi_ctr]                     ; counter := 0
    xor     eax, eax
    mov     qword ptr [rcx], rax
    mov     qword ptr [rcx+8], rax
    WINCALL aes_ctr_xor, addr g_zi_rk, qword ptr [rbp-40], dword ptr [rbp-32], \
            addr g_zi_ctr, dword ptr [g_zi_nr]
    xor     eax, eax
    FRAME_EPILOG
    ret
zd_wrongpw:
    mov     eax, -3
    FRAME_EPILOG
    ret
zd_corrupt:
    mov     eax, -1
    FRAME_EPILOG
    ret
zi_decrypt endp

; zi_plain(ecx = member index) -> rax = plaintext ptr, edx = length.  (After a
;   successful zi_decrypt: the ciphertext region now holds plaintext.)
zi_plain proc
    mov     eax, ecx
    imul    eax, eax, MEMREC
    lea     r10, [g_zi_mem]
    add     r10, rax
    mov     rax, qword ptr [r10+16]
    add     rax, 18
    mov     edx, dword ptr [r10+24]
    ret
zi_plain endp

; =============================================================================
; zi_u2w(rcx = src UTF-8, edx = srclen) -> rax = NUL-terminated wide ptr in the
;   arena (advances g_zi_ap).  Empty input yields an empty wide string.
; =============================================================================
zi_u2w proc frame
    FRAME_PROLOG 96                             ; room for 6-arg MBtoWC arg spill
    mov     qword ptr [rbp-24], rcx             ; src
    mov     dword ptr [rbp-28], edx             ; srclen
    mov     r10, qword ptr [g_zi_arena]         ; dst = arena + ap
    mov     eax, dword ptr [g_zi_ap]
    add     r10, rax
    mov     qword ptr [rbp-40], r10             ; dst
    ; cap (wchars) = (ZI_ARENA - ap - 2) / 2, guarded against unsigned underflow.
    ; A SIGNED check on the remaining bytes catches both an exhausted arena and any
    ; prior overrun (ap >= ZI_ARENA); the old unsigned subtract wrapped to ~2GB.
    mov     ecx, ZI_ARENA
    sub     ecx, dword ptr [g_zi_ap]           ; remaining bytes
    cmp     ecx, 2
    jle     zw_full                            ; no room for even a NUL -> empty string
    sub     ecx, 2
    shr     ecx, 1
    mov     dword ptr [rbp-44], ecx             ; wide cap (bounds MBtoWC's writes)
    cmp     dword ptr [rbp-28], 0
    je      zw_empty
    WINCALL MultiByteToWideChar, CP_UTF8_, 0, qword ptr [rbp-24], dword ptr [rbp-28], \
            qword ptr [rbp-40], dword ptr [rbp-44]
    jmp     zw_term
zw_empty:
    xor     eax, eax
zw_term:
    ; NUL-terminate + advance ap by (wchars+1)*2 (<= remaining, so ap stays <= ZI_ARENA)
    mov     r10, qword ptr [rbp-40]
    mov     word ptr [r10+rax*2], 0
    inc     eax
    lea     eax, [eax*2]
    add     dword ptr [g_zi_ap], eax
    mov     rax, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
zw_full:
    lea     rax, [zi_empty_w]                  ; arena exhausted -> static empty wide str
    FRAME_EPILOG
    ret
zi_u2w endp

; zj_lit(rcx = literal bytes, edx = len) -> eax = 1 if g_zi_p matches (and is
;   advanced past it), else 0.  Leaf.
zj_lit proc
    mov     r10, qword ptr [g_zi_p]
    xor     r8d, r8d
zjl_lp:
    cmp     r8d, edx
    jae     zjl_ok
    mov     r9, r10
    add     r9, r8
    cmp     r9, qword ptr [g_zi_jend]
    jae     zjl_no
    mov     al, byte ptr [rcx+r8]
    cmp     al, byte ptr [r10+r8]
    jne     zjl_no
    inc     r8d
    jmp     zjl_lp
zjl_ok:
    add     r10, r8
    mov     qword ptr [g_zi_p], r10
    mov     eax, 1
    ret
zjl_no:
    xor     eax, eax
    ret
zj_lit endp

; zj_num() -> eax = parsed unsigned integer at g_zi_p (advances past digits).  Leaf.
zj_num proc
    mov     r10, qword ptr [g_zi_p]
    xor     eax, eax
zjn_lp:
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjn_done
    movzx   r8d, byte ptr [r10]
    cmp     r8d, '0'
    jb      zjn_done
    cmp     r8d, '9'
    ja      zjn_done
    imul    eax, eax, 10
    sub     r8d, '0'
    add     eax, r8d
    inc     r10
    jmp     zjn_lp
zjn_done:
    mov     qword ptr [g_zi_p], r10
    ret
zj_num endp

; =============================================================================
; zj_str(rcx = dst UTF-8) -> eax = decoded byte length.  g_zi_p must point at the
;   opening quote; decodes JSON escapes and advances past the closing quote.
; =============================================================================
zj_str proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx             ; dst
    xor     r11d, r11d                          ; out len
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjs_end
    cmp     byte ptr [r10], '"'
    jne     zjs_end
    inc     r10                                 ; past opening quote
zjs_lp:
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjs_end
    cmp     r11d, ZI_SBUF - 4                   ; output full (<=3 bytes/iter + NUL
    jae     zjs_full                            ; headroom)? stop emitting, drain input
    movzx   eax, byte ptr [r10]
    cmp     eax, '"'
    je      zjs_close
    cmp     eax, '\'
    je      zjs_esc
    ; literal byte
    mov     rcx, qword ptr [rbp-24]
    mov     byte ptr [rcx+r11], al
    inc     r11d
    inc     r10
    jmp     zjs_lp
zjs_esc:
    inc     r10                                 ; past backslash
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjs_end
    movzx   eax, byte ptr [r10]
    inc     r10
    cmp     eax, 'n'
    je      zjs_e_n
    cmp     eax, 'r'
    je      zjs_e_r
    cmp     eax, 't'
    je      zjs_e_t
    cmp     eax, 'b'
    je      zjs_e_b
    cmp     eax, 'f'
    je      zjs_e_f
    cmp     eax, 'u'
    je      zjs_e_u
    ; \" \\ \/ and any other -> the literal char in eax
    jmp     zjs_put
zjs_e_n:
    mov     eax, 0Ah
    jmp     zjs_put
zjs_e_r:
    mov     eax, 0Dh
    jmp     zjs_put
zjs_e_t:
    mov     eax, 09h
    jmp     zjs_put
zjs_e_b:
    mov     eax, 08h
    jmp     zjs_put
zjs_e_f:
    mov     eax, 0Ch
    jmp     zjs_put
zjs_put:
    mov     rcx, qword ptr [rbp-24]
    mov     byte ptr [rcx+r11], al
    inc     r11d
    jmp     zjs_lp
zjs_e_u:
    ; read 4 hex digits -> codepoint in edx, UTF-8 encode
    xor     edx, edx
    mov     r9d, 4
zjs_uhex:
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjs_end
    movzx   eax, byte ptr [r10]
    inc     r10
    shl     edx, 4
    cmp     eax, '9'
    jbe     zjs_udig
    or      eax, 20h                            ; lower-case
    sub     eax, 'a'-10
    jmp     zjs_uadd
zjs_udig:
    sub     eax, '0'
zjs_uadd:
    and     eax, 0Fh
    or      edx, eax
    dec     r9d
    jnz     zjs_uhex
    ; UTF-8 encode edx (BMP) into dst
    mov     rcx, qword ptr [rbp-24]
    cmp     edx, 80h
    jae     zjs_u2
    mov     byte ptr [rcx+r11], dl              ; 1 byte
    inc     r11d
    jmp     zjs_lp
zjs_u2:
    cmp     edx, 800h
    jae     zjs_u3
    mov     eax, edx                            ; 2 bytes: 110xxxxx 10xxxxxx
    shr     eax, 6
    or      eax, 0C0h
    mov     byte ptr [rcx+r11], al
    inc     r11d
    mov     eax, edx
    and     eax, 3Fh
    or      eax, 80h
    mov     byte ptr [rcx+r11], al
    inc     r11d
    jmp     zjs_lp
zjs_u3:
    mov     eax, edx                            ; 3 bytes: 1110xxxx 10xxxxxx 10xxxxxx
    shr     eax, 12
    or      eax, 0E0h
    mov     byte ptr [rcx+r11], al
    inc     r11d
    mov     eax, edx
    shr     eax, 6
    and     eax, 3Fh
    or      eax, 80h
    mov     byte ptr [rcx+r11], al
    inc     r11d
    mov     eax, edx
    and     eax, 3Fh
    or      eax, 80h
    mov     byte ptr [rcx+r11], al
    inc     r11d
    jmp     zjs_lp
zjs_full:
    ; output cap reached: a single string >= ZI_SBUF only occurs in a crafted
    ; archive.  Drain the rest of the string (honoring escapes so an escaped quote
    ; cannot end it early) WITHOUT writing, keeping g_zi_p in sync, then stop.
    ; Memory-safe truncation; the oversized value is discarded.
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjs_end
    movzx   eax, byte ptr [r10]
    inc     r10
    cmp     eax, '\'
    jne     zjs_full_q
    cmp     r10, qword ptr [g_zi_jend]          ; skip the escaped char
    jae     zjs_end
    inc     r10
    jmp     zjs_full
zjs_full_q:
    cmp     eax, '"'
    jne     zjs_full
    jmp     zjs_end                             ; consumed the closing quote
zjs_close:
    inc     r10                                 ; past closing quote
zjs_end:
    mov     qword ptr [g_zi_p], r10
    mov     eax, r11d
    FRAME_EPILOG
    ret
zj_str endp

; zj_skipch(al = char) - if *g_zi_p == char, advance past it.  Leaf.
zj_skipch proc
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjc_done
    cmp     byte ptr [r10], al
    jne     zjc_done
    inc     r10
    mov     qword ptr [g_zi_p], r10
zjc_done:
    ret
zj_skipch endp

; =============================================================================
; zi_addattach(ecx = base type 9/10, rdx = label wide (0/none), r8 = path UTF-8,
;   r9d = pathlen, [rbp+? via mem] n) - decrypt the referenced member, stage it,
;   and write g_field_list[n] as a VFL_RAW {AttachRef, filename} field.
;   -> eax = 1 field added / 0 skipped (missing / undecryptable attachment).
;   n (field slot) passed in g_zi_slot.
; =============================================================================
zi_addattach proc frame
    FRAME_PROLOG 128                            ; room for 6-arg MBtoWC arg spill
    mov     dword ptr [g_zi_atype], ecx
    mov     qword ptr [g_zi_alabel], rdx
    mov     qword ptr [rbp-24], r8              ; path
    mov     dword ptr [rbp-28], r9d             ; pathlen
    ; find the member
    mov     rcx, r8
    mov     edx, r9d
    call    zi_find
    cmp     eax, -1
    je      za_skip
    mov     dword ptr [rbp-32], eax             ; member idx
    mov     ecx, eax
    call    zi_decrypt
    test    eax, eax
    jnz     za_skip
    mov     ecx, dword ptr [rbp-32]
    call    zi_plain                            ; rax=ptr edx=len
    mov     qword ptr [rbp-40], rax
    mov     dword ptr [rbp-44], edx
    ; stage the plaintext -> g_zi_ref
    mov     rcx, rax
    mov     edx, dword ptr [rbp-44]
    lea     r8, [g_zi_ref]
    call    attach_stage
    test    eax, eax
    jnz     za_skip
    ; filename = basename(path) (after the last '/')
    mov     r10, qword ptr [rbp-24]             ; path
    mov     r8d, dword ptr [rbp-28]             ; pathlen
    mov     ecx, r8d                            ; start = pathlen
    xor     r9d, r9d                            ; last-slash+1 = 0
zaf_scan:
    test    ecx, ecx
    jz      zaf_done
    dec     ecx
    cmp     byte ptr [r10+rcx], '/'
    jne     zaf_scan
    lea     r9d, [rcx+1]                        ; base starts after '/'
zaf_done:
    mov     eax, r8d
    sub     eax, r9d                            ; fnlen = pathlen - base
    mov     dword ptr [rbp-48], eax             ; fnlen
    mov     r10, qword ptr [rbp-24]
    add     r10, r9                             ; fnptr
    mov     qword ptr [rbp-56], r10
    ; ensure the arena has room for the worst-case blob before any write:
    ;   4 (rawlen) + ARF_SIZE + (255+1)*2 (max wide filename incl NUL, MBtoWC-capped)
    mov     eax, dword ptr [g_zi_ap]
    add     eax, 4 + ARF_SIZE + 512
    cmp     eax, ZI_ARENA
    ja      za_skip
    ; build blob in arena: {u32 rawlen, AttachRef[68], filename wide (NUL-term)}
    mov     r11, qword ptr [g_zi_arena]
    mov     eax, dword ptr [g_zi_ap]
    add     r11, rax
    mov     qword ptr [rbp-64], r11             ; blob base
    ; copy AttachRef into blob+4
    lea     rax, [r11+4]
    lea     r8, [g_zi_ref]
    xor     ecx, ecx
za_cpref:
    mov     dl, byte ptr [r8+rcx]
    mov     byte ptr [rax+rcx], dl
    inc     ecx
    cmp     ecx, ARF_SIZE
    jb      za_cpref
    ; append the filename as wide (convert), directly after AttachRef
    ; wide dst = blob + 4 + 68
    mov     r10, qword ptr [rbp-64]
    lea     r10, [r10+4+ARF_SIZE]
    mov     qword ptr [rbp-40], r10             ; wide dst (reuse -40)
    WINCALL MultiByteToWideChar, CP_UTF8_, 0, qword ptr [rbp-56], dword ptr [rbp-48], \
            qword ptr [rbp-40], 255
    ; NUL-terminate the wide filename
    mov     r10, qword ptr [rbp-40]
    mov     word ptr [r10+rax*2], 0
    inc     eax                                 ; wchars incl NUL
    lea     eax, [eax*2]                        ; filename bytes
    ; rawlen = ARF_SIZE + filename bytes
    add     eax, ARF_SIZE
    mov     r11, qword ptr [rbp-64]
    mov     dword ptr [r11], eax                ; u32 rawlen
    ; advance ap by 4 + rawlen
    add     eax, 4
    add     dword ptr [g_zi_ap], eax
    ; write g_field_list[slot] = {type|VFL_RAW, label, blob}
    mov     eax, dword ptr [g_zi_slot]
    imul    eax, eax, 24
    lea     r10, [g_field_list]
    add     r10, rax
    mov     ecx, dword ptr [g_zi_atype]
    or      ecx, VFL_RAW
    mov     qword ptr [r10+0], rcx
    mov     rax, qword ptr [g_zi_alabel]
    mov     qword ptr [r10+8], rax
    mov     rax, qword ptr [rbp-64]
    mov     qword ptr [r10+16], rax
    mov     eax, 1
    FRAME_EPILOG
    ret
za_skip:
    xor     eax, eax
    FRAME_EPILOG
    ret
zi_addattach endp

; =============================================================================
; zi_stage_title(rcx = index, rdx = UTF-8 src, r8d = srclen) - convert the entry
;   title to a NUL-terminated wide string in the persistent title arena and record
;   it in g_zi_titles[index] / g_zi_tlens[index].  On overflow, records "".
; =============================================================================
zi_stage_title proc frame
    FRAME_PROLOG 128                            ; room for 6-arg MBtoWC arg spill
    mov     qword ptr [rbp-24], rcx             ; index
    mov     qword ptr [rbp-32], rdx             ; src
    mov     dword ptr [rbp-36], r8d             ; srclen
    cmp     rcx, ZI_MAXENT
    jae     st_full
    lea     r10, [g_zi_tbuf]                    ; dst = tbuf + tap
    mov     eax, dword ptr [g_zi_tap]
    add     r10, rax
    mov     qword ptr [rbp-48], r10             ; dst
    mov     ecx, ZI_TBUF                        ; cap (wchars) = (TBUF - tap - 2)/2
    sub     ecx, dword ptr [g_zi_tap]           ; remaining bytes
    cmp     ecx, 2                              ; SIGNED guard: catches tap >= TBUF-1
    jle     st_full                            ; (old unsigned path wrapped to ~2GB)
    sub     ecx, 2
    shr     ecx, 1
    mov     dword ptr [rbp-52], ecx             ; cap
    cmp     dword ptr [rbp-36], 0
    je      st_empty
    WINCALL MultiByteToWideChar, CP_UTF8_, 0, qword ptr [rbp-32], dword ptr [rbp-36], \
            qword ptr [rbp-48], dword ptr [rbp-52]
    jmp     st_term
st_empty:
    xor     eax, eax
st_term:
    mov     r10, qword ptr [rbp-48]             ; NUL-terminate
    mov     word ptr [r10+rax*2], 0
    mov     dword ptr [rbp-56], eax             ; wchars (excl NUL)
    mov     rcx, qword ptr [rbp-24]             ; g_zi_titles[index] = dst
    lea     r8, [g_zi_titles]
    mov     rdx, qword ptr [rbp-48]
    mov     qword ptr [r8+rcx*8], rdx
    lea     r8, [g_zi_tlens]                   ; g_zi_tlens[index] = wchars
    mov     edx, dword ptr [rbp-56]
    mov     dword ptr [r8+rcx*4], edx
    mov     eax, dword ptr [rbp-56]            ; advance tap by (wchars+1)*2
    inc     eax
    lea     eax, [eax*2]
    add     dword ptr [g_zi_tap], eax
    FRAME_EPILOG
    ret
st_full:
    mov     rcx, qword ptr [rbp-24]
    cmp     rcx, ZI_MAXENT
    jae     st_ret
    lea     r8, [g_zi_titles]                  ; empty-title fallback keeps indices aligned
    lea     rdx, [zi_empty_w]
    mov     qword ptr [r8+rcx*8], rdx
    lea     r8, [g_zi_tlens]
    mov     dword ptr [r8+rcx*4], 0
st_ret:
    FRAME_EPILOG
    ret
zi_stage_title endp

; =============================================================================
; zi_walk() -> eax.  Walk the entry array at g_zi_p..g_zi_jend once.
;   g_zi_mode = 0 (stage): decode every title into g_zi_titles[], count into
;               g_zi_stg_n; build nothing.  Returns 0.
;   g_zi_mode = 1 (commit): build + vault_build_entry only for entries whose
;               g_sel[e] is set; others are parsed and discarded.  Returns the
;               number of entries actually imported.
; =============================================================================
zi_walk proc frame
    FRAME_PROLOG 112                            ; grown from 96: [rbp-72]/[rbp-80] are the
                                                ; forward-progress markers below, and must sit
                                                ; ABOVE the 32-byte callee shadow (a callee
                                                ; would clobber a marker inside it).
    mov     dword ptr [g_zi_count], 0
    mov     dword ptr [g_zi_e], 0
    mov     qword ptr [rbp-72], 0              ; entry-loop progress marker (0 = none yet)
    mov     al, '['
    call    zj_skipch
zij_entry:
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [rbp-72]             ; FORWARD-PROGRESS guard: if this entry
    je      zij_done                            ;   iteration begins where the last one did,
    mov     qword ptr [rbp-72], r10             ;   the cursor is stuck on malformed json ->
                                                ;   stop.  Without it a crafted vordr.json
                                                ;   spins zij_entry forever (a DoS; found by
                                                ;   the jfuzz structural fuzzer).
    cmp     r10, qword ptr [g_zi_jend]
    jae     zij_done
    movzx   eax, byte ptr [r10]
    cmp     eax, ']'
    je      zij_done
    cmp     eax, ','
    jne     zij_e0
    inc     r10
    mov     qword ptr [g_zi_p], r10
zij_e0:
    mov     al, '{'
    call    zj_skipch
    ; per-entry build flag: commit mode builds only g_sel[e]-selected entries
    mov     dword ptr [g_zi_build], 0
    cmp     dword ptr [g_zi_mode], 1
    jne     zij_titr                            ; stage -> build nothing
    mov     eax, dword ptr [g_zi_e]
    cmp     eax, ZI_MAXENT
    jae     zij_titr
    lea     r10, [g_sel]
    movzx   ecx, byte ptr [r10+rax]
    mov     dword ptr [g_zi_build], ecx
zij_titr:
    lea     rcx, [zl_title]                     ; "title":
    mov     edx, 8
    call    zj_lit
    lea     rcx, [g_zi_sbuf]                    ; decode title -> sbuf
    call    zj_str
    mov     dword ptr [rbp-52], eax             ; title UTF-8 len
    cmp     dword ptr [g_zi_mode], 1
    je      zij_titdone                         ; commit: title already staged
    mov     ecx, dword ptr [g_zi_e]             ; stage: capture the title
    lea     rdx, [g_zi_sbuf]
    mov     r8d, dword ptr [rbp-52]
    call    zi_stage_title
zij_titdone:
    lea     rcx, [zl_fields]                    ; ,"fields":[
    mov     edx, 11
    call    zj_lit
    mov     dword ptr [g_zi_ap], 0              ; fresh arena for this entry
    mov     dword ptr [rbp-24], 0               ; n (field slot)
    mov     qword ptr [rbp-80], 0              ; field-loop progress marker (reset per entry)
zij_field:
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [rbp-80]             ; FORWARD-PROGRESS guard (see zij_entry): a
    je      zij_fend                            ;   stuck cursor in the fields array would
    mov     qword ptr [rbp-80], r10             ;   otherwise spin zij_field forever
    cmp     r10, qword ptr [g_zi_jend]
    jae     zij_fend
    movzx   eax, byte ptr [r10]
    cmp     eax, ']'
    je      zij_fend
    cmp     eax, ','
    jne     zij_f0
    inc     r10
    mov     qword ptr [g_zi_p], r10
zij_f0:
    mov     al, '{'
    call    zj_skipch
    lea     rcx, [zl_type]                      ; "type":
    mov     edx, 7
    call    zj_lit
    call    zj_num
    mov     dword ptr [rbp-28], eax             ; type
    lea     rcx, [zl_label]                     ; ,"label":
    mov     edx, 9
    call    zj_lit
    lea     rcx, [g_zi_sbuf]                    ; decode label -> sbuf
    call    zj_str
    mov     dword ptr [rbp-32], eax             ; labellen
    mov     qword ptr [rbp-40], 0               ; label wide (0 = none)
    test    eax, eax
    jz      zij_lbldone
    lea     rcx, [g_zi_sbuf]
    mov     edx, eax
    call    zi_u2w
    mov     qword ptr [rbp-40], rax             ; label wide
zij_lbldone:
    lea     rcx, [zl_value]                     ; ,"value":
    mov     edx, 9
    call    zj_lit
    lea     rcx, [g_zi_sbuf]                    ; decode value -> sbuf
    call    zj_str
    mov     dword ptr [rbp-48], eax             ; vallen
    mov     al, '}'
    call    zj_skipch
    ; ---- build the field (selected entries only; else parsed + discarded) ----
    cmp     dword ptr [g_zi_build], 0
    je      zij_field
    cmp     dword ptr [rbp-24], MAX_FIELDS      ; g_field_list full? discard extra
    jae     zij_field                           ; fields (already parsed, stays in sync)
    mov     eax, dword ptr [rbp-28]             ; type
    cmp     eax, VF_IMAGE
    je      zij_att
    cmp     eax, VF_FILE
    je      zij_att
    ; text field: value UTF-8 -> wide
    lea     rcx, [g_zi_sbuf]
    mov     edx, dword ptr [rbp-48]
    call    zi_u2w                              ; rax = value wide
    mov     r10d, dword ptr [rbp-24]            ; slot
    imul    r10d, r10d, 24
    lea     r11, [g_field_list]
    add     r11, r10
    mov     ecx, dword ptr [rbp-28]
    mov     qword ptr [r11+0], rcx
    mov     rcx, qword ptr [rbp-40]             ; label wide
    mov     qword ptr [r11+8], rcx
    mov     qword ptr [r11+16], rax
    inc     dword ptr [rbp-24]
    jmp     zij_field
zij_att:
    ; attachment: value = zip path in g_zi_sbuf
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [g_zi_slot], eax
    mov     ecx, dword ptr [rbp-28]             ; base type
    mov     rdx, qword ptr [rbp-40]             ; label wide
    lea     r8, [g_zi_sbuf]                     ; path
    mov     r9d, dword ptr [rbp-48]             ; pathlen
    call    zi_addattach
    test    eax, eax
    jz      zij_field                           ; skipped -> slot unchanged
    inc     dword ptr [rbp-24]
    jmp     zij_field
zij_fend:
    mov     al, ']'
    call    zj_skipch
    mov     al, '}'
    call    zj_skipch
    ; build the entry (commit + selected) if it accumulated any fields
    cmp     dword ptr [g_zi_build], 0
    je      zij_eadv
    mov     eax, dword ptr [rbp-24]
    test    eax, eax
    jz      zij_eadv
    mov     dword ptr [g_field_n], eax
    call    vault_build_entry
    test    eax, eax
    jnz     zij_eadv
    inc     dword ptr [g_zi_count]
zij_eadv:
    inc     dword ptr [g_zi_e]
    jmp     zij_entry
zij_done:
    cmp     dword ptr [g_zi_mode], 1
    je      zij_dret
    mov     eax, dword ptr [g_zi_e]             ; stage: publish the entry count
    cmp     eax, ZI_MAXENT                      ; clamp: g_zi_titles/g_zi_tlens hold only
    jbe     @F                                  ; ZI_MAXENT slots (entries past that were
    mov     eax, ZI_MAXENT                      ; dropped by zi_stage_title) - a larger
@@:                                            ; count would drive an OOB read in the GUI
    mov     dword ptr [g_zi_stg_n], eax
zij_dret:
    mov     eax, dword ptr [g_zi_count]
    FRAME_EPILOG
    ret
zi_walk endp

; zi_free_wipe() - release the per-entry arena (if held) and wipe the UTF-8 pw.
zi_free_wipe proc frame
    FRAME_PROLOG 32
    mov     rcx, qword ptr [g_zi_arena]
    test    rcx, rcx
    jz      zfw_wipe
    mov     rdx, ZI_ARENA
    call    mem_free
    mov     qword ptr [g_zi_arena], 0
zfw_wipe:
    lea     rcx, [g_zi_u8pw]
    mov     edx, ZI_PWCAP
    call    secure_zero
    mov     dword ptr [g_zi_pwlen], 0
    FRAME_EPILOG
    ret
zi_free_wipe endp

; =============================================================================
; zi_stage(rcx=raw, edx=rawlen, r8=wide pw, r9d=pw bytes) -> eax
;   >=0  entries staged: their titles are in g_zi_titles[0..n) / g_zi_tlens,
;        g_zi_stg_n = n.  The arena + decrypted json + password are KEPT so a
;        subsequent zi_commit (or zi_abort) can finish the job.
;   -3   wrong password        -1   not a readable Vordr zip / error
; On every error path the arena is freed and the password wiped.
; =============================================================================
public zi_stage
zi_stage proc frame
    FRAME_PROLOG 160                            ; room for the 8-arg WCtoMB arg spill
    mov     qword ptr [rbp-24], rcx             ; raw
    mov     dword ptr [rbp-28], edx             ; rawlen
    ; wide pw -> UTF-8 g_zi_u8pw (stage count in r9d: WINCALL rax-clobber footgun)
    shr     r9d, 1                              ; wide chars
    mov     dword ptr [rbp-32], r9d
    WINCALL WideCharToMultiByte, CP_UTF8_, 0, r8, dword ptr [rbp-32], addr g_zi_u8pw, ZI_PWCAP, 0, 0
    mov     dword ptr [g_zi_pwlen], eax
    test    eax, eax                            ; 0 with a non-empty password = it did
    jnz     zs_pwok                             ;   not fit.  Report "wrong password"
    cmp     dword ptr [rbp-32], 0               ;   rather than silently trying the
    je      zs_pwok                             ;   empty one - which is not what the
    mov     dword ptr [rbp-40], -3               ;   archive was sealed with (ZE_PWCAP)
    jmp     zs_fail
zs_pwok:
    lea     rax, [g_zi_u8pw]
    mov     qword ptr [g_zi_pwptr], rax
    ; allocate the per-entry arena
    mov     rcx, ZI_ARENA
    call    mem_alloc
    test    rax, rax
    jz      zs_err
    mov     qword ptr [g_zi_arena], rax
    ; scan members
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-28]
    call    zi_scan
    call    attach_reset                        ; start fresh pending-attachment set
    ; find + decrypt the data file
    lea     rcx, [zi_jsonname]
    mov     edx, 10
    call    zi_find
    cmp     eax, -1
    jne     zs_json
    mov     dword ptr [rbp-40], -1              ; no vordr.json in the archive
    jmp     zs_fail
zs_json:
    mov     dword ptr [rbp-36], eax             ; member idx
    mov     ecx, eax
    call    zi_decrypt
    test    eax, eax
    jz      zs_json_ok
    mov     dword ptr [rbp-40], eax             ; -3 wrong pw / -1 corrupt
    jmp     zs_fail
zs_json_ok:
    mov     ecx, dword ptr [rbp-36]
    call    zi_plain                            ; rax=ptr edx=len
    mov     qword ptr [g_zi_jptr], rax          ; persist json for the commit pass
    mov     dword ptr [g_zi_jlen], edx
    mov     qword ptr [g_zi_p], rax
    add     rax, rdx
    mov     qword ptr [g_zi_jend], rax
    mov     dword ptr [g_zi_tap], 0
    mov     dword ptr [g_zi_stg_n], 0
    mov     dword ptr [g_zi_mode], 0            ; STAGE: collect titles
    call    zi_walk
    mov     eax, dword ptr [g_zi_stg_n]         ; keep arena + pw for zi_commit
    FRAME_EPILOG
    ret
zs_fail:
    call    zi_free_wipe
    mov     eax, dword ptr [rbp-40]
    FRAME_EPILOG
    ret
zs_err:
    call    zi_free_wipe
    mov     eax, -1
    FRAME_EPILOG
    ret
zi_stage endp

; =============================================================================
; zi_commit() -> eax = entries imported.  Re-walk the staged json, building only
;   the entries whose g_sel[e] is set, then free the arena + wipe the password.
; =============================================================================
public zi_commit
zi_commit proc frame
    FRAME_PROLOG 48
    mov     rax, qword ptr [g_zi_jptr]
    mov     qword ptr [g_zi_p], rax
    mov     edx, dword ptr [g_zi_jlen]
    add     rax, rdx
    mov     qword ptr [g_zi_jend], rax
    mov     dword ptr [g_zi_ap], 0
    mov     dword ptr [g_zi_mode], 1            ; COMMIT: build selected entries
    call    zi_walk
    mov     dword ptr [rbp-24], eax
    call    zi_free_wipe
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
zi_commit endp

; zi_abort() - discard a staged import (user cancelled the selection).
public zi_abort
zi_abort proc frame
    FRAME_PROLOG 32
    call    zi_free_wipe
    FRAME_EPILOG
    ret
zi_abort endp

; zfz_rand() -> rax = next xorshift64 value (updates g_zfz_rng).  Leaf; rcx dead.
zfz_rand proc
    mov     rax, qword ptr [g_zfz_rng]
    mov     rcx, rax
    shl     rcx, 13
    xor     rax, rcx
    mov     rcx, rax
    shr     rcx, 7
    xor     rax, rcx
    mov     rcx, rax
    shl     rcx, 17
    xor     rax, rcx
    mov     qword ptr [g_zfz_rng], rax
    ret
zfz_rand endp

; =============================================================================
; cmd_zfuzz - structural fuzzer for the ZIP import parser.  The
;   .vaultz format is STORED-only AES-zip (no DEFLATE, so there is no inflate
;   path to fuzz); the attacker-controlled surface is zi_scan, which reads
;   local-header size fields with no crypto gate in front of it.  This
;   deterministically xorshift-mutates a copy of a valid vordr.json local
;   header (bit flips, byte sets, TLV size/namelen smashes, truncations),
;   runs zi_scan, then touches the last byte of every recorded member's
;   decrypt region {salt,verify,cipher[usize],hmac} - the exact bytes
;   zi_decrypt would read/write.  With zi_scan's bounds guard every touch is
;   in-range; a guard regression (or a memory-bomb usize) would fault here.
;   ZFZ_ITERS iterations; seed is random per run and logged (G7, --seed N to
;   reproduce); exit 0 = completed with no crash.
; =============================================================================
LANDING_PAD
public cmd_zfuzz
cmd_zfuzz proc frame
    FRAME_PROLOG 112
    ; [rbp-16]=buf [rbp-32]=iters [rbp-40]=scanned [rbp-48]=rejected
    ; [rbp-56]=curlen [rbp-64]=nmut [rbp-72]=member i [rbp-80]=n
    call    fuzz_seed                                     ; G7: random (or --seed) + logged
    mov     qword ptr [g_zfz_rng], rax
    mov     rcx, ZFZ_FIX_LEN
    call    mem_alloc
    test    rax, rax
    jz      zfz_oom
    mov     qword ptr [rbp-16], rax
    mov     qword ptr [rbp-40], 0                          ; scanned
    mov     qword ptr [rbp-48], 0                          ; rejected
    mov     qword ptr [rbp-32], ZFZ_ITERS
zfz_iter:
    cmp     qword ptr [rbp-32], 0
    je      zfz_report
    mov     r11, qword ptr [rbp-16]                        ; restore pristine fixture
    lea     r10, [zfz_fix]
    xor     r8, r8
zfz_restore:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r11+r8], al
    inc     r8
    cmp     r8, ZFZ_FIX_LEN
    jb      zfz_restore
    mov     qword ptr [rbp-56], ZFZ_FIX_LEN                ; curlen
    call    zfz_rand
    and     rax, 3
    inc     rax
    mov     qword ptr [rbp-64], rax
zfz_mut:
    cmp     qword ptr [rbp-64], 0
    je      zfz_run
    mov     rax, qword ptr [rbp-56]
    test    rax, rax
    jz      zfz_mutnext
    call    zfz_rand
    mov     rcx, rax                                       ; r
    xor     edx, edx
    div     qword ptr [rbp-56]                             ; rdx = off = r mod curlen
    mov     r8, rdx
    mov     rax, rcx
    shr     rax, 2
    and     rax, 3
    cmp     rax, 0
    je      zfz_flip
    cmp     rax, 1
    je      zfz_set
    cmp     rax, 2
    je      zfz_trunc
    mov     rax, r8                                        ; op 3: smash a u32
    add     rax, 4
    cmp     rax, qword ptr [rbp-56]
    ja      zfz_mutnext
    mov     r9, qword ptr [rbp-16]
    add     r9, r8
    mov     rax, rcx
    shr     rax, 8
    mov     dword ptr [r9], eax
    jmp     zfz_mutnext
zfz_flip:
    mov     r9, qword ptr [rbp-16]
    add     r9, r8
    mov     rax, rcx
    and     rax, 7
    mov     r10, 1
    mov     rcx, rax
    shl     r10, cl
    mov     al, byte ptr [r9]
    xor     al, r10b
    mov     byte ptr [r9], al
    jmp     zfz_mutnext
zfz_set:
    mov     r9, qword ptr [rbp-16]
    add     r9, r8
    mov     rax, rcx
    shr     rax, 8
    mov     byte ptr [r9], al
    jmp     zfz_mutnext
zfz_trunc:
    mov     rax, rcx
    shr     rax, 8
    xor     edx, edx
    mov     r10, ZFZ_FIX_LEN + 1
    div     r10
    mov     qword ptr [rbp-56], rdx
zfz_mutnext:
    dec     qword ptr [rbp-64]
    jmp     zfz_mut
zfz_run:
    mov     rcx, qword ptr [rbp-16]
    mov     edx, dword ptr [rbp-56]
    call    zi_scan                                        ; -> eax = member count
    mov     dword ptr [rbp-80], eax
    test    eax, eax
    jz      zfz_rej
    inc     qword ptr [rbp-40]                             ; scanned (>=1 member)
    mov     qword ptr [rbp-72], 0
zfz_walk:
    mov     eax, dword ptr [rbp-80]
    cmp     qword ptr [rbp-72], rax
    jae     zfz_next
    mov     eax, dword ptr [rbp-72]
    imul    eax, eax, MEMREC
    lea     r10, [g_zi_mem]
    add     r10, rax                                       ; -> member record
    ; touch the last byte of the decrypt region: dataptr + usize + 27
    mov     rax, qword ptr [r10+16]                        ; dataptr
    mov     ecx, dword ptr [r10+24]                        ; usize
    add     rax, rcx
    movzx   edx, byte ptr [rax+27]                         ; faults if guard is wrong
    ; touch the last name byte: nameptr + namelen - 1 (bounded by dataptr<=end)
    mov     ecx, dword ptr [r10+8]                         ; namelen
    test    ecx, ecx
    jz      zfz_walknext
    mov     rax, qword ptr [r10+0]                         ; nameptr
    add     rax, rcx
    movzx   edx, byte ptr [rax-1]
zfz_walknext:
    inc     qword ptr [rbp-72]
    jmp     zfz_walk
zfz_rej:
    inc     qword ptr [rbp-48]
zfz_next:
    dec     qword ptr [rbp-32]
    jmp     zfz_iter
zfz_report:
    lea     rcx, [zfz_m1]
    mov     edx, zfz_m1_len
    call    print_a
    mov     rcx, ZFZ_ITERS
    call    print_u64
    lea     rcx, [zfz_m2]
    mov     edx, zfz_m2_len
    call    print_a
    mov     rcx, qword ptr [rbp-40]
    call    print_u64
    lea     rcx, [zfz_m3]
    mov     edx, zfz_m3_len
    call    print_a
    mov     rcx, qword ptr [rbp-48]
    call    print_u64
    lea     rcx, [zfz_m4]
    mov     edx, zfz_m4_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
zfz_oom:
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_zfuzz endp

; =============================================================================
; cmd_jfuzz - structural fuzzer for the DECRYPTED-JSON parser (zi_walk / zj_str /
;   zj_num / zj_lit / zi_u2w / zi_stage_title).  cmd_zfuzz covers only the
;   pre-crypto zi_scan surface; this closes the coverage gap on everything
;   downstream of decryption.  It mutates a valid vordr.json seed and drives the
;   STAGE pass (g_zi_mode=0), which decodes every title and label (JSON strings +
;   the UTF-8->wide conversion) without needing an open vault.  The parser is
;   bounds-safe by construction (reads are gated by g_zi_p < g_zi_jend, writes to
;   g_zi_sbuf/arena are capped); this proves it stays crash-free under mutation.
;   Survives every iteration => exit 0 = pass.
; =============================================================================
.data
CSTR jfz_ok,  "jfuzz: PASS ("
CSTR jfz_ok2, " iters, 0 crashes in the decrypted-json parser)",13,10
jfz_seed label byte
    db '[{"title":"account","fields":[{"type":1,"label":"user","value":"bob"},'
    db '{"type":2,"label":"note","value":"hello world"}]},'
    db '{"title":"second","fields":[{"type":1,"label":"x","value":"y"}]}]'
jfz_seed_end label byte
JFZ_SEED_LEN equ jfz_seed_end - jfz_seed
JFZ_ITERS    equ 20000

.data?
align 8
jfz_buf     db 1024 dup (?)

.code
LANDING_PAD
public cmd_jfuzz
cmd_jfuzz proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=iters  [rbp-32]=curlen  [rbp-40]=nmut
    call    fuzz_seed                                ; G7: random (or --seed) + logged
    mov     qword ptr [g_zfz_rng], rax
    mov     rcx, ZI_ARENA                            ; arena: zi_walk decodes wide here
    call    mem_alloc
    test    rax, rax
    jz      jfz_oom
    mov     qword ptr [g_zi_arena], rax
    lea     rax, [g_zi_u8pw]
    mov     qword ptr [g_zi_pwptr], rax
    mov     dword ptr [g_zi_pwlen], 0
    mov     qword ptr [rbp-24], JFZ_ITERS
jfz_iter:
    cmp     qword ptr [rbp-24], 0
    je      jfz_report
    lea     r10, [jfz_seed]                          ; restore pristine seed
    lea     r11, [jfz_buf]
    xor     r8, r8
jfz_restore:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r11+r8], al
    inc     r8
    cmp     r8, JFZ_SEED_LEN
    jb      jfz_restore
    mov     qword ptr [rbp-32], JFZ_SEED_LEN         ; curlen
    call    zfz_rand                                 ; 1..4 mutations this round
    and     rax, 3
    inc     rax
    mov     qword ptr [rbp-40], rax
jfz_mut:
    cmp     qword ptr [rbp-40], 0
    je      jfz_run
    mov     rax, qword ptr [rbp-32]
    test    rax, rax
    jz      jfz_mutnext
    call    zfz_rand
    mov     rcx, rax                                 ; r
    xor     edx, edx
    div     qword ptr [rbp-32]                       ; rdx = off = r mod curlen
    mov     r8, rdx
    mov     rax, rcx
    shr     rax, 2
    and     rax, 3
    cmp     rax, 2
    je      jfz_trunc                                ; op 2: truncate
    lea     r9, [jfz_buf]                            ; op 0/1/3: set byte at off
    add     r9, r8
    mov     rax, rcx
    shr     rax, 8
    mov     byte ptr [r9], al
    jmp     jfz_mutnext
jfz_trunc:
    mov     rax, rcx
    shr     rax, 8
    xor     edx, edx
    mov     r10, JFZ_SEED_LEN + 1
    div     r10
    mov     qword ptr [rbp-32], rdx                  ; curlen = r mod (seedlen+1)
jfz_mutnext:
    dec     qword ptr [rbp-40]
    jmp     jfz_mut
jfz_run:
    lea     rax, [jfz_buf]
    mov     qword ptr [g_zi_jptr], rax
    mov     qword ptr [g_zi_p], rax
    mov     r10, qword ptr [rbp-32]
    mov     dword ptr [g_zi_jlen], r10d
    add     rax, r10
    mov     qword ptr [g_zi_jend], rax
    mov     dword ptr [g_zi_tap], 0
    mov     dword ptr [g_zi_stg_n], 0
    mov     dword ptr [g_zi_mode], 0                 ; STAGE: decode titles/labels
    call    zi_walk
    dec     qword ptr [rbp-24]
    jmp     jfz_iter
jfz_report:
    call    zi_free_wipe                             ; release the arena + wipe pw
    lea     rcx, [jfz_ok]
    mov     edx, jfz_ok_len
    call    print_a
    mov     rcx, JFZ_ITERS
    call    print_u64
    lea     rcx, [jfz_ok2]
    mov     edx, jfz_ok2_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
jfz_oom:
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_jfuzz endp

end
