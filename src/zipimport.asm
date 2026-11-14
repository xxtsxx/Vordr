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
extern secmem_alloc:proc                ; the per-entry arena holds every imported value
extern secmem_free:proc                 ;   as plaintext: locked, like the vault body
extern VirtualLock:proc                 ; best-effort pin of the raw archive, which the
extern VirtualUnlock:proc               ;   decrypt runs over IN PLACE
extern secure_zero:proc
extern pbkdf2_ae:proc                    ; PBKDF2-HMAC-SHA1 1000 iters -> g_ae_dk
extern aes_expand_key:proc
extern aes_ctr_xor:proc
extern hmac_sha1:proc
extern sha256_hash:proc
extern ct_memcmp:proc                    ; constant-time compare (hardening.asm)
extern MultiByteToWideChar:proc
extern WideCharToMultiByte:proc
extern attach_reset_pending:proc
extern attach_stage:proc
extern vault_build_entry:proc
extern vault_entry_len:proc             ; walking a decrypted .vordr import source
extern entry_field_ptr:proc             ;   (pointer-based: it is NOT the live body)
extern entry_has_field:proc
extern print_a:proc
extern print_u64:proc
extern fuzz_seed:proc                   ; G7: reproducible/logged fuzzer seed (main.asm)
externdef g_ae_dk:byte
externdef g_body_ptr:qword
externdef g_body_len:qword
externdef g_field_list:qword
externdef g_field_n:dword
externdef g_sel:byte                      ; per-entry import selection mask (from gui.asm)

ARF_SIZE    equ 68
ATT_FILE_MAX equ 10000000h                ; 256 MiB per-attachment cap (mirrors vault/gui)
CP_UTF8_    equ 65001
ZI_MAXMEM   equ 8192                      ; max archive members
MAX_SEL     equ 8192                      ; mirrors gui.asm/vault.asm - constcheck gates
ZI_MAXENT   equ MAX_SEL                   ;   the trio, so the checklist, the selection
                                          ;   mask and the merge cannot drift apart
ZI_ARENA    equ 4*1024*1024              ; per-entry wide/blob scratch
ZI_SBUF     equ 256*1024                  ; one string's decoded UTF-8
ZI_TBUF     equ 1024*1024                 ; persistent staged-title wide storage
; g_field_list capacity.  This MUST equal main.asm's MAX_FIELDS - that is the module
; that actually allocates the array (dq 3*MAX_FIELDS).  It said 56 while main.asm and
; gui.asm both said 96, and the comment claimed they matched, so an imported entry
; silently lost every field past the 56th even though the array had room for 96.
; Too small only loses data; too LARGE would overrun the array, so if these ever drift
; again, drift downward.  There is no cross-module constant check to catch this.
MAX_FIELDS  equ 96                        ; == main.asm MAX_FIELDS (verified 2026-07-27)
MEMREC      equ 32                        ; {nameptr8, namelen4, _4, dataptr8, usize4, _4}

.data?
align 8
g_zfz_rng   dq ?                          ; fuzzzip xorshift64 state (dbg/test only)
g_zi_end    dq ?                          ; raw end
g_zi_raw    dq ?                          ; the archive being staged (pinned while held)
g_zi_rawlen dq ?
g_zi_rawlk  dd ?                          ; 1 = VirtualLock on it succeeded
g_zi_pwptr  dq ?                          ; UTF-8 pw ptr (= g_zi_u8pw)
g_zi_pwlen  dd ?
ZI_PWCAP    equ 1024                      ; 254 wide chars can be 762 UTF-8 bytes; the
ZI_NBUF     equ 1024                      ; decoded attachment "name" capacity
public g_zi_u8pw, g_zi_sbuf, g_zi_nbuf, g_zi_ref ; pinned + crash-wiped by secmem.asm
public g_zi_rk, g_zi_tbuf, g_zi_err, g_zi_p, g_zi_jend
g_zi_jcap   dq ?                          ; secmem byte capacity of g_zi_jptr (0 = none)
g_zi_err    dd ?                          ; sticky JSON/UTF-8 decode error flag
            dd ?                          ; keep natural alignment of subsequent globals
g_zi_u8pw   db ZI_PWCAP dup (?)           ;   old 512/500 truncated to an EMPTY password
g_zi_n      dd ?                          ; member count
public g_zi_unsup
g_zi_unsup  dd ?                          ; zi_scan met a member Vordr cannot read
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
g_zi_anamen dd ?                          ; decoded "name" length; 0 = predates the key
g_zi_nbuf   db ZI_NBUF dup (?)            ; decoded "name" (kept apart from g_zi_sbuf,
                                          ;   which still holds the value/path)
g_zi_has_sha dd ?                         ; 1 = attachment field carries "sha256"
g_zi_sha_hex db 128 dup (?)               ; decoded "sha256" hex string
g_zi_sha_exp db 32 dup (?)                ; expected SHA-256(plaintext)
g_zi_sha_act db 32 dup (?)                ; actual SHA-256(plaintext)
g_zi_mode   dd ?                          ; zi_walk: 0 = stage (titles), 1 = commit (build)
g_zi_e      dd ?                          ; zi_walk: running entry index
g_zi_build  dd ?                          ; zi_walk: current entry builds fields (1) or discards (0)
g_zi_jptr   dq ?                          ; decrypted vordr.json ptr (persists stage -> commit)
g_zi_jlen   dd ?
g_zi_tap    dd ?                          ; staged-title arena bump offset
align 8
public g_zi_stg_n, g_zi_trunc
g_zi_stg_n  dd ?                          ; number of entries staged (titles ready)
g_zi_trunc  dd ?                          ; source total when it exceeded ZI_MAXENT
                                          ;   (0 = everything fitted)
public g_zi_titles
g_zi_titles dq ZI_MAXENT dup (?)          ; per-entry wide title ptr (into g_zi_tbuf)
public g_zi_tlens
g_zi_tlens  dd ZI_MAXENT dup (?)          ; per-entry wide title length (wchars)
g_zi_tbuf   db ZI_TBUF dup (?)            ; persistent staged-title text (wide)
public g_zi_hide
g_zi_hide   db ZI_MAXENT dup (?)          ; 1 = staged row the checklist must not show.
                                          ;   Staging CANNOT compact these away: fed_merge
                                          ;   indexes g_sel by the SOURCE entry index, so
                                          ;   dropping rows would slide every tick onto the
                                          ;   wrong record.  Stage all, hide some.

.const
zi_jsonname db "vordr.json"
zi_empty_w  dw 0                          ; NUL wide string (title fallback on overflow)
zl_title    db '"title":'
zl_fields   db ',"fields":['
zl_type     db '"type":'
zl_label    db ',"label":'
zl_value    db ',"value":'
zl_name     db ',"name":'                  ; optional, attachments only (see zi_addattach)
zl_sha256   db ',"sha256":'                ; optional, attachments only: SHA-256(plaintext)

; --- fuzzzip fixture: a minimal WinZip-AES STORED archive for vordr.json with
; LFH (usize=256, csize=284), Central Directory (67B at +335), and EOCD (22B).
align 4
zfz_fix label byte
    dd  04034b50h                         ; local file header signature
    dw  20                                ; version needed
    dw  1                                 ; flags (bit0 = encrypted)
    dw  99                                ; method = AE-x
    dw  0, 0                              ; mod time, mod date
    dd  0                                 ; crc32
    dd  284                               ; csize = 18 hdr + 256 cipher + 10 hmac
    dd  256                               ; usize (cipher length)
    dw  10                                ; namelen
    dw  11                                ; extralen: the AE record zi_scan requires
    db  'v','o','r','d','r','.','j','s','o','n'
    dw  9901h, 7, 2                       ; AE extra: id, size 7, AE-2
    db  'A','E', 3                        ;   vendor, strength 3 = AES-256
    dw  0                                 ;   actual method: stored
    db  284 dup (0AAh)                    ; member data (garbage salt/verify/cipher/hmac)
    dd  02014b50h                         ; central directory header signature (@ +335)
    dw  20, 20                            ; version made by, version needed
    dw  1                                 ; flags
    dw  99                                ; method = AE-x
    dw  0, 0                              ; mod time, mod date
    dd  0                                 ; crc32
    dd  284                               ; csize
    dd  256                               ; usize
    dw  10                                ; namelen
    dw  11                                ; extralen
    dw  0, 0, 0                           ; commentlen, disk, internal attrs
    dd  0                                 ; external attrs
    dd  0                                 ; local header offset
    db  'v','o','r','d','r','.','j','s','o','n'
    dw  9901h, 7, 2
    db  'A','E', 3
    dw  0
    dd  06054b50h                         ; EOCD signature (@ +402)
    dw  0, 0                              ; disk numbers
    dw  1, 1                              ; entries on disk, total entries
    dd  67                                ; central directory size
    dd  335                               ; central directory offset
    dw  0                                 ; comment length
ZFZ_FIX_LEN equ 424
.errnz ($ - zfz_fix) - ZFZ_FIX_LEN
ZFZ_ITERS   equ 100000
CSTR zfz_m1, "fuzzzip: "
CSTR zfz_m2, " iters  "
CSTR zfz_m3, " scanned  "
CSTR zfz_m4, " rejected  0 crashes",13,10
CSTR zfz_thin, "fuzzzip: FAIL - almost nothing got past the scan, so the parser was barely exercised: the fixture no longer looks like a member zi_scan accepts",13,10

.code

; =============================================================================
; zi_scan(rcx = raw, edx = rawlen) -> eax = member count.
;   Locates the End of Central Directory (PK\x05\x06), walks Central Directory
;   records (PK\x01\x02) for authoritative member metadata, and cross-checks
;   each Local File Header (PK\x03\x04) before recording into g_zi_mem.
; =============================================================================
zi_scan proc frame
    FRAME_PROLOG 96
    mov     dword ptr [g_zi_unsup], 0
    mov     dword ptr [g_zi_n], 0
    mov     edx, edx
    cmp     rdx, 22
    jb      zs_empty
    mov     qword ptr [rbp-16], rcx             ; raw_base
    lea     rax, [rcx+rdx]
    mov     qword ptr [rbp-24], rax             ; raw_end
    mov     qword ptr [g_zi_end], rax
    ; Search backwards from raw_end - 22 (up to 65535 comment bytes) for EOCD
    mov     r9, rcx                             ; min_eocd = raw_base
    cmp     rdx, 22 + 65535
    jbe     @F
    mov     r9, rax
    sub     r9, 22 + 65535
@@: lea     r10, [rax-22]                       ; p = raw_end - 22
zs_eocd_lp:
    cmp     r10, r9
    jb      zs_empty
    cmp     dword ptr [r10], 06054b50h
    jne     zs_eocd_prev
    movzx   eax, word ptr [r10+20]              ; comment length
    lea     r8, [r10+rax+22]
    cmp     r8, qword ptr [rbp-24]
    je      zs_eocd_ok
zs_eocd_prev:
    dec     r10
    jmp     zs_eocd_lp
zs_eocd_ok:
    cmp     word ptr [r10+4], 0                 ; multi-disk archives unsupported
    jne     zs_unsup
    cmp     word ptr [r10+6], 0
    jne     zs_unsup
    movzx   eax, word ptr [r10+10]              ; total entries
    cmp     ax, 0FFFFh                          ; Zip64 sentinel
    je      zs_unsup
    movzx   ecx, word ptr [r10+8]               ; entries on this disk
    cmp     eax, ecx
    jne     zs_empty
    cmp     eax, ZI_MAXMEM                      ; refuse archives exceeding ZI_MAXMEM closed
    ja      zs_empty
    mov     dword ptr [rbp-60], eax             ; total_entries
    mov     eax, dword ptr [r10+16]             ; cd_off (zero-extended)
    mov     ecx, dword ptr [r10+12]             ; cd_size (zero-extended)
    cmp     eax, 0FFFFFFFFh
    je      zs_unsup
    cmp     ecx, 0FFFFFFFFh
    je      zs_unsup
    mov     r8, r10
    sub     r8, qword ptr [rbp-16]              ; eocd_off
    cmp     rax, r8
    ja      zs_empty
    mov     r9, r8
    sub     r9, rax                             ; eocd_off - cd_off
    cmp     rcx, r9
    ja      zs_empty
    mov     r8, qword ptr [rbp-16]
    add     r8, rax
    mov     qword ptr [rbp-32], r8              ; cd_base
    mov     qword ptr [rbp-48], r8              ; cd_cur
    add     r8, rcx
    mov     qword ptr [rbp-40], r8              ; cd_end
    mov     dword ptr [rbp-64], 0               ; count = 0
zs_cd_lp:
    mov     eax, dword ptr [rbp-64]
    cmp     eax, dword ptr [rbp-60]
    jae     zs_cd_end
    cmp     eax, ZI_MAXMEM
    jae     zs_empty
    mov     rcx, qword ptr [rbp-48]             ; cd_cur
    lea     rax, [rcx+46]
    cmp     rax, qword ptr [rbp-40]
    ja      zs_empty
    cmp     dword ptr [rcx], 02014b50h          ; CD signature
    jne     zs_empty
    movzx   r8d, word ptr [rcx+28]              ; cd_namelen
    mov     dword ptr [rbp-76], r8d
    movzx   r9d, word ptr [rcx+30]              ; cd_extralen
    movzx   edx, word ptr [rcx+32]              ; cd_commlen
    lea     rax, [rcx+46]
    add     rax, r8
    add     rax, r9
    add     rax, rdx
    cmp     rax, qword ptr [rbp-40]
    ja      zs_empty
    mov     qword ptr [rbp-56], rax             ; cd_next
    cmp     word ptr [rcx+10], 99               ; method == WinZip AE
    jne     zs_unsup
    mov     eax, dword ptr [rcx+20]             ; csize
    mov     dword ptr [rbp-68], eax
    mov     edx, dword ptr [rcx+24]             ; usize
    cmp     edx, ATT_FILE_MAX                   ; cap per-member size at 256 MiB pre-decrypt
    ja      zs_unsup
    mov     dword ptr [rbp-72], edx
    add     rdx, 28
    cmp     rdx, rax                            ; csize == usize + 28
    jne     zs_unsup
    ; Verify matching Local File Header at raw_base + lfh_off
    mov     eax, dword ptr [rcx+42]             ; lfh_off (zero-extended)
    mov     r11, qword ptr [rbp-16]
    add     r11, rax                            ; lfh
    lea     rdx, [r11+30]
    cmp     rdx, qword ptr [rbp-32]             ; lfh + 30 <= cd_base
    ja      zs_empty
    cmp     dword ptr [r11], 04034b50h
    jne     zs_empty
    cmp     word ptr [r11+8], 99
    jne     zs_unsup
    movzx   eax, word ptr [r11+26]              ; lfh_namelen
    cmp     eax, dword ptr [rbp-76]             ; must match CD namelen
    jne     zs_empty
    movzx   edx, word ptr [r11+6]               ; lfh_flags
    test    edx, 8                              ; bit 3 streaming data descriptor?
    jnz     zs_lfh_name
    mov     eax, dword ptr [r11+18]             ; non-streaming: LFH sizes must match CD
    cmp     eax, dword ptr [rbp-68]
    jne     zs_empty
    mov     eax, dword ptr [r11+22]
    cmp     eax, dword ptr [rbp-72]
    jne     zs_empty
zs_lfh_name:
    xor     r8d, r8d
zs_ncmp:
    cmp     r8d, dword ptr [rbp-76]
    jae     zs_ncmp_ok
    mov     al, byte ptr [rcx+r8+46]
    cmp     al, byte ptr [r11+r8+30]
    jne     zs_empty
    inc     r8d
    jmp     zs_ncmp
zs_ncmp_ok:
    movzx   r8d, word ptr [r11+26]
    movzx   r9d, word ptr [r11+28]              ; lfh_extralen
    lea     rax, [r11+30]
    add     rax, r8
    add     rax, r9                             ; dataptr
    cmp     rax, qword ptr [rbp-32]
    ja      zs_empty
    mov     qword ptr [rbp-88], rax             ; dataptr (keep disjoint from [rbp-76])
    mov     edx, dword ptr [rbp-68]             ; csize (zero-extended)
    mov     r10, qword ptr [rbp-32]
    sub     r10, rax                            ; cd_base - dataptr
    cmp     rdx, r10
    ja      zs_empty
    ; Validate AE-2 extra (0x9901: AES-256 strength 3, stored inner method 0)
    ; Check CD extra first; if omitted there, fall back to LFH extra.
    movzx   r8d, word ptr [rcx+28]              ; cd_namelen
    movzx   r9d, word ptr [rcx+30]              ; cd_extralen
    lea     rax, [rcx+r8+46]                    ; cd extra start
    lea     rdx, [rax+r9]                       ; cd extra end
zs_cd_ex:
    lea     r10, [rax+4]
    cmp     r10, rdx
    ja      zs_try_lfh_ex
    cmp     word ptr [rax], 9901h
    je      zs_ae_chk
    movzx   r10d, word ptr [rax+2]
    lea     rax, [rax+r10+4]
    jmp     zs_cd_ex
zs_try_lfh_ex:
    movzx   r8d, word ptr [r11+26]              ; lfh_namelen
    movzx   r9d, word ptr [r11+28]              ; lfh_extralen
    lea     rax, [r11+r8+30]                    ; lfh extra start
    lea     rdx, [rax+r9]                       ; lfh extra end
zs_lfh_ex:
    lea     r10, [rax+4]
    cmp     r10, rdx
    ja      zs_unsup
    cmp     word ptr [rax], 9901h
    je      zs_ae_chk
    movzx   r10d, word ptr [rax+2]
    lea     rax, [rax+r10+4]
    jmp     zs_lfh_ex
zs_ae_chk:
    lea     r10, [rax+11]
    cmp     r10, rdx
    ja      zs_unsup
    cmp     word ptr [rax+2], 7
    jb      zs_unsup
    cmp     byte ptr [rax+8], 3                 ; AES-256
    jne     zs_unsup
    cmp     word ptr [rax+9], 0                 ; stored inside AES
    jne     zs_unsup
    ; Record validated member into g_zi_mem[count]
    mov     eax, dword ptr [rbp-64]
    imul    eax, eax, MEMREC
    lea     r10, [g_zi_mem]
    add     r10, rax
    lea     rax, [rcx+46]                       ; authoritative CD nameptr
    mov     qword ptr [r10+0], rax
    mov     eax, dword ptr [rbp-76]
    mov     dword ptr [r10+8], eax              ; namelen
    mov     rax, qword ptr [rbp-88]
    mov     qword ptr [r10+16], rax             ; dataptr
    mov     eax, dword ptr [rbp-72]
    mov     dword ptr [r10+24], eax             ; usize
    inc     dword ptr [rbp-64]
    mov     rax, qword ptr [rbp-56]
    mov     qword ptr [rbp-48], rax             ; cd_cur = cd_next
    jmp     zs_cd_lp
zs_cd_end:
    mov     rax, qword ptr [rbp-48]
    cmp     rax, qword ptr [rbp-40]
    jne     zs_empty
zs_done_ok:
    mov     eax, dword ptr [rbp-64]
    mov     dword ptr [g_zi_n], eax
    FRAME_EPILOG
    ret
zs_unsup:
    mov     dword ptr [g_zi_unsup], 1
zs_empty:
    mov     dword ptr [g_zi_n], 0
    xor     eax, eax
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
; zi_decrypt(ecx = member index, rdx = *out_ptr, r8 = *out_len, r9 = *out_cap)
;   -> eax = 0 ok / -3 wrong pw / -1 corrupt.
;   Verifies the 2-byte password check + the HMAC over immutable g_zi_raw, then
;   allocates a fresh locked secmem buffer and AES-256-CTR decrypts into it so
;   multiple records referencing the same member all succeed.
; =============================================================================
zi_decrypt proc frame
    FRAME_PROLOG 128                            ; room for 5-arg WINCALL spill + locals
    mov     qword ptr [rbp-64], rdx             ; *out_ptr
    mov     qword ptr [rbp-72], r8              ; *out_len
    mov     qword ptr [rbp-80], r9              ; *out_cap
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
    ; ---- Allocate locked secmem buffer & copy ciphertext ----
    mov     ecx, dword ptr [rbp-32]             ; usize (zero-extended)
    test    rcx, rcx
    jnz     @F
    mov     ecx, 1
@@: mov     qword ptr [rbp-88], rcx             ; alloc cap = max(usize, 1)
    call    secmem_alloc
    test    rax, rax
    jz      zd_corrupt
    mov     qword ptr [rbp-48], rax             ; plaintext buffer
    mov     r10, qword ptr [rbp-40]             ; src ciphertext in g_zi_raw
    mov     r11, rax                            ; dst secmem buffer
    mov     r8d, dword ptr [rbp-32]
    xor     ecx, ecx
zd_cp:
    cmp     ecx, r8d
    jae     zd_cpd
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    inc     ecx
    jmp     zd_cp
zd_cpd:
    ; ---- AES-256-CTR decrypt in secmem buffer ----
    lea     rcx, [g_ae_dk]
    mov     rdx, 32
    lea     r8, [g_zi_rk]
    call    aes_expand_key
    mov     dword ptr [g_zi_nr], eax
    lea     rcx, [g_zi_ctr]                     ; counter := 0
    xor     eax, eax
    mov     qword ptr [rcx], rax
    mov     qword ptr [rcx+8], rax
    WINCALL aes_ctr_xor, addr g_zi_rk, qword ptr [rbp-48], dword ptr [rbp-32], \
            addr g_zi_ctr, dword ptr [g_zi_nr]
    mov     r10, qword ptr [rbp-64]
    mov     rax, qword ptr [rbp-48]
    mov     qword ptr [r10], rax
    mov     r10, qword ptr [rbp-72]
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [r10], eax
    mov     r10, qword ptr [rbp-80]
    mov     rax, qword ptr [rbp-88]
    mov     qword ptr [r10], rax
    mov     dword ptr [rbp-92], 0
    jmp     zd_wipe_ret
zd_wrongpw:
    mov     dword ptr [rbp-92], -3
    jmp     zd_wipe_ret
zd_corrupt:
    mov     dword ptr [rbp-92], -1
zd_wipe_ret:
    lea     rcx, [g_ae_dk]
    mov     edx, 80
    call    secure_zero
    lea     rcx, [g_zi_rk]
    mov     edx, 15*16
    call    secure_zero
    lea     rcx, [g_zi_ctr]
    mov     edx, 16
    call    secure_zero
    lea     rcx, [g_zi_auth]
    mov     edx, 20
    call    secure_zero
    mov     eax, dword ptr [rbp-92]
    FRAME_EPILOG
    ret
zi_decrypt endp

; =============================================================================
; zi_u2w(rcx = src UTF-8, edx = srclen) -> rax = NUL-terminated wide ptr in the
;   arena (advances g_zi_ap).  Empty input yields an empty wide string; overflow
;   or invalid UTF-8 sets g_zi_err = 1 and returns zi_empty_w safely.
; =============================================================================
zi_u2w proc frame
    FRAME_PROLOG 96                             ; room for 6-arg MBtoWC arg spill
    mov     qword ptr [rbp-24], rcx             ; src
    mov     dword ptr [rbp-28], edx             ; srclen
    mov     r10, qword ptr [g_zi_arena]         ; dst = arena + ap
    mov     eax, dword ptr [g_zi_ap]
    add     r10, rax
    mov     qword ptr [rbp-40], r10             ; dst
    mov     ecx, ZI_ARENA
    sub     ecx, dword ptr [g_zi_ap]           ; remaining bytes
    cmp     ecx, 2
    jle     zw_full                            ; no room for even a NUL
    sub     ecx, 2
    shr     ecx, 1
    cmp     ecx, CONVW_MAX - 1                  ; bound to vault field UTF-16 cap
    jbe     @F
    mov     ecx, CONVW_MAX - 1
@@: mov     dword ptr [rbp-44], ecx             ; wide cap (bounds MBtoWC's writes)
    cmp     dword ptr [rbp-28], 0
    je      zw_empty
    WINCALL MultiByteToWideChar, CP_UTF8_, 8, qword ptr [rbp-24], dword ptr [rbp-28], \
            qword ptr [rbp-40], dword ptr [rbp-44]
    test    eax, eax
    jz      zw_full                             ; conversion/capacity failure -> flag error
    jmp     zw_term
zw_empty:
    xor     eax, eax
zw_term:
    mov     r10, qword ptr [rbp-40]
    mov     word ptr [r10+rax*2], 0
    inc     eax
    lea     eax, [eax*2]
    add     dword ptr [g_zi_ap], eax
    mov     rax, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
zw_full:
    mov     dword ptr [g_zi_err], 1
    lea     rax, [zi_empty_w]
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
; zj_str(rcx = dst UTF-8, edx = dst byte capacity) -> eax = decoded byte length.
;   g_zi_p must point at the opening quote; decodes JSON escapes (strict \uXXXX
;   hex + UTF-16 surrogate pairs, rejecting \u0000 and raw control chars) and
;   advances past the closing quote.  Sets g_zi_err = 1 and returns 0 on error
;   or capacity overflow.
; =============================================================================
public zj_str
zj_str proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx             ; dst
    xor     r11d, r11d                          ; out len
    mov     edx, edx
    cmp     edx, 5
    jb      zjs_bad_nostream
    sub     edx, 4
    mov     dword ptr [rbp-28], edx             ; cap_limit = cap - 4 (room for 4B UTF-8)
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjs_bad
    cmp     byte ptr [r10], '"'
    jne     zjs_bad
    inc     r10                                 ; past opening quote
zjs_lp:
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjs_bad
    movzx   eax, byte ptr [r10]
    cmp     eax, '"'
    je      zjs_close
    cmp     eax, 20h                            ; RFC 8259: raw control chars (< 0x20) invalid
    jb      zjs_bad
    cmp     r11d, dword ptr [rbp-28]            ; output full? fail closed + drain input
    jae     zjs_over
    cmp     eax, '\'
    je      zjs_esc
    mov     rcx, qword ptr [rbp-24]
    mov     byte ptr [rcx+r11], al
    inc     r11d
    inc     r10
    jmp     zjs_lp
zjs_esc:
    inc     r10                                 ; past backslash
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjs_bad
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
    cmp     eax, '"'
    je      zjs_put
    cmp     eax, '\'
    je      zjs_put
    cmp     eax, '/'
    je      zjs_put
    jmp     zjs_bad                             ; invalid escape sequence
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
zjs_put:
    mov     rcx, qword ptr [rbp-24]
    mov     byte ptr [rcx+r11], al
    inc     r11d
    jmp     zjs_lp
zjs_e_u:
    ; Parse 4 strict hex digits -> edx
    lea     rax, [r10+4]
    cmp     rax, qword ptr [g_zi_jend]
    ja      zjs_bad
    xor     edx, edx
    mov     r9d, 4
zjs_uhex1:
    movzx   eax, byte ptr [r10]
    inc     r10
    cmp     eax, '0'
    jb      zjs_bad
    cmp     eax, '9'
    jbe     zjs_uh1_d
    or      eax, 20h
    cmp     eax, 'a'
    jb      zjs_bad
    cmp     eax, 'f'
    ja      zjs_bad
    sub     eax, 'a' - 10
    jmp     zjs_uh1_ok
zjs_uh1_d:
    sub     eax, '0'
zjs_uh1_ok:
    shl     edx, 4
    or      edx, eax
    dec     r9d
    jnz     zjs_uhex1
    test    edx, edx                            ; reject embedded \u0000
    jz      zjs_bad
    ; Check UTF-16 surrogate range 0xD800..0xDFFF
    mov     eax, edx
    sub     eax, 0D800h
    cmp     eax, 800h
    jae     zjs_bmp                             ; BMP scalar (non-surrogate)
    cmp     eax, 400h
    jae     zjs_bad                             ; lone low surrogate (0xDC00..0xDFFF)
    ; High surrogate (0xD800..0xDBFF): require trailing \uDC00..\uDFFF
    mov     r8d, eax                            ; high - 0xD800 (10 bits)
    lea     rcx, [r10+6]
    cmp     rcx, qword ptr [g_zi_jend]
    ja      zjs_bad
    cmp     byte ptr [r10], '\'
    jne     zjs_bad
    cmp     byte ptr [r10+1], 'u'
    jne     zjs_bad
    add     r10, 2
    xor     edx, edx
    mov     r9d, 4
zjs_uhex2:
    movzx   eax, byte ptr [r10]
    inc     r10
    cmp     eax, '0'
    jb      zjs_bad
    cmp     eax, '9'
    jbe     zjs_uh2_d
    or      eax, 20h
    cmp     eax, 'a'
    jb      zjs_bad
    cmp     eax, 'f'
    ja      zjs_bad
    sub     eax, 'a' - 10
    jmp     zjs_uh2_ok
zjs_uh2_d:
    sub     eax, '0'
zjs_uh2_ok:
    shl     edx, 4
    or      edx, eax
    dec     r9d
    jnz     zjs_uhex2
    mov     eax, edx
    sub     eax, 0DC00h
    cmp     eax, 400h
    jae     zjs_bad                             ; second unit not a low surrogate
    shl     r8d, 10
    lea     edx, [r8+rax+10000h]                ; 21-bit scalar U+10000..U+10FFFF
    ; 4-byte UTF-8: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
    mov     rcx, qword ptr [rbp-24]
    mov     eax, edx
    shr     eax, 18
    or      eax, 0F0h
    mov     byte ptr [rcx+r11], al
    inc     r11d
    mov     eax, edx
    shr     eax, 12
    and     eax, 3Fh
    or      eax, 80h
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
zjs_bmp:
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
zjs_over:
    ; Capacity exceeded: drain to closing quote (if present), flag g_zi_err, return 0.
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjs_bad
    movzx   eax, byte ptr [r10]
    inc     r10
    cmp     eax, '\'
    jne     zjs_over_q
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjs_bad
    inc     r10
    jmp     zjs_over
zjs_over_q:
    cmp     eax, '"'
    jne     zjs_over
zjs_bad:
    mov     qword ptr [g_zi_p], r10
zjs_bad_nostream:
    mov     dword ptr [g_zi_err], 1
    xor     eax, eax
    FRAME_EPILOG
    ret
zjs_close:
    inc     r10                                 ; past closing quote
    mov     qword ptr [g_zi_p], r10
    mov     eax, r11d
    FRAME_EPILOG
    ret
zj_str endp

; zi_type_ok(eax = field type from the JSON) -> eax = a type safe to store.  Leaf.
;   The archive's "type" went straight into the vault.  A value carrying VF_LABELED
;   (8000h) produced a field flagged as labelled with no label length, which made
;   the whole vault fail to unlock after the next save - and with three backup
;   generations rotating on every save, unrecoverably so.  VFL_RAW (40000000h) made
;   the importer read a length out of the text itself.  VF_SYSTEM forged a system
;   item.  Only the kinds the exporter actually writes pass; anything else becomes
;   plain text, so the value is still imported and still visible.
zi_type_ok proc
    cmp     eax, VF_TITLE
    jb      zto_text
    cmp     eax, VF_NOTES                       ; 1..5: title/user/secret/url/notes
    jbe     zto_ok
    cmp     eax, VF_TOTP
    jb      zto_text                            ; 6 is unused
    cmp     eax, VF_ICON                        ; 7..12: totp/text/image/file/fav/icon
    jbe     zto_ok
    cmp     eax, VF_GROUP
    je      zto_ok
    cmp     eax, VF_SPACER
    je      zto_ok
zto_text:                                       ; history, trash marker, system kinds,
    mov     eax, VF_TEXT                        ;   flag bits, unknown: never as-is
zto_ok:
    ret
zi_type_ok endp

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
; zi_utf8_ok(rcx = UTF-8 ptr, edx = byte len) -> eax = 1 valid / 0 invalid.
;   Validates UTF-8 strictly with MB_ERR_INVALID_CHARS (8); sets g_zi_err on
;   malformed sequences so STAGE rejects invalid UTF-8 before commit.
; =============================================================================
zi_utf8_ok proc frame
    FRAME_PROLOG 64                             ; room for 6-arg MBtoWC spill
    test    edx, edx
    jz      zu8_ok
    WINCALL MultiByteToWideChar, CP_UTF8_, 8, rcx, edx, 0, 0
    test    eax, eax
    jz      zu8_bad
zu8_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
zu8_bad:
    mov     dword ptr [g_zi_err], 1
    xor     eax, eax
    FRAME_EPILOG
    ret
zi_utf8_ok endp

; zi_parse_sha_hex() -> eax = 1 if g_zi_sha_hex[0..63] is 64 strict hex digits
;   (decoded into g_zi_sha_exp[0..31]), else 0.  Leaf.
zi_parse_sha_hex proc
    lea     r10, [g_zi_sha_hex]
    lea     r11, [g_zi_sha_exp]
    xor     ecx, ecx
zpsh_lp:
    cmp     ecx, 32
    jae     zpsh_ok
    movzx   eax, byte ptr [r10+rcx*2]
    cmp     eax, '0'
    jb      zpsh_bad
    cmp     eax, '9'
    jbe     zpsh_h1d
    or      eax, 20h
    cmp     eax, 'a'
    jb      zpsh_bad
    cmp     eax, 'f'
    ja      zpsh_bad
    sub     eax, 'a' - 10
    jmp     zpsh_h1ok
zpsh_h1d:
    sub     eax, '0'
zpsh_h1ok:
    shl     eax, 4
    mov     r8d, eax
    movzx   eax, byte ptr [r10+rcx*2+1]
    cmp     eax, '0'
    jb      zpsh_bad
    cmp     eax, '9'
    jbe     zpsh_h2d
    or      eax, 20h
    cmp     eax, 'a'
    jb      zpsh_bad
    cmp     eax, 'f'
    ja      zpsh_bad
    sub     eax, 'a' - 10
    jmp     zpsh_h2ok
zpsh_h2d:
    sub     eax, '0'
zpsh_h2ok:
    or      r8d, eax
    mov     byte ptr [r11+rcx], r8b
    inc     ecx
    jmp     zpsh_lp
zpsh_ok:
    mov     eax, 1
    ret
zpsh_bad:
    xor     eax, eax
    ret
zi_parse_sha_hex endp

; =============================================================================
; zi_addattach(ecx = base type 9/10, rdx = label wide (0/none), r8 = path UTF-8,
;   r9d = pathlen) - decrypt the referenced member, verify SHA-256(plaintext)
;   when present in vordr.json, stage it, and write g_field_list[n] as a VFL_RAW
;   {AttachRef, filename} field.  Fails closed (sets g_zi_err = 1) on any missing,
;   tampered, or unstageable member.
; =============================================================================
zi_addattach proc frame
    FRAME_PROLOG 144                            ; room for locals (-88) + 6-arg MBtoWC spill
    mov     dword ptr [g_zi_atype], ecx
    mov     qword ptr [g_zi_alabel], rdx
    mov     qword ptr [rbp-24], r8              ; path
    mov     dword ptr [rbp-28], r9d             ; pathlen
    mov     qword ptr [rbp-40], 0               ; pt_ptr
    mov     dword ptr [rbp-44], 0               ; pt_len
    mov     qword ptr [rbp-56], 0               ; pt_cap
    ; find the member (missing member MUST fail closed)
    mov     rcx, r8
    mov     edx, r9d
    call    zi_find
    cmp     eax, -1
    je      za_arena_err
    mov     dword ptr [rbp-32], eax             ; member idx
    mov     ecx, eax
    lea     rdx, [rbp-40]                       ; &pt_ptr
    lea     r8, [rbp-44]                        ; &pt_len
    lea     r9, [rbp-56]                        ; &pt_cap
    call    zi_decrypt
    test    eax, eax
    jnz     za_arena_err
    ; Verify SHA-256(plaintext) binding against encrypted vordr.json when present.
    cmp     dword ptr [g_zi_has_sha], 0
    je      za_sha_ok
    mov     rcx, qword ptr [rbp-40]
    mov     edx, dword ptr [rbp-44]
    lea     r8, [g_zi_sha_act]
    call    sha256_hash
    lea     rcx, [g_zi_sha_act]
    lea     rdx, [g_zi_sha_exp]
    mov     r8d, 32
    call    ct_memcmp
    mov     dword ptr [rbp-88], eax
    lea     rcx, [g_zi_sha_act]
    mov     edx, 32
    call    secure_zero
    cmp     dword ptr [rbp-88], 0
    je      za_sha_ok
    mov     rcx, qword ptr [rbp-40]
    mov     rdx, qword ptr [rbp-56]
    call    secmem_free
    mov     qword ptr [rbp-40], 0
    jmp     za_arena_err
za_sha_ok:
    ; stage the plaintext -> g_zi_ref, then wipe + release the decrypt buffer immediately
    mov     rcx, qword ptr [rbp-40]
    mov     edx, dword ptr [rbp-44]
    lea     r8, [g_zi_ref]
    call    attach_stage
    mov     dword ptr [rbp-88], eax             ; save attach_stage rc
    mov     rcx, qword ptr [rbp-40]
    mov     rdx, qword ptr [rbp-56]
    call    secmem_free
    mov     qword ptr [rbp-40], 0
    cmp     dword ptr [rbp-88], 0
    jne     za_arena_err
    ; filename: prefer the json's "name".  Member names are opaque (16 hex of the
    ; attachment id), so the path's last component is no longer the real name.
    ; An archive written before that change carries no "name" - and there the
    ; basename IS the real filename, so fall back to it.
    cmp     dword ptr [g_zi_anamen], 0
    je      zaf_frompath
    mov     eax, dword ptr [g_zi_anamen]
    mov     dword ptr [rbp-68], eax             ; fnlen
    lea     r10, [g_zi_nbuf]
    mov     qword ptr [rbp-64], r10             ; fnptr
    jmp     zaf_have
zaf_frompath:
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
    mov     dword ptr [rbp-68], eax             ; fnlen
    mov     r10, qword ptr [rbp-24]
    add     r10, r9                             ; fnptr
    mov     qword ptr [rbp-64], r10
zaf_have:
    ; Validate the full UTF-8 filename strictly BEFORE clamping length.
    mov     rcx, qword ptr [rbp-64]
    mov     edx, dword ptr [rbp-68]
    call    zi_utf8_ok
    test    eax, eax
    jz      za_arena_err
    ; Clamp to <= 255 UTF-8 bytes on a clean codepoint boundary.
    mov     ecx, dword ptr [rbp-68]
    cmp     ecx, 255
    jbe     zaf_fnok
    mov     ecx, 255
    mov     r10, qword ptr [rbp-64]
zaf_u8trim:
    test    ecx, ecx
    jz      zaf_trimmed
    movzx   edx, byte ptr [r10+rcx]
    and     edx, 0C0h
    cmp     edx, 80h                            ; UTF-8 continuation byte?
    jne     zaf_trimmed
    dec     ecx
    jmp     zaf_u8trim
zaf_trimmed:
    mov     dword ptr [rbp-68], ecx
zaf_fnok:
    ; ensure the arena has room for the worst-case blob before any write:
    ;   4 (rawlen) + ARF_SIZE + (255+1)*2 (max wide filename incl NUL, MBtoWC-capped)
    mov     eax, dword ptr [g_zi_ap]
    add     eax, 4 + ARF_SIZE + 512
    cmp     eax, ZI_ARENA
    ja      za_arena_err
    ; build blob in arena: {u32 rawlen, AttachRef[68], filename wide (NUL-term)}
    mov     r11, qword ptr [g_zi_arena]
    mov     eax, dword ptr [g_zi_ap]
    add     r11, rax
    mov     qword ptr [rbp-80], r11             ; blob base
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
    mov     r10, qword ptr [rbp-80]
    lea     r10, [r10+4+ARF_SIZE]
    mov     qword ptr [rbp-40], r10             ; wide dst
    cmp     dword ptr [rbp-68], 0
    je      za_fnempty
    WINCALL MultiByteToWideChar, CP_UTF8_, 8, qword ptr [rbp-64], dword ptr [rbp-68], \
            qword ptr [rbp-40], 255
    test    eax, eax
    jz      za_arena_err
    jmp     za_fnterm
za_fnempty:
    xor     eax, eax
za_fnterm:
    ; NUL-terminate the wide filename
    mov     r10, qword ptr [rbp-40]
    mov     word ptr [r10+rax*2], 0
    inc     eax                                 ; wchars incl NUL
    lea     eax, [eax*2]                        ; filename bytes
    ; rawlen = ARF_SIZE + filename bytes
    add     eax, ARF_SIZE
    mov     r11, qword ptr [rbp-80]
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
    mov     rax, qword ptr [rbp-80]
    mov     qword ptr [r10+16], rax
    mov     eax, 1
    FRAME_EPILOG
    ret
za_arena_err:
    mov     dword ptr [g_zi_err], 1
    xor     eax, eax
    FRAME_EPILOG
    ret
zi_addattach endp

; =============================================================================
; zi_stage_title(rcx = index, rdx = UTF-8 src, r8d = srclen) - convert the entry
;   title to a NUL-terminated wide string in the persistent title arena and record
;   it in g_zi_titles[index] / g_zi_tlens[index].  On overflow, records "".
; =============================================================================
; =============================================================================
; zi_stage_vault(rcx = decrypted foreign vault body) -> eax = entries staged.
;   Fills the same staging arrays zi_stage builds from a ZIP, so the existing
;   selection checklist drives a .vordr import unchanged.
;
;   Every source entry is staged AT ITS PHYSICAL INDEX - fed_merge indexes g_sel by that
;   index, so compacting the list would slide every tick onto a different record.  Rows
;   that must not be offered (the source's system item, and anything in its trash) are
;   flagged in g_zi_hide instead; fed_merge refuses them independently anyway.
; =============================================================================
public zi_stage_vault
zi_stage_vault proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=body [rbp-32]=cursor [rbp-40]=i [rbp-48]=count [rbp-56]=title len
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [g_zi_tap], 0
    mov     dword ptr [g_zi_stg_n], 0
    test    rcx, rcx
    jz      zsv_done
    mov     eax, dword ptr [rcx]
    mov     dword ptr [g_zi_trunc], 0
    cmp     eax, ZI_MAXENT
    jbe     @F
    mov     dword ptr [g_zi_trunc], eax         ; remember the REAL total: silently importing
    mov     eax, ZI_MAXENT                      ;   a subset of someone's vault is the kind of
@@: mov     dword ptr [rbp-48], eax
    lea     r10, [rcx+4]
    mov     qword ptr [rbp-32], r10
    mov     dword ptr [rbp-40], 0
zsv_loop:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, dword ptr [rbp-48]
    jae     zsv_done
    lea     r11, [g_zi_hide]                    ; hidden unless proven otherwise
    mov     byte ptr [r11+rax], 1
    mov     rcx, qword ptr [rbp-32]
    mov     edx, VF_SYSTEM
    call    entry_has_field
    test    eax, eax
    jnz     zsv_blank                           ; the source's own system item
    mov     rcx, qword ptr [rbp-32]
    mov     edx, VF_DELETED
    call    entry_has_field
    test    eax, eax
    jnz     zsv_blank                           ; a record the source had in its trash
    mov     rcx, qword ptr [rbp-32]             ; title -> the checklist row
    mov     edx, VF_TITLE
    lea     r8, [rbp-56]
    call    entry_field_ptr
    test    rax, rax
    jz      zsv_blank                           ; untitled: nothing to show, so do not offer
    mov     rcx, qword ptr [rbp-40]
    mov     rdx, rax
    mov     r8d, dword ptr [rbp-56]
    call    zi_stage_title
    mov     eax, dword ptr [rbp-40]
    lea     r11, [g_zi_hide]
    mov     byte ptr [r11+rax], 0               ; a real, showable row
    jmp     zsv_next
zsv_blank:
    mov     rcx, qword ptr [rbp-40]             ; keep the index slot occupied
    lea     rdx, [zi_empty_w]
    xor     r8d, r8d
    call    zi_stage_title
zsv_next:
    mov     rcx, qword ptr [rbp-32]
    call    vault_entry_len
    add     qword ptr [rbp-32], rax
    inc     dword ptr [rbp-40]
    jmp     zsv_loop
zsv_done:
    mov     eax, dword ptr [rbp-48]
    mov     dword ptr [g_zi_stg_n], eax
    FRAME_EPILOG
    ret
zi_stage_vault endp

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
    mov     rcx, qword ptr [rbp-32]
    mov     edx, dword ptr [rbp-36]
    call    zi_utf8_ok
    test    eax, eax
    jz      st_full
    WINCALL MultiByteToWideChar, CP_UTF8_, 8, qword ptr [rbp-32], dword ptr [rbp-36], \
            qword ptr [rbp-48], dword ptr [rbp-52]
    test    eax, eax
    jz      st_full
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
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [g_zi_jend]
    jae     zij_bad
    cmp     byte ptr [r10], '['
    jne     zij_bad
    inc     r10
    mov     qword ptr [g_zi_p], r10
zij_entry:
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [rbp-72]             ; FORWARD-PROGRESS guard: stuck cursor -> malformed
    je      zij_bad
    mov     qword ptr [rbp-72], r10
    cmp     r10, qword ptr [g_zi_jend]
    jae     zij_bad                             ; truncated before closing ']' -> malformed
    movzx   eax, byte ptr [r10]
    cmp     eax, ']'
    je      zij_close
    cmp     eax, ','
    jne     zij_e0
    inc     r10
    mov     qword ptr [g_zi_p], r10
zij_e0:
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [g_zi_jend]
    jae     zij_bad
    cmp     byte ptr [r10], '{'
    jne     zij_bad
    inc     r10
    mov     qword ptr [g_zi_p], r10
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
    test    eax, eax
    jz      zij_bad
    lea     rcx, [g_zi_sbuf]                    ; decode title -> sbuf
    mov     edx, ZI_SBUF
    call    zj_str
    cmp     dword ptr [g_zi_err], 0
    jne     zij_done
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
    test    eax, eax
    jz      zij_bad
    mov     dword ptr [g_zi_ap], 0              ; fresh arena for this entry
    mov     dword ptr [rbp-24], 0               ; n (field slot)
    mov     qword ptr [rbp-80], 0              ; field-loop progress marker (reset per entry)
zij_field:
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [rbp-80]             ; FORWARD-PROGRESS guard (see zij_entry)
    je      zij_bad
    mov     qword ptr [rbp-80], r10
    cmp     r10, qword ptr [g_zi_jend]
    jae     zij_bad
    movzx   eax, byte ptr [r10]
    cmp     eax, ']'
    je      zij_fend
    cmp     eax, ','
    jne     zij_f0
    inc     r10
    mov     qword ptr [g_zi_p], r10
zij_f0:
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [g_zi_jend]
    jae     zij_bad
    cmp     byte ptr [r10], '{'
    jne     zij_bad
    inc     r10
    mov     qword ptr [g_zi_p], r10
    lea     rcx, [zl_type]                      ; "type":
    mov     edx, 7
    call    zj_lit
    test    eax, eax
    jz      zij_bad
    call    zj_num
    call    zi_type_ok                          ; untrusted: only plain user kinds pass
    mov     dword ptr [rbp-28], eax             ; type
    lea     rcx, [zl_label]                     ; ,"label":
    mov     edx, 9
    call    zj_lit
    test    eax, eax
    jz      zij_bad
    lea     rcx, [g_zi_sbuf]                    ; decode label -> sbuf
    mov     edx, ZI_SBUF
    call    zj_str
    cmp     dword ptr [g_zi_err], 0
    jne     zij_done
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
    test    eax, eax
    jz      zij_bad
    lea     rcx, [g_zi_sbuf]                    ; decode value -> sbuf
    mov     edx, ZI_SBUF
    call    zj_str
    cmp     dword ptr [g_zi_err], 0
    jne     zij_done
    mov     dword ptr [rbp-48], eax             ; vallen
    lea     rcx, [g_zi_sbuf]
    mov     edx, eax
    call    zi_utf8_ok
    test    eax, eax
    jz      zij_done
    ; optional ,"name":"<real filename>" - attachments only, and only in archives
    ; written after member names were made opaque.  Its absence is normal: an
    ; older archive carries the real name as the last path component instead.
    mov     dword ptr [g_zi_anamen], 0
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [g_zi_jend]
    jae     zij_noname
    movzx   eax, byte ptr [r10]
    cmp     eax, ','
    jne     zij_noname
    lea     rcx, [zl_name]                      ; ,"name":
    mov     edx, 8
    call    zj_lit
    test    eax, eax
    jz      zij_noname
    lea     rcx, [g_zi_nbuf]                    ; decode name -> its own buffer
    mov     edx, ZI_NBUF
    call    zj_str
    cmp     dword ptr [g_zi_err], 0
    jne     zij_done
    mov     dword ptr [g_zi_anamen], eax
    lea     rcx, [g_zi_nbuf]
    mov     edx, eax
    call    zi_utf8_ok
    test    eax, eax
    jz      zij_done
zij_noname:
    ; optional ,"sha256":"<64-hex>" - cryptographic binding of attachment plaintext.
    ; Validated in BOTH stage and commit passes; legacy archives lacking it remain valid.
    mov     dword ptr [g_zi_has_sha], 0
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [g_zi_jend]
    jae     zij_bad
    movzx   eax, byte ptr [r10]
    cmp     eax, ','
    jne     zij_nosha
    lea     rcx, [zl_sha256]                    ; ,"sha256":
    mov     edx, 10
    call    zj_lit
    test    eax, eax
    jz      zij_bad                             ; unknown trailing field key -> reject
    lea     rcx, [g_zi_sha_hex]
    mov     edx, 128
    call    zj_str
    cmp     dword ptr [g_zi_err], 0
    jne     zij_done
    cmp     eax, 64
    jne     zij_bad
    call    zi_parse_sha_hex
    test    eax, eax
    jz      zij_bad
    mov     dword ptr [g_zi_has_sha], 1
zij_nosha:
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [g_zi_jend]
    jae     zij_bad
    cmp     byte ptr [r10], '}'
    jne     zij_bad
    inc     r10
    mov     qword ptr [g_zi_p], r10
    ; ---- build the field (selected entries only; else parsed + discarded) ----
    cmp     dword ptr [g_zi_build], 0
    je      zij_field
    cmp     dword ptr [rbp-24], MAX_FIELDS      ; g_field_list full? fail closed rather than
    jae     zij_bad                             ;   silently dropping fields
    mov     eax, dword ptr [rbp-28]             ; type
    cmp     eax, VF_IMAGE
    je      zij_att
    cmp     eax, VF_FILE
    je      zij_att
    ; text field: value UTF-8 -> wide
    lea     rcx, [g_zi_sbuf]
    mov     edx, dword ptr [rbp-48]
    call    zi_u2w                              ; rax = value wide
    cmp     dword ptr [g_zi_err], 0
    jne     zij_done
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
    cmp     dword ptr [g_zi_err], 0
    jne     zij_done
    test    eax, eax
    jz      zij_bad
    inc     dword ptr [rbp-24]
    jmp     zij_field
zij_fend:
    mov     al, ']'
    call    zj_skipch
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [g_zi_jend]
    jae     zij_bad
    cmp     byte ptr [r10], '}'
    jne     zij_bad
    inc     r10
    mov     qword ptr [g_zi_p], r10
    ; build the entry (commit + selected) if it accumulated any fields
    cmp     dword ptr [g_zi_build], 0
    je      zij_eadv
    mov     eax, dword ptr [rbp-24]
    test    eax, eax
    jz      zij_eadv
    mov     dword ptr [g_field_n], eax
    call    vault_build_entry
    test    eax, eax
    jnz     zij_bad
    inc     dword ptr [g_zi_count]
zij_eadv:
    inc     dword ptr [g_zi_e]
    jmp     zij_entry
zij_close:
    inc     r10
    mov     qword ptr [g_zi_p], r10
    jmp     zij_done
zij_bad:
    mov     dword ptr [g_zi_err], 1
zij_done:
    cmp     dword ptr [g_zi_mode], 1
    je      zij_dret
    mov     dword ptr [g_zi_trunc], 0
    mov     eax, dword ptr [g_zi_e]             ; stage: publish the entry count
    cmp     eax, ZI_MAXENT                      ; clamp: g_zi_titles/g_zi_tlens hold only
    jbe     @F                                  ; ZI_MAXENT slots
    mov     dword ptr [g_zi_trunc], eax         ; surface truncation warning like zi_stage_vault
    mov     eax, ZI_MAXENT
@@:
    mov     dword ptr [g_zi_stg_n], eax
zij_dret:
    mov     eax, dword ptr [g_zi_count]
    FRAME_EPILOG
    ret
zi_walk endp

; zi_free_wipe() - release the per-entry arena + decrypted json (if held) and wipe secrets.
zi_free_wipe proc frame
    FRAME_PROLOG 48
    mov     rcx, qword ptr [g_zi_arena]
    test    rcx, rcx
    jz      zfw_jbuf
    mov     rdx, ZI_ARENA
    call    secmem_free                         ; wipes before release
    mov     qword ptr [g_zi_arena], 0
zfw_jbuf:
    mov     rcx, qword ptr [g_zi_jptr]
    test    rcx, rcx
    jz      zfw_jclr
    mov     rdx, qword ptr [g_zi_jcap]
    test    rdx, rdx
    jz      zfw_jclr                            ; static buffer (jfuzz) -> do not VirtualFree
    call    secmem_free                         ; wipes before release
zfw_jclr:
    mov     qword ptr [g_zi_jptr], 0
    mov     dword ptr [g_zi_jlen], 0
    mov     qword ptr [g_zi_jcap], 0
    lea     rcx, [g_zi_u8pw]
    mov     edx, ZI_PWCAP
    call    secure_zero
    mov     dword ptr [g_zi_pwlen], 0
    ; Wipe every transient secret buffer used during staging and commit:
    ; sbuf (values/labels/titles), nbuf (filenames), tbuf (staged wide titles),
    ; expanded AES key schedule, PBKDF2 output, staged AttachRef, CTR, and HMAC.
    lea     rcx, [g_zi_sbuf]
    mov     edx, ZI_SBUF
    call    secure_zero
    lea     rcx, [g_zi_nbuf]
    mov     edx, ZI_NBUF
    call    secure_zero
    lea     rcx, [g_zi_tbuf]
    mov     edx, ZI_TBUF
    call    secure_zero
    mov     dword ptr [g_zi_tap], 0
    lea     rcx, [g_zi_rk]
    mov     edx, 15*16
    call    secure_zero
    lea     rcx, [g_ae_dk]
    mov     edx, 80
    call    secure_zero
    lea     rcx, [g_zi_ref]
    mov     edx, ARF_SIZE
    call    secure_zero
    lea     rcx, [g_zi_ctr]
    mov     edx, 16
    call    secure_zero
    lea     rcx, [g_zi_auth]
    mov     edx, 20
    call    secure_zero
    lea     rcx, [g_zi_sha_hex]
    mov     edx, 128
    call    secure_zero
    lea     rcx, [g_zi_sha_exp]
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_zi_sha_act]
    mov     edx, 32
    call    secure_zero
    mov     dword ptr [g_zi_has_sha], 0
    cmp     dword ptr [g_zi_rawlk], 0           ; release the pin on the archive (the
    je      zfw_done                            ;   caller wipes and frees it)
    mov     dword ptr [g_zi_rawlk], 0
    WINCALL VirtualUnlock, qword ptr [g_zi_raw], qword ptr [g_zi_rawlen]
zfw_done:
    FRAME_EPILOG
    ret
zi_free_wipe endp

; =============================================================================
; zi_stage(rcx=raw, edx=rawlen, r8=wide pw, r9d=pw bytes) -> eax
;   >=0  entries staged: their titles are in g_zi_titles[0..n) / g_zi_tlens,
;        g_zi_stg_n = n.  The arena + decrypted json + password are KEPT so a
;        subsequent zi_commit (or zi_abort) can finish the job.
;   -3   wrong password        -1   not a readable Vordr zip / error
;   -4   an encrypted ZIP Vordr cannot read (not AES-256 stored)
; On every error path the arena is freed and the password wiped.
; =============================================================================
public zi_stage
zi_stage proc frame
    FRAME_PROLOG 160                            ; room for the 8-arg WCtoMB arg spill
    mov     qword ptr [rbp-24], rcx             ; raw
    mov     dword ptr [rbp-28], edx             ; rawlen
    mov     dword ptr [g_zi_err], 0
    mov     qword ptr [g_zi_jptr], 0
    mov     dword ptr [g_zi_jlen], 0
    mov     qword ptr [g_zi_jcap], 0
    mov     qword ptr [g_zi_arena], 0
    mov     dword ptr [g_zi_rawlk], 0
    ; wide pw -> UTF-8 g_zi_u8pw (stage count in r9d: WINCALL rax-clobber footgun)
    shr     r9d, 1                              ; wide chars
    mov     dword ptr [rbp-32], r9d
    test    r9d, r9d                            ; refuse empty export password outright
    jnz     @F
    mov     dword ptr [rbp-40], -3
    jmp     zs_fail
@@: WINCALL WideCharToMultiByte, CP_UTF8_, 80h, r8, dword ptr [rbp-32], addr g_zi_u8pw, ZI_PWCAP, 0, 0
    mov     dword ptr [g_zi_pwlen], eax
    test    eax, eax                            ; 0 = did not fit or invalid UTF-16 surrogates
    jnz     zs_pwok
    mov     dword ptr [rbp-40], -3
    jmp     zs_fail
zs_pwok:
    lea     rax, [g_zi_u8pw]
    mov     qword ptr [g_zi_pwptr], rax
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [g_zi_raw], rax
    mov     eax, dword ptr [rbp-28]
    mov     qword ptr [g_zi_rawlen], rax
    mov     dword ptr [g_zi_rawlk], 0
    WINCALL VirtualLock, qword ptr [g_zi_raw], qword ptr [g_zi_rawlen]
    test    eax, eax
    jz      @F
    mov     dword ptr [g_zi_rawlk], 1
@@:
    ; allocate the per-entry arena
    mov     rcx, ZI_ARENA
    call    secmem_alloc
    test    rax, rax
    jz      zs_err
    mov     qword ptr [g_zi_arena], rax
    ; scan members
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-28]
    call    zi_scan
    cmp     dword ptr [g_zi_unsup], 0
    je      zs_supported
    mov     dword ptr [rbp-40], -4              ; a ZIP, but not one Vordr can read
    jmp     zs_fail
zs_supported:
    call    attach_reset_pending                ; start a fresh PENDING set only
    ; find + decrypt the data file into a fresh secmem buffer
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
    lea     rdx, [g_zi_jptr]
    lea     r8, [g_zi_jlen]
    lea     r9, [g_zi_jcap]
    call    zi_decrypt
    test    eax, eax
    jz      zs_json_ok
    mov     dword ptr [rbp-40], eax             ; -3 wrong pw / -1 corrupt
    jmp     zs_fail
zs_json_ok:
    mov     rax, qword ptr [g_zi_jptr]
    mov     edx, dword ptr [g_zi_jlen]
    mov     qword ptr [g_zi_p], rax
    add     rax, rdx
    mov     qword ptr [g_zi_jend], rax
    mov     dword ptr [g_zi_tap], 0
    mov     dword ptr [g_zi_stg_n], 0
    mov     dword ptr [g_zi_mode], 0            ; STAGE: collect titles + validate json
    call    zi_walk
    cmp     dword ptr [g_zi_err], 0
    jne     zs_err                              ; malformed JSON or UTF-8 -> reject closed
    mov     eax, dword ptr [g_zi_stg_n]         ; keep arena + json + pw for zi_commit
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
; zi_commit() -> eax = entries imported (<0 on error).  Re-walk the staged json,
;   building only the entries whose g_sel[e] is set, then free the arena + wipe
;   the password.
; =============================================================================
public zi_commit
zi_commit proc frame
    FRAME_PROLOG 64
    ; Snapshot live vault body length & count so any mid-commit failure rolls back atomically.
    mov     rax, qword ptr [g_body_len]
    mov     qword ptr [rbp-32], rax
    mov     dword ptr [rbp-40], 0
    mov     r10, qword ptr [g_body_ptr]
    test    r10, r10
    jz      @F
    mov     eax, dword ptr [r10]
    mov     dword ptr [rbp-40], eax
@@: mov     dword ptr [g_zi_err], 0
    mov     rax, qword ptr [g_zi_jptr]
    mov     qword ptr [g_zi_p], rax
    mov     edx, dword ptr [g_zi_jlen]
    add     rax, rdx
    mov     qword ptr [g_zi_jend], rax
    mov     dword ptr [g_zi_ap], 0
    mov     dword ptr [g_zi_mode], 1            ; COMMIT: build selected entries
    call    zi_walk
    mov     dword ptr [rbp-24], eax
    mov     ecx, dword ptr [g_zi_err]
    mov     dword ptr [rbp-28], ecx
    call    zi_free_wipe
    cmp     dword ptr [rbp-28], 0
    jne     zic_err
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
zic_err:
    mov     r10, qword ptr [g_body_ptr]
    test    r10, r10
    jz      zic_err_att
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [r10], eax                ; restore entry_count
    mov     rcx, qword ptr [rbp-32]             ; old body_len
    mov     rdx, qword ptr [g_body_len]
    mov     qword ptr [g_body_len], rcx         ; restore body_len
    cmp     rdx, rcx
    jbe     zic_err_att
    sub     rdx, rcx                            ; bytes appended before abort
    add     rcx, r10
    call    secure_zero
zic_err_att:
    call    attach_reset_pending
    mov     eax, -1
    FRAME_EPILOG
    ret
zi_commit endp

; zi_abort() - discard a staged import (user cancelled the selection).
public zi_abort
zi_abort proc frame
    FRAME_PROLOG 32
    call    attach_reset_pending
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
    ; "0 crashes" over inputs that were all rejected at the first check proves
    ; nothing.  Mutating 1-4 bytes of a valid fixture leaves most inputs scannable;
    ; require at least a tenth (it read 0 scanned when the fixture stopped matching).
    cmp     qword ptr [rbp-40], ZFZ_ITERS / 10
    jae     zfz_enough
    lea     rcx, [zfz_thin]
    mov     edx, zfz_thin_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
zfz_enough:
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
CSTR jfz_tbad, "jfuzz: FAIL (an archive field type reached the vault unsanitised)",13,10
; {type from the archive, what may be stored}: flag bits, the raw-blob marker, the
; system kinds, history and the trash marker must never pass through as given.
align 4
jfz_types label dword
    dd  VF_SECRET,                  VF_SECRET
    dd  VF_SPACER,                  VF_SPACER
    dd  VF_LABELED or VF_USERNAME,  VF_TEXT
    dd  40000000h or VF_IMAGE,      VF_TEXT
    dd  VF_SYSTEM,                  VF_TEXT
    dd  VF_SYS_PWVERIFY,            VF_TEXT
    dd  VF_PWHIST,                  VF_TEXT
    dd  VF_DELETED,                 VF_TEXT
    dd  0,                          VF_TEXT
    dd  6,                          VF_TEXT
    dd  0FFFFFFFFh,                 VF_TEXT
JFZ_TYPES_N equ ($ - jfz_types) / 8
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
    lea     r10, [jfz_types]                         ; the type sanitiser, case by case
    xor     ecx, ecx
jfz_tchk:
    cmp     ecx, JFZ_TYPES_N
    jae     jfz_tdone
    mov     eax, dword ptr [r10+rcx*8]
    call    zi_type_ok
    cmp     eax, dword ptr [r10+rcx*8+4]
    jne     jfz_tfail
    inc     ecx
    jmp     jfz_tchk
jfz_tfail:
    lea     rcx, [jfz_tbad]
    mov     edx, jfz_tbad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
jfz_tdone:
    call    fuzz_seed                                ; G7: random (or --seed) + logged
    mov     qword ptr [g_zfz_rng], rax
    mov     rcx, ZI_ARENA                            ; arena: zi_walk decodes wide here
    call    secmem_alloc                             ;   (zi_free_wipe releases it as secmem)
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
    mov     qword ptr [g_zi_jcap], 0
    mov     qword ptr [g_zi_p], rax
    mov     r10, qword ptr [rbp-32]
    mov     dword ptr [g_zi_jlen], r10d
    add     rax, r10
    mov     qword ptr [g_zi_jend], rax
    mov     dword ptr [g_zi_tap], 0
    mov     dword ptr [g_zi_stg_n], 0
    mov     dword ptr [g_zi_err], 0
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
