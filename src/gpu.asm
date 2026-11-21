; =============================================================================
; gpu.asm - Zero-dependency Direct3D 11 DirectCompute procedural backdrops
; -----------------------------------------------------------------------------
; Computes 7 procedural GPU backdrop styles + Flat fallback via System32\d3d11.dll
; (hardware GPU adapter first, automatic D3D11 WARP SIMD fallback on headless
; or GPU-less machines) using offline-compiled HLSL cs_5_0 DXBC bytecode
; (src/gpu_backdrops.inc, generated from tools/backdrops.hlsl):
;
;   0 : Cut planes     (layered shadowed diagonal folds + under-fold glow)
;   1 : Low-poly neon  (matte Delaunay relief + continuous neon zig-zag seams)
;   2 : Corner mosaic  (anti-aliased equilateral triangle corner dissolve)
;   3 : Optical arcs   (Apollonian circle-inversion refractive light caustics)
;   4 : Crystal rim    (anisotropic crystalline shards + dual-tone rim edges)
;   5 : Guardian sigil (emissive faceted Vordr sentinel crest + horizon bounce)
;   6 : Cipher rings   (golden-angle concentric cipher-wheel bead arcs)
;   7 : Flat           (solid g_col_bg fill, GPU bypassed)
;
; Painting & performance contract:
;   - GPU dispatches ONLY when dimensions, vault salt seed, active color scheme,
;     or selected Backdrop style change, caching a static 8-byte/px basis;
;   - Calm 360-degree hue cycling blends the cached basis on CPU via SSE2 in
;     < 5 ms with zero D3D11 dispatches per tick.
; =============================================================================

include macros.inc

extern LoadLibraryExW:proc
extern GetProcAddress:proc
extern VirtualAlloc:proc
extern VirtualFree:proc
extern CreateCompatibleDC:proc
extern CreateDIBSection:proc
extern SelectObject:proc
extern DeleteObject:proc
extern BitBlt:proc
extern GdiFlush:proc
extern GetClientRect:proc
extern GetParent:proc
extern MapWindowPoints:proc
extern FillRect:proc
extern sha256_hash:proc
ifdef PROBE_IO
extern print_a:proc
endif
extern theme_glass_tint:proc
extern theme_glass_alpha:proc
extern col_mix:proc

externdef g_vaulthwnd:qword
externdef g_settings_hwnd:qword
externdef g_comp_hdc:qword
externdef g_col_bg:dword
externdef g_col_panel:dword
externdef g_col_side:dword
externdef g_col_accent:dword
externdef g_col_accent2:dword
externdef g_col_dark:dword
externdef g_scheme:dword
externdef g_br_bg:qword

public gpu_init, gpu_active, gpu_paint_bg, gpu_fill_child_bg, gpu_sample_child_bg
public gpu_fill_glass_child, gpu_sample_glass_child
public gpu_fill_side_glass_child, gpu_sample_side_glass_child
public gpu_is_surface_hwnd, gpu_set_vault_seed, gpu_ensure_surface
ifdef PROBE_IO
public cmd_gpukat
endif
public g_backdrop_pref, g_backdrop_lock, g_gpu_backend, g_gpu_dispatches
public g_gpu_hdc, g_gpu_time_ms

LOAD_LIB_SYS32      equ 0800h           ; LOAD_LIBRARY_SEARCH_SYSTEM32
SRCCOPY_            equ 0CC0020h
MEM_COMMIT_RES_     equ 3000h           ; MEM_COMMIT | MEM_RESERVE
MEM_RELEASE_        equ 8000h           ; MEM_RELEASE
PAGE_RW_            equ 4               ; PAGE_READWRITE

D3D_DRV_HARDWARE    equ 1
D3D_DRV_WARP        equ 5
D3D11_CREATE_ST     equ 1               ; D3D11_CREATE_DEVICE_SINGLETHREADED
D3D11_SDK_VER       equ 7
D3D11_BIND_CB       equ 4               ; D3D11_BIND_CONSTANT_BUFFER
D3D11_BIND_UAV      equ 80h             ; D3D11_BIND_UNORDERED_ACCESS
D3D11_USAGE_DEFAULT equ 0
D3D11_USAGE_STAGING equ 3
D3D11_CPU_READ      equ 20000h          ; D3D11_CPU_ACCESS_READ
D3D11_MISC_STRUCT   equ 40h             ; D3D11_RESOURCE_MISC_BUFFER_STRUCTURED
D3D11_UAV_DIM_BUF   equ 1               ; D3D11_UAV_DIMENSION_BUFFER
D3D11_MAP_READ_     equ 1

; COM vtable byte offsets (verified against Windows Kits 10 um\d3d11.h)
VT_RELEASE          equ 010h            ; IUnknown::Release              [2]
VT_CREATE_BUF       equ 018h            ; ID3D11Device::CreateBuffer     [3]
VT_CREATE_UAV       equ 040h            ; ID3D11Device::CreateUAV        [8]
VT_CREATE_CS        equ 090h            ; ID3D11Device::CreateCS        [18]
VT_CTX_MAP          equ 070h            ; ID3D11DeviceContext::Map      [14]
VT_CTX_UNMAP        equ 078h            ; ID3D11DeviceContext::Unmap    [15]
VT_CTX_DISPATCH     equ 148h            ; ID3D11DeviceContext::Dispatch [41]
VT_CTX_COPYRES      equ 178h            ; ID3D11DeviceContext::CopyRes  [47]
VT_CTX_UPDSUB       equ 180h            ; ID3D11DeviceContext::UpdSub   [48]
VT_CTX_CS_UAV       equ 220h            ; ID3D11DeviceContext::CSSetUAV [68]
VT_CTX_CS_SHD       equ 228h            ; ID3D11DeviceContext::CSSetShd [69]
VT_CTX_CS_CB        equ 238h            ; ID3D11DeviceContext::CSSetCB  [71]

GPU_SEED_DEF0       equ 564F5244h       ; "VORD"
GPU_SEED_DEF1       equ 424B4450h       ; "BKDP"

.const
WSTR w_d3d11_dll, <d3d11.dll>
a_d3d11_create    db "D3D11CreateDevice", 0
gpu_seed_dom      db "vordr-backdrop-v1", 0     ; 18 bytes domain prefix
gpu_seed_dom_len  equ $ - gpu_seed_dom
align 4
d3d_fls           dd 0B100h, 0B000h             ; FL_11_1, FL_11_0

include gpu_backdrops.inc

ifdef PROBE_IO
CSTR gpk_ok_hw,   "gpukat: PASS (D3D11 hardware cs_5_0 7 backdrop modes + cache + vault seed + flat toggle)", 13, 10
CSTR gpk_ok_warp, "gpukat: PASS (D3D11 WARP cs_5_0 7 backdrop modes + cache + vault seed + flat toggle)", 13, 10
CSTR gpk_bad,     "gpukat: FAIL", 13, 10
endif

.data
align 8
g_backdrop_pref   dd 0                  ; 0..6 = GPU styles, 7 = Flat
g_backdrop_lock   dd 0                  ; 1 = locked by HKLM policy
g_gpu_backend     dd 0                  ; 0 = uninit, 1 = HW GPU, 2 = WARP, -1 = unavail
g_gpu_force_warp  dd 0                  ; AUD-24: set to 1 after HW TDR/device-removed
g_gpu_dispatches  dd 0                  ; total compute dispatches executed
g_gpu_time_ms     dd 0                  ; calm ambient clock in ms (0 = static)
g_gpu_last_tms    dd -1                 ; last composed g_gpu_time_ms
g_gpu_seed0       dd GPU_SEED_DEF0
g_gpu_seed1       dd GPU_SEED_DEF1
g_gpu_key_valid   dd 0
g_gpu_w           dd 0
g_gpu_h           dd 0

align 8
g_d3d_hmod        dq 0
g_fn_d3dcreate    dq 0
g_d3d_dev         dq 0
g_d3d_ctx         dq 0
g_d3d_cs          dq 0
g_d3d_cb          dq 0
g_d3d_uav_buf     dq 0
g_d3d_uav         dq 0
g_d3d_stg_buf     dq 0

g_gpu_hdc         dq 0
g_gpu_hbmp        dq 0
g_gpu_oldbmp      dq 0
g_gpu_bits        dq 0
g_gpu_base_bits   dq 0                  ; cached static (matte BGRA8, w1|w2) basis (8B/px)

.data?
align 8
g_gpu_last_key    dd 10 dup (?)         ; 40-byte render-state fingerprint
ifdef PROBE_IO
g_gpu_kat_salt    db 32 dup (?)
align 4
g_gpu_kat_sig     dd 16 dup (?)         ; per-mode pixel checksums in gpukat
endif

.code

; gpu_rel_com(rcx = &com_ptr) - safely Release and zero a COM interface slot.
gpu_rel_com proc frame
    FRAME_PROLOG 48
    mov     rax, qword ptr [rcx]
    test    rax, rax
    jz      grc_done
    mov     qword ptr [rcx], 0
    mov     rcx, rax
    mov     rdx, qword ptr [rax]
    call    qword ptr [rdx + VT_RELEASE]
grc_done:
    FRAME_EPILOG
    ret
gpu_rel_com endp

; gpu_free_buffers() - release size-dependent D3D11 buffers + GDI DIB section.
gpu_free_buffers proc frame
    FRAME_PROLOG 48
    lea     rcx, [g_d3d_uav]
    call    gpu_rel_com
    lea     rcx, [g_d3d_uav_buf]
    call    gpu_rel_com
    lea     rcx, [g_d3d_stg_buf]
    call    gpu_rel_com
    cmp     qword ptr [g_gpu_hbmp], 0
    je      gfb_nobmp
    cmp     qword ptr [g_gpu_hdc], 0
    je      gfb_delbmp
    WINCALL SelectObject, qword ptr [g_gpu_hdc], qword ptr [g_gpu_oldbmp]
    mov     qword ptr [g_gpu_oldbmp], 0
gfb_delbmp:
    WINCALL DeleteObject, qword ptr [g_gpu_hbmp]
    mov     qword ptr [g_gpu_hbmp], 0
gfb_nobmp:
    cmp     qword ptr [g_gpu_base_bits], 0
    je      gfb_nobase
    WINCALL VirtualFree, qword ptr [g_gpu_base_bits], 0, MEM_RELEASE_
    mov     qword ptr [g_gpu_base_bits], 0
gfb_nobase:
    mov     qword ptr [g_gpu_bits], 0
    mov     dword ptr [g_gpu_w], 0
    mov     dword ptr [g_gpu_h], 0
    mov     dword ptr [g_gpu_key_valid], 0
    mov     dword ptr [g_gpu_last_tms], -1
    FRAME_EPILOG
    ret
gpu_free_buffers endp

; gpu_init() -> eax = 1 ready, 0 unavailable.
gpu_init proc frame
    FRAME_PROLOG 256
    ; Locals: [rbp-16]=fl_out  [rbp-48..rbp-25]=D3D11_BUFFER_DESC(24B)  [rbp-56]=drv_kind
    mov     eax, dword ptr [g_gpu_backend]
    cmp     eax, 0
    jg      gi_ok
    jl      gi_no

    cmp     qword ptr [g_d3d_hmod], 0
    jne     gi_try_hw
    WINCALL LoadLibraryExW, addr w_d3d11_dll, 0, LOAD_LIB_SYS32
    test    rax, rax
    jz      gi_fail
    mov     qword ptr [g_d3d_hmod], rax
    WINCALL GetProcAddress, rax, addr a_d3d11_create
    test    rax, rax
    jz      gi_fail
    xor     rax, qword ptr [g_ptr_cookie]
    mov     qword ptr [g_fn_d3dcreate], rax

gi_try_hw:
    cmp     dword ptr [g_gpu_force_warp], 0
    jne     gi_try_warp
    ; 1) Try hardware GPU adapter first
    mov     dword ptr [rbp-56], 1               ; backend 1 = HW
    xor     ecx, ecx                            ; pAdapter = NULL
    mov     edx, D3D_DRV_HARDWARE               ; DriverType = HARDWARE
    xor     r8d, r8d                            ; Software = NULL
    mov     r9d, D3D11_CREATE_ST                ; Flags = SINGLETHREADED
    lea     rax, [d3d_fls]
    mov     qword ptr [rsp+32], rax             ; pFeatureLevels
    mov     dword ptr [rsp+40], 2               ; FeatureLevels = 2
    mov     dword ptr [rsp+48], D3D11_SDK_VER   ; SDKVersion = 7
    lea     rax, [g_d3d_dev]
    mov     qword ptr [rsp+56], rax             ; ppDevice
    lea     rax, [rbp-16]
    mov     qword ptr [rsp+64], rax             ; pFeatureLevel
    lea     rax, [g_d3d_ctx]
    mov     qword ptr [rsp+72], rax             ; ppImmediateContext
    mov     rax, qword ptr [g_fn_d3dcreate]
    xor     rax, qword ptr [g_ptr_cookie]
    call    rax
    test    eax, eax
    jns     gi_have_dev

gi_try_warp:
    ; 2) Fallback to Windows built-in D3D11 WARP rasterizer/compute JIT
    mov     dword ptr [rbp-56], 2               ; backend 2 = WARP
    xor     ecx, ecx
    mov     edx, D3D_DRV_WARP
    xor     r8d, r8d
    mov     r9d, D3D11_CREATE_ST
    lea     rax, [d3d_fls]
    mov     qword ptr [rsp+32], rax
    mov     dword ptr [rsp+40], 2
    mov     dword ptr [rsp+48], D3D11_SDK_VER
    lea     rax, [g_d3d_dev]
    mov     qword ptr [rsp+56], rax
    lea     rax, [rbp-16]
    mov     qword ptr [rsp+64], rax
    lea     rax, [g_d3d_ctx]
    mov     qword ptr [rsp+72], rax
    mov     rax, qword ptr [g_fn_d3dcreate]
    xor     rax, qword ptr [g_ptr_cookie]
    call    rax
    test    eax, eax
    js      gi_fail

gi_have_dev:
    ; 3) CreateComputeShader(dev, gpu_cs_backdrops, gpu_cs_backdrops_len, NULL, &g_d3d_cs)
    mov     rcx, qword ptr [g_d3d_dev]
    test    rcx, rcx
    jz      gi_fail_clean
    mov     r10, qword ptr [rcx]
    lea     rdx, [gpu_cs_backdrops]
    mov     r8d, gpu_cs_backdrops_len
    xor     r9d, r9d
    lea     rax, [g_d3d_cs]
    mov     qword ptr [rsp+32], rax
    call    qword ptr [r10 + VT_CREATE_CS]
    test    eax, eax
    js      gi_fail_clean

    ; 4) Create 64-byte Constant Buffer (Usage=DEFAULT, BindFlags=CONSTANT_BUFFER)
    mov     dword ptr [rbp-48], 64              ; ByteWidth = 64
    mov     dword ptr [rbp-44], D3D11_USAGE_DEFAULT
    mov     dword ptr [rbp-40], D3D11_BIND_CB
    mov     dword ptr [rbp-36], 0               ; CPUAccessFlags
    mov     dword ptr [rbp-32], 0               ; MiscFlags
    mov     dword ptr [rbp-28], 0               ; StructureByteStride
    mov     rcx, qword ptr [g_d3d_dev]
    mov     r10, qword ptr [rcx]
    lea     rdx, [rbp-48]
    xor     r8d, r8d
    lea     r9, [g_d3d_cb]
    call    qword ptr [r10 + VT_CREATE_BUF]
    test    eax, eax
    js      gi_fail_clean

    mov     eax, dword ptr [rbp-56]
    mov     dword ptr [g_gpu_backend], eax
gi_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret

gi_fail_clean:
    lea     rcx, [g_d3d_cb]
    call    gpu_rel_com
    lea     rcx, [g_d3d_cs]
    call    gpu_rel_com
    lea     rcx, [g_d3d_ctx]
    call    gpu_rel_com
    lea     rcx, [g_d3d_dev]
    call    gpu_rel_com
gi_fail:
    mov     dword ptr [g_gpu_backend], -1
gi_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
gpu_init endp

; gpu_active() -> eax = 1 if Backdrop is a GPU style (0..7) and D3D11 device is ready.
gpu_active proc frame
    FRAME_PROLOG 32
    cmp     dword ptr [g_backdrop_pref], BACKDROP_FLAT
    jae     ga_off
    call    gpu_init
    FRAME_EPILOG
    ret
ga_off:
    xor     eax, eax
    FRAME_EPILOG
    ret
gpu_active endp

; gpu_is_surface_hwnd(rcx = hwnd) -> eax = 1 if hwnd is DLG_VAULT or DLG_SETTINGS
;   AND a GPU backdrop is currently active.
gpu_is_surface_hwnd proc frame
    FRAME_PROLOG 48
    test    rcx, rcx
    jz      gish_no
    cmp     rcx, qword ptr [g_vaulthwnd]
    je      gish_chk
    cmp     rcx, qword ptr [g_settings_hwnd]
    je      gish_chk
gish_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
gish_chk:
    call    gpu_active
    FRAME_EPILOG
    ret
gpu_is_surface_hwnd endp

; gpu_set_vault_seed(rcx = ptr_salt32_or_null)
;   Derives deterministic non-secret geometry seeds from SHA-256("vordr-backdrop-v1" || salt32),
;   or restores default seeds when rcx == 0 (locked).
gpu_set_vault_seed proc frame
    FRAME_PROLOG 160
    ; [rbp-64..rbp-15]=msg(50B)  [rbp-96..rbp-65]=digest(32B)
    test    rcx, rcx
    jz      gsvs_def
    mov     r9, rcx
    lea     r10, [gpu_seed_dom]
    lea     r11, [rbp-64]
    xor     ecx, ecx
gsvs_dom:
    mov     al, byte ptr [r10 + rcx]
    mov     byte ptr [r11 + rcx], al
    inc     ecx
    cmp     ecx, gpu_seed_dom_len
    jb      gsvs_dom
    xor     ecx, ecx
gsvs_slt:
    mov     al, byte ptr [r9 + rcx]
    mov     byte ptr [r11 + gpu_seed_dom_len + rcx], al
    inc     ecx
    cmp     ecx, 32
    jb      gsvs_slt
    lea     rcx, [rbp-64]
    mov     edx, gpu_seed_dom_len + 32
    lea     r8, [rbp-96]
    call    sha256_hash
    mov     eax, dword ptr [rbp-96]
    mov     dword ptr [g_gpu_seed0], eax
    mov     eax, dword ptr [rbp-92]
    mov     dword ptr [g_gpu_seed1], eax
    mov     dword ptr [g_gpu_key_valid], 0
    mov     dword ptr [g_gpu_last_tms], -1
    FRAME_EPILOG
    ret
gsvs_def:
    mov     dword ptr [g_gpu_seed0], GPU_SEED_DEF0
    mov     dword ptr [g_gpu_seed1], GPU_SEED_DEF1
    mov     dword ptr [g_gpu_key_valid], 0
    mov     dword ptr [g_gpu_last_tms], -1
    FRAME_EPILOG
    ret
gpu_set_vault_seed endp

; gpu_hue_rot_rgb(ecx = colorref 0x00BBGGRR, edx = idx8 0..255) -> eax = 0x00BBGGRR
;   Exact Q14 luminance-preserving 3D Rodrigues hue rotation around (1,1,1)/sqrt(3).
gpu_hue_rot_rgb proc frame
    FRAME_PROLOG 48
    and     edx, 0FFh
    lea     r10, [gpu_ca_lut]
    mov     r8d, dword ptr [r10 + rdx*4]        ; ca
    lea     r10, [gpu_sa_lut]
    mov     r9d, dword ptr [r10 + rdx*4]        ; sa
    movzx   r10d, cl                            ; R
    mov     r11d, ecx
    shr     r11d, 8
    and     r11d, 0FFh                          ; G
    shr     ecx, 16
    and     ecx, 0FFh                           ; B

    mov     eax, r10d
    add     eax, r11d
    add     eax, ecx
    imul    eax, eax, 5461
    add     eax, 8192
    mov     dword ptr [rbp-16], eax             ; baseL

    ; R'
    mov     edx, r10d
    add     edx, edx
    sub     edx, r11d
    sub     edx, ecx
    imul    edx, r8d
    add     edx, eax
    mov     eax, r11d
    sub     eax, ecx
    imul    eax, r9d
    add     eax, edx
    sar     eax, 14
    test    eax, eax
    jns     @F
    xor     eax, eax
@@: cmp     eax, 255
    jle     @F
    mov     eax, 255
@@: mov     dword ptr [rbp-20], eax

    ; G'
    mov     edx, r11d
    add     edx, edx
    sub     edx, ecx
    sub     edx, r10d
    imul    edx, r8d
    add     edx, dword ptr [rbp-16]
    mov     eax, ecx
    sub     eax, r10d
    imul    eax, r9d
    add     eax, edx
    sar     eax, 14
    test    eax, eax
    jns     @F
    xor     eax, eax
@@: cmp     eax, 255
    jle     @F
    mov     eax, 255
@@: mov     dword ptr [rbp-24], eax

    ; B'
    mov     edx, ecx
    add     edx, edx
    sub     edx, r10d
    sub     edx, r11d
    imul    edx, r8d
    add     edx, dword ptr [rbp-16]
    mov     eax, r10d
    sub     eax, r11d
    imul    eax, r9d
    add     eax, edx
    sar     eax, 14
    test    eax, eax
    jns     @F
    xor     eax, eax
@@: cmp     eax, 255
    jle     @F
    mov     eax, 255
@@: shl     eax, 16
    mov     edx, dword ptr [rbp-24]
    shl     edx, 8
    or      eax, edx
    or      eax, dword ptr [rbp-20]
    FRAME_EPILOG
    ret
gpu_hue_rot_rgb endp

; gpu_boost_low_sat(ecx = colorref, edx = seed_colorref) -> eax = colorref
gpu_boost_low_sat proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-16], ecx
    mov     dword ptr [rbp-20], edx
    movzx   eax, cl
    mov     r8d, ecx
    shr     r8d, 8
    and     r8d, 0FFh
    mov     r9d, ecx
    shr     r9d, 16
    and     r9d, 0FFh
    mov     r10d, eax
    mov     r11d, eax
    cmp     r8d, r10d
    jle     @F
    mov     r10d, r8d
@@: cmp     r8d, r11d
    jge     @F
    mov     r11d, r8d
@@: cmp     r9d, r10d
    jle     @F
    mov     r10d, r9d
@@: cmp     r9d, r11d
    jge     @F
    mov     r11d, r9d
@@: sub     r10d, r11d
    cmp     r10d, 46
    jge     gbls_keep
    mov     ecx, dword ptr [rbp-20]
    mov     edx, dword ptr [rbp-16]
    mov     r8d, 115
    call    col_mix
    FRAME_EPILOG
    ret
gbls_keep:
    mov     eax, dword ptr [rbp-16]
    FRAME_EPILOG
    ret
gpu_boost_low_sat endp

; gpu_compose_cycle() - SSE2 chromatic accent composition from cached g_gpu_base_bits
;   into g_gpu_bits at g_gpu_time_ms (< 0.8 ms/frame, zero D3D11 dispatches).
gpu_compose_cycle proc frame
    FRAME_PROLOG 160
    mov     rax, qword ptr [g_gpu_base_bits]
    test    rax, rax
    jz      gcc_done
    mov     qword ptr [rbp-16], rax             ; srcPtr
    mov     rax, qword ptr [g_gpu_bits]
    test    rax, rax
    jz      gcc_done
    mov     qword ptr [rbp-24], rax             ; dstPtr
    cmp     dword ptr [g_gpu_w], 0
    jle     gcc_done
    cmp     dword ptr [g_gpu_h], 0
    jle     gcc_done

    mov     ecx, dword ptr [g_col_accent]
    mov     dword ptr [rbp-28], ecx             ; acc1
    mov     edx, dword ptr [g_col_accent2]
    mov     dword ptr [rbp-32], edx             ; acc2

    ; Ensure acc2 is chromatically distinct from acc1 (|dR| + |dG| + |dB| >= 90)
    movzx   eax, cl
    movzx   r8d, dl
    sub     eax, r8d
    jns     @F
    neg     eax
@@: mov     r10d, eax
    mov     eax, ecx
    shr     eax, 8
    and     eax, 0FFh
    mov     r8d, edx
    shr     r8d, 8
    and     r8d, 0FFh
    sub     eax, r8d
    jns     @F
    neg     eax
@@: add     r10d, eax
    mov     eax, ecx
    shr     eax, 16
    and     eax, 0FFh
    mov     r8d, edx
    shr     r8d, 16
    and     r8d, 0FFh
    sub     eax, r8d
    jns     @F
    neg     eax
@@: add     r10d, eax
    cmp     r10d, 90
    jge     gcc_chk_time
    mov     edx, 80                             ; ~1.96 rad offset
    call    gpu_hue_rot_rgb
    mov     dword ptr [rbp-32], eax

gcc_chk_time:
    mov     dword ptr [rbp-36], 0               ; basePhase_q8
    mov     dword ptr [rbp-40], 0               ; ramp_q8
    mov     dword ptr [rbp-44], 0               ; delta2_q8
    mov     dword ptr [rbp-48], 0               ; stepX_q8
    cmp     dword ptr [g_gpu_time_ms], 0
    je      gcc_prep_bias

    ; Boost near-monochrome accents gently during active cycling
    mov     ecx, dword ptr [rbp-28]
    mov     edx, 00F29447h                      ; RGB(71, 148, 242)
    call    gpu_boost_low_sat
    mov     dword ptr [rbp-28], eax
    mov     ecx, dword ptr [rbp-32]
    mov     edx, 009E61EBh                      ; RGB(235, 97, 158)
    call    gpu_boost_low_sat
    mov     dword ptr [rbp-32], eax

    ; basePhase_q8 = (time_ms * 5736) >> 10 (~11.7s full 360-deg cycle)
    mov     eax, dword ptr [g_gpu_time_ms]
    imul    rax, rax, 5736
    shr     rax, 10
    mov     dword ptr [rbp-36], eax

    ; ramp_q8 = min(256, time_ms >> 3)
    mov     eax, dword ptr [g_gpu_time_ms]
    shr     eax, 3
    cmp     eax, 256
    jbe     @F
    mov     eax, 256
@@: mov     dword ptr [rbp-40], eax             ; ramp_q8

    ; stepX_q8 per 16px span = ((241984 * ramp_q8) / w) >> 8
    imul    eax, eax, 241984
    xor     edx, edx
    div     dword ptr [g_gpu_w]
    shr     eax, 8
    mov     dword ptr [rbp-48], eax

    ; delta2_q8 = (sin(sec * 0.31) * 0.55) in Q8 LUT units
    mov     eax, dword ptr [g_gpu_time_ms]
    imul    rax, rax, 3234
    shr     rax, 18
    and     eax, 0FFh
    lea     r10, [gpu_sa_lut]
    mov     eax, dword ptr [r10 + rax*4]
    imul    eax, eax, 608
    sar     eax, 10
    mov     dword ptr [rbp-44], eax

gcc_prep_bias:
    mov     dword ptr [rbp-112], 128
    mov     dword ptr [rbp-108], 128
    mov     dword ptr [rbp-104], 128
    mov     dword ptr [rbp-100], 0
    mov     dword ptr [rbp-64], -1              ; lastPair = -1
    mov     dword ptr [rbp-52], 0               ; y = 0

gcc_row_lp:
    mov     eax, dword ptr [rbp-52]
    cmp     eax, dword ptr [g_gpu_h]
    jae     gcc_done

    ; rowPhase_q8 = basePhase_q8 - (((y * 9387) / h) * ramp_q8 >> 8)
    imul    eax, eax, 9387
    xor     edx, edx
    div     dword ptr [g_gpu_h]
    imul    eax, dword ptr [rbp-40]
    shr     eax, 8
    mov     ecx, dword ptr [rbp-36]
    sub     ecx, eax
    mov     dword ptr [rbp-60], ecx             ; curPhase_q8

    mov     eax, dword ptr [g_gpu_w]
    mov     dword ptr [rbp-56], eax             ; remX = w

gcc_span_lp:
    mov     ecx, dword ptr [rbp-56]
    test    ecx, ecx
    jle     gcc_next_row
    cmp     ecx, 16
    jle     @F
    mov     ecx, 16
@@: mov     dword ptr [rbp-68], ecx             ; spanLen

    mov     eax, dword ptr [rbp-60]
    mov     edx, eax
    shr     edx, 8
    and     edx, 0FFh                           ; idx1
    add     eax, dword ptr [rbp-44]
    shr     eax, 8
    and     eax, 0FFh                           ; idx2
    mov     ecx, eax
    shl     ecx, 8
    or      ecx, edx                            ; pair = (idx2 << 8) | idx1
    cmp     ecx, dword ptr [rbp-64]
    je      gcc_have_xmm
    mov     dword ptr [rbp-64], ecx

    ; Compute rotated acc1 (idx1) and acc2 (idx2) -> [rbp-96]
    mov     ecx, dword ptr [rbp-28]
    call    gpu_hue_rot_rgb
    mov     dword ptr [rbp-72], eax             ; rotAcc1

    mov     edx, dword ptr [rbp-64]
    shr     edx, 8
    and     edx, 0FFh
    mov     ecx, dword ptr [rbp-32]
    call    gpu_hue_rot_rgb                     ; eax = rotAcc2, [rbp-72] = rotAcc1

    mov     ecx, dword ptr [rbp-72]
    mov     edx, ecx
    shr     edx, 16
    and     edx, 0FFh
    mov     word ptr [rbp-96], dx               ; B1
    mov     edx, eax
    shr     edx, 16
    and     edx, 0FFh
    mov     word ptr [rbp-94], dx               ; B2

    mov     edx, ecx
    shr     edx, 8
    and     edx, 0FFh
    mov     word ptr [rbp-92], dx               ; G1
    mov     edx, eax
    shr     edx, 8
    and     edx, 0FFh
    mov     word ptr [rbp-90], dx               ; G2

    movzx   edx, cl
    mov     word ptr [rbp-88], dx               ; R1
    movzx   edx, al
    mov     word ptr [rbp-86], dx               ; R2
    mov     dword ptr [rbp-84], 0

gcc_have_xmm:
    movdqu  xmm2, xmmword ptr [rbp-96]
    movdqu  xmm3, xmmword ptr [rbp-112]
    mov     r8, qword ptr [rbp-16]
    mov     r9, qword ptr [rbp-24]
    mov     ecx, dword ptr [rbp-68]

gcc_px_lp:
    mov     eax, dword ptr [r8]
    mov     edx, dword ptr [r8 + 4]
    test    edx, edx
    jz      gcc_px_st
    movd    xmm1, edx
    pshufd  xmm1, xmm1, 0
    pmaddwd xmm1, xmm2
    paddd   xmm1, xmm3
    psrld   xmm1, 8
    packssdw xmm1, xmm1
    packuswb xmm1, xmm1
    movd    xmm0, eax
    paddusb xmm0, xmm1
    movd    eax, xmm0
gcc_px_st:
    mov     dword ptr [r9], eax
    add     r8, 8
    add     r9, 4
    dec     ecx
    jnz     gcc_px_lp

    mov     qword ptr [rbp-16], r8
    mov     qword ptr [rbp-24], r9
    mov     eax, dword ptr [rbp-68]
    sub     dword ptr [rbp-56], eax
    mov     eax, dword ptr [rbp-48]
    add     dword ptr [rbp-60], eax
    jmp     gcc_span_lp

gcc_next_row:
    inc     dword ptr [rbp-52]
    jmp     gcc_row_lp

gcc_done:
    FRAME_EPILOG
    ret
gpu_compose_cycle endp

; gpu_ensure_surface(ecx = width, edx = height) -> eax = 1 cached DIB ready, 0 fallback.
gpu_ensure_surface proc frame
    FRAME_PROLOG 352
    ; Stack layout (all locals >= rbp-248, leaving 104B for max 7-arg calls):
    ;   [rbp-16] = w              [rbp-20] = h              [rbp-24] = num_px
    ;   [rbp-28] = byte_w         [rbp-32] = mode           [rbp-40] = null_ptr
    ;   [rbp-88..rbp-53]  = key[9] (36B)
    ;   [rbp-136..rbp-97] = BITMAPINFOHEADER (40B)
    ;   [rbp-168..rbp-145]= D3D11_BUFFER_DESC / UAV_DESC (24B)
    ;   [rbp-232..rbp-169]= BackdropCB (64B)
    ;   [rbp-248..rbp-233]= D3D11_MAPPED_SUBRESOURCE (16B)
    mov     eax, dword ptr [g_backdrop_pref]
    cmp     eax, BACKDROP_FLAT
    jae     ges_fail
    mov     dword ptr [rbp-32], eax             ; mode (0..7)

    cmp     ecx, 16
    jge     @F
    mov     ecx, 16
@@: cmp     ecx, 7680
    jle     @F
    mov     ecx, 7680
@@: cmp     edx, 16
    jge     @F
    mov     edx, 16
@@: cmp     edx, 4320
    jle     @F
    mov     edx, 4320
@@: mov     dword ptr [rbp-16], ecx
    mov     dword ptr [rbp-20], edx

    call    gpu_init
    test    eax, eax
    jz      ges_fail

    mov     ecx, dword ptr [rbp-16]
    mov     edx, dword ptr [rbp-20]
    cmp     ecx, dword ptr [g_gpu_w]
    jne     ges_resize
    cmp     edx, dword ptr [g_gpu_h]
    jne     ges_resize
    cmp     qword ptr [g_gpu_bits], 0
    je      ges_resize
    cmp     qword ptr [g_gpu_base_bits], 0
    je      ges_resize
    jmp     ges_check_key

ges_resize:
    call    gpu_free_buffers
    cmp     qword ptr [g_gpu_hdc], 0
    jne     ges_have_dc
    WINCALL CreateCompatibleDC, 0
    test    rax, rax
    jz      ges_fail
    mov     qword ptr [g_gpu_hdc], rax
ges_have_dc:
    lea     r10, [rbp-136]
    xor     eax, eax
    mov     qword ptr [r10+0], rax
    mov     qword ptr [r10+8], rax
    mov     qword ptr [r10+16], rax
    mov     qword ptr [r10+24], rax
    mov     qword ptr [r10+32], rax
    mov     dword ptr [r10+0], 40               ; biSize
    mov     ecx, dword ptr [rbp-16]
    mov     dword ptr [r10+4], ecx              ; biWidth
    mov     edx, dword ptr [rbp-20]
    neg     edx
    mov     dword ptr [r10+8], edx              ; biHeight = -h (top-down!)
    mov     word ptr [r10+12], 1                ; biPlanes = 1
    mov     word ptr [r10+14], 32               ; biBitCount = 32 (BGRA8)

    WINCALL CreateDIBSection, qword ptr [g_gpu_hdc], addr rbp-136, 0, addr g_gpu_bits, 0, 0
    test    rax, rax
    jz      ges_fail_free
    mov     qword ptr [g_gpu_hbmp], rax
    WINCALL SelectObject, qword ptr [g_gpu_hdc], rax
    mov     qword ptr [g_gpu_oldbmp], rax

    mov     eax, dword ptr [rbp-16]
    imul    eax, dword ptr [rbp-20]
    mov     dword ptr [rbp-24], eax             ; num_px = w * h
    shl     eax, 3
    mov     dword ptr [rbp-28], eax             ; byte_w = w * h * 8 (uint2 per pixel)

    ; Allocate CPU static basis buffer (8 bytes/pixel)
    mov     edx, dword ptr [rbp-28]
    WINCALL VirtualAlloc, 0, rdx, MEM_COMMIT_RES_, PAGE_RW_
    test    rax, rax
    jz      ges_fail_free
    mov     qword ptr [g_gpu_base_bits], rax

    ; Create GPU Structured UAV Buffer (uint2 = 8 bytes/element)
    mov     eax, dword ptr [rbp-28]
    mov     dword ptr [rbp-168], eax            ; ByteWidth
    mov     dword ptr [rbp-164], D3D11_USAGE_DEFAULT
    mov     dword ptr [rbp-160], D3D11_BIND_UAV
    mov     dword ptr [rbp-156], 0              ; CPUAccessFlags
    mov     dword ptr [rbp-152], D3D11_MISC_STRUCT
    mov     dword ptr [rbp-148], 8              ; StructureByteStride = 8
    mov     rcx, qword ptr [g_d3d_dev]
    mov     r10, qword ptr [rcx]
    lea     rdx, [rbp-168]
    xor     r8d, r8d
    lea     r9, [g_d3d_uav_buf]
    call    qword ptr [r10 + VT_CREATE_BUF]
    test    eax, eax
    js      ges_dev_lost

    ; Create UnorderedAccessView over g_d3d_uav_buf
    mov     dword ptr [rbp-168], 0              ; DXGI_FORMAT_UNKNOWN (structured)
    mov     dword ptr [rbp-164], D3D11_UAV_DIM_BUF
    mov     dword ptr [rbp-160], 0              ; FirstElement = 0
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [rbp-156], eax            ; NumElements = num_px
    mov     dword ptr [rbp-152], 0              ; Flags = 0
    mov     rcx, qword ptr [g_d3d_dev]
    mov     r10, qword ptr [rcx]
    mov     rdx, qword ptr [g_d3d_uav_buf]
    lea     r8, [rbp-168]
    lea     r9, [g_d3d_uav]
    call    qword ptr [r10 + VT_CREATE_UAV]
    test    eax, eax
    js      ges_dev_lost

    ; Create Staging Readback Buffer (uint2 = 8 bytes/element)
    mov     eax, dword ptr [rbp-28]
    mov     dword ptr [rbp-168], eax            ; ByteWidth
    mov     dword ptr [rbp-164], D3D11_USAGE_STAGING
    mov     dword ptr [rbp-160], 0              ; BindFlags = 0
    mov     dword ptr [rbp-156], D3D11_CPU_READ
    mov     dword ptr [rbp-152], D3D11_MISC_STRUCT
    mov     dword ptr [rbp-148], 8              ; StructureByteStride = 8
    mov     rcx, qword ptr [g_d3d_dev]
    mov     r10, qword ptr [rcx]
    lea     rdx, [rbp-168]
    xor     r8d, r8d
    lea     r9, [g_d3d_stg_buf]
    call    qword ptr [r10 + VT_CREATE_BUF]
    test    eax, eax
    js      ges_dev_lost

    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [g_gpu_w], eax
    mov     eax, dword ptr [rbp-20]
    mov     dword ptr [g_gpu_h], eax

ges_check_key:
    ; Build 9-dword static geometry/palette fingerprint at [rbp-88..rbp-53]
    ; (excludes g_gpu_time_ms so D3D11 dispatches ONLY ONCE per static config!)
    mov     ecx, dword ptr [rbp-16]
    mov     dword ptr [rbp-88], ecx
    mov     ecx, dword ptr [rbp-20]
    mov     dword ptr [rbp-84], ecx
    mov     ecx, dword ptr [g_gpu_seed0]
    mov     dword ptr [rbp-80], ecx
    mov     ecx, dword ptr [g_gpu_seed1]
    mov     dword ptr [rbp-76], ecx
    mov     ecx, dword ptr [g_col_bg]
    mov     dword ptr [rbp-72], ecx
    mov     ecx, dword ptr [g_col_panel]
    mov     dword ptr [rbp-68], ecx
    mov     ecx, dword ptr [g_col_accent]
    mov     dword ptr [rbp-64], ecx
    mov     ecx, dword ptr [g_col_accent2]
    mov     dword ptr [rbp-60], ecx
    mov     ecx, dword ptr [g_col_dark]
    shl     ecx, 16
    or      ecx, dword ptr [rbp-32]             ; (dark << 16) | mode
    mov     dword ptr [rbp-56], ecx

    cmp     dword ptr [g_gpu_key_valid], 0
    je      ges_dispatch
    lea     r8, [rbp-88]
    lea     r9, [g_gpu_last_key]
    xor     ecx, ecx
ges_cmp_lp:
    mov     eax, dword ptr [r8 + rcx*4]
    cmp     eax, dword ptr [r9 + rcx*4]
    jne     ges_dispatch
    inc     ecx
    cmp     ecx, 9
    jb      ges_cmp_lp
    jmp     ges_check_cycle

ges_dispatch:
    ; Populate 64-byte BackdropCB at [rbp-232..rbp-169]
    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [rbp-232 + 0], eax        ; u_width
    mov     eax, dword ptr [rbp-20]
    mov     dword ptr [rbp-232 + 4], eax        ; u_height
    mov     eax, dword ptr [g_gpu_seed0]
    mov     dword ptr [rbp-232 + 8], eax        ; u_seed0
    mov     eax, dword ptr [g_gpu_seed1]
    mov     dword ptr [rbp-232 + 12], eax       ; u_seed1
    mov     eax, dword ptr [g_col_bg]
    mov     dword ptr [rbp-232 + 16], eax       ; u_col_bg
    mov     eax, dword ptr [g_col_panel]
    mov     dword ptr [rbp-232 + 20], eax       ; u_col_panel
    mov     eax, dword ptr [g_col_accent]
    mov     dword ptr [rbp-232 + 24], eax       ; u_col_acc
    mov     eax, dword ptr [g_col_accent2]
    mov     dword ptr [rbp-232 + 28], eax       ; u_col_acc2
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [rbp-232 + 32], eax       ; u_mode
    mov     eax, dword ptr [g_col_dark]
    mov     dword ptr [rbp-232 + 36], eax       ; u_dark
    mov     dword ptr [rbp-232 + 40], 0         ; u_pad0
    mov     dword ptr [rbp-232 + 44], 0         ; u_pad1
    mov     qword ptr [rbp-232 + 48], 0
    mov     qword ptr [rbp-232 + 56], 0

    ; UpdateSubresource(ctx, g_d3d_cb, 0, NULL, &cb, 0, 0)
    mov     rcx, qword ptr [g_d3d_ctx]
    mov     r10, qword ptr [rcx]
    mov     rdx, qword ptr [g_d3d_cb]
    xor     r8d, r8d
    xor     r9d, r9d
    lea     rax, [rbp-232]
    mov     qword ptr [rsp+32], rax
    mov     dword ptr [rsp+40], 0
    mov     dword ptr [rsp+48], 0
    call    qword ptr [r10 + VT_CTX_UPDSUB]

    ; CSSetShader(ctx, g_d3d_cs, NULL, 0)
    mov     rcx, qword ptr [g_d3d_ctx]
    mov     r10, qword ptr [rcx]
    mov     rdx, qword ptr [g_d3d_cs]
    xor     r8d, r8d
    xor     r9d, r9d
    call    qword ptr [r10 + VT_CTX_CS_SHD]

    ; CSSetConstantBuffers(ctx, 0, 1, &g_d3d_cb)
    mov     rcx, qword ptr [g_d3d_ctx]
    mov     r10, qword ptr [rcx]
    xor     edx, edx
    mov     r8d, 1
    lea     r9, [g_d3d_cb]
    call    qword ptr [r10 + VT_CTX_CS_CB]

    ; CSSetUnorderedAccessViews(ctx, 0, 1, &g_d3d_uav, NULL)
    mov     rcx, qword ptr [g_d3d_ctx]
    mov     r10, qword ptr [rcx]
    xor     edx, edx
    mov     r8d, 1
    lea     r9, [g_d3d_uav]
    mov     qword ptr [rsp+32], 0
    call    qword ptr [r10 + VT_CTX_CS_UAV]

    ; Dispatch(ctx, (w + 15) >> 4, (h + 15) >> 4, 1)
    mov     rcx, qword ptr [g_d3d_ctx]
    mov     r10, qword ptr [rcx]
    mov     edx, dword ptr [rbp-16]
    add     edx, 15
    shr     edx, 4
    mov     r8d, dword ptr [rbp-20]
    add     r8d, 15
    shr     r8d, 4
    mov     r9d, 1
    call    qword ptr [r10 + VT_CTX_DISPATCH]

    ; Unbind UAV before CopyResource
    mov     qword ptr [rbp-40], 0
    mov     rcx, qword ptr [g_d3d_ctx]
    mov     r10, qword ptr [rcx]
    xor     edx, edx
    mov     r8d, 1
    lea     r9, [rbp-40]
    mov     qword ptr [rsp+32], 0
    call    qword ptr [r10 + VT_CTX_CS_UAV]

    ; CopyResource(ctx, g_d3d_stg_buf, g_d3d_uav_buf)
    mov     rcx, qword ptr [g_d3d_ctx]
    mov     r10, qword ptr [rcx]
    mov     rdx, qword ptr [g_d3d_stg_buf]
    mov     r8, qword ptr [g_d3d_uav_buf]
    call    qword ptr [r10 + VT_CTX_COPYRES]

    ; Map(ctx, g_d3d_stg_buf, 0, D3D11_MAP_READ, 0, &mapped)
    mov     qword ptr [rbp-248], 0
    mov     rcx, qword ptr [g_d3d_ctx]
    mov     r10, qword ptr [rcx]
    mov     rdx, qword ptr [g_d3d_stg_buf]
    xor     r8d, r8d
    mov     r9d, D3D11_MAP_READ_
    mov     dword ptr [rsp+32], 0
    lea     rax, [rbp-248]
    mov     qword ptr [rsp+40], rax
    call    qword ptr [r10 + VT_CTX_MAP]
    test    eax, eax
    js      ges_dev_lost

    ; Copy uint2 (8B/px) basis from mapped.pData -> g_gpu_base_bits
    mov     r8, qword ptr [rbp-248]
    mov     r9, qword ptr [g_gpu_base_bits]
    test    r8, r8
    jz      ges_unmap
    test    r9, r9
    jz      ges_unmap
    mov     ecx, dword ptr [rbp-16]
    imul    ecx, dword ptr [rbp-20]
    test    ecx, ecx
    jz      ges_unmap
ges_cp_qw:
    mov     rax, qword ptr [r8]
    mov     qword ptr [r9], rax
    add     r8, 8
    add     r9, 8
    dec     ecx
    jnz     ges_cp_qw

ges_unmap:
    mov     rcx, qword ptr [g_d3d_ctx]
    mov     r10, qword ptr [rcx]
    mov     rdx, qword ptr [g_d3d_stg_buf]
    xor     r8d, r8d
    call    qword ptr [r10 + VT_CTX_UNMAP]

    ; Commit 9-dword static state fingerprint
    lea     r8, [rbp-88]
    lea     r9, [g_gpu_last_key]
    xor     ecx, ecx
ges_sv_lp:
    mov     eax, dword ptr [r8 + rcx*4]
    mov     dword ptr [r9 + rcx*4], eax
    inc     ecx
    cmp     ecx, 9
    jb      ges_sv_lp
    mov     dword ptr [g_gpu_key_valid], 1
    mov     dword ptr [g_gpu_last_tms], -1
    inc     dword ptr [g_gpu_dispatches]

ges_check_cycle:
    mov     eax, dword ptr [g_gpu_time_ms]
    cmp     eax, dword ptr [g_gpu_last_tms]
    je      ges_ready
    call    gpu_compose_cycle
    mov     eax, dword ptr [g_gpu_time_ms]
    mov     dword ptr [g_gpu_last_tms], eax
    WINCALL GdiFlush
ges_ready:
    mov     eax, 1
    FRAME_EPILOG
    ret

ges_dev_lost:
    ; AUD-24: TDR / DXGI_ERROR_DEVICE_REMOVED during Map: release all D3D11 COM objects
    ; and fall back to WARP (if we were on HW) or mark GPU unavailable (-1) so AMBIENT_TIMER
    ; never loops re-dispatching a removed device.
    call    gpu_free_buffers
    lea     rcx, [g_d3d_cb]
    call    gpu_rel_com
    lea     rcx, [g_d3d_cs]
    call    gpu_rel_com
    lea     rcx, [g_d3d_ctx]
    call    gpu_rel_com
    lea     rcx, [g_d3d_dev]
    call    gpu_rel_com
    cmp     dword ptr [g_gpu_backend], 1
    jne     ges_dl_disable
    mov     dword ptr [g_gpu_force_warp], 1
    mov     dword ptr [g_gpu_backend], 0
    jmp     ges_fail
ges_dl_disable:
    mov     dword ptr [g_gpu_backend], -1
    jmp     ges_fail

ges_fail_free:
    call    gpu_free_buffers
ges_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
gpu_ensure_surface endp

; gpu_paint_bg(rcx = hdc, rdx = hwnd) -> eax = 1 painted, 0 use solid fallback.
gpu_paint_bg proc frame
    FRAME_PROLOG 176
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     rcx, rdx
    call    gpu_is_surface_hwnd
    test    eax, eax
    jz      gpb_no

    WINCALL GetClientRect, qword ptr [g_vaulthwnd], addr rbp-48
    mov     ecx, dword ptr [rbp-40]
    mov     edx, dword ptr [rbp-36]
    cmp     ecx, 0
    jle     gpb_no
    cmp     edx, 0
    jle     gpb_no
    call    gpu_ensure_surface
    test    eax, eax
    jz      gpb_no

    WINCALL GetClientRect, qword ptr [rbp-24], addr rbp-64
    mov     qword ptr [rbp-80], 0
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [g_vaulthwnd]
    je      gpb_blt
    WINCALL MapWindowPoints, qword ptr [rbp-24], qword ptr [g_vaulthwnd], addr rbp-80, 1
gpb_blt:
    WINCALL BitBlt, qword ptr [rbp-16], 0, 0, dword ptr [rbp-56], dword ptr [rbp-52], \
            qword ptr [g_gpu_hdc], dword ptr [rbp-80], dword ptr [rbp-76], SRCCOPY_
    mov     eax, 1
    FRAME_EPILOG
    ret
gpb_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
gpu_paint_bg endp

; gpu_fill_child_bg(rcx = hdc, rdx = hwnd_child, r8 = ptr_rc_local) -> eax = 1 painted, 0 fallback.
gpu_fill_child_bg proc frame
    FRAME_PROLOG 176
    test    rcx, rcx
    jz      gfcb_no
    cmp     rcx, qword ptr [g_comp_hdc]
    je      gfcb_ok
    test    rdx, rdx
    jz      gfcb_no
    test    r8, r8
    jz      gfcb_no
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8

    WINCALL GetParent, rdx
    mov     rcx, rax
    call    gpu_is_surface_hwnd
    test    eax, eax
    jz      gfcb_no

    WINCALL GetClientRect, qword ptr [g_vaulthwnd], addr rbp-48
    mov     ecx, dword ptr [rbp-40]
    mov     edx, dword ptr [rbp-36]
    cmp     ecx, 0
    jle     gfcb_no
    cmp     edx, 0
    jle     gfcb_no
    call    gpu_ensure_surface
    test    eax, eax
    jz      gfcb_no

    mov     r10, qword ptr [rbp-32]
    mov     eax, dword ptr [r10+0]
    mov     dword ptr [rbp-64], eax
    mov     ecx, dword ptr [r10+4]
    mov     dword ptr [rbp-60], ecx
    WINCALL MapWindowPoints, qword ptr [rbp-24], qword ptr [g_vaulthwnd], addr rbp-64, 1

    mov     r10, qword ptr [rbp-32]
    mov     r8d, dword ptr [r10+8]
    sub     r8d, dword ptr [r10+0]
    jle     gfcb_ok
    mov     r9d, dword ptr [r10+12]
    sub     r9d, dword ptr [r10+4]
    jle     gfcb_ok
    WINCALL BitBlt, qword ptr [rbp-16], dword ptr [r10+0], dword ptr [r10+4], r8d, r9d, \
            qword ptr [g_gpu_hdc], dword ptr [rbp-64], dword ptr [rbp-60], SRCCOPY_
gfcb_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
gfcb_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
gpu_fill_child_bg endp

; gpu_sample_child_bg(rcx = hwnd_child) -> eax = COLORREF (0x00BBGGRR) under the
;   center of hwnd_child from g_gpu_bits, or -1 if unavailable.
gpu_sample_child_bg proc frame
    FRAME_PROLOG 96
    test    rcx, rcx
    jz      gscb_no
    mov     qword ptr [rbp-16], rcx
    WINCALL GetParent, rcx
    mov     rcx, rax
    call    gpu_is_surface_hwnd
    test    eax, eax
    jz      gscb_no
    cmp     qword ptr [g_gpu_bits], 0
    je      gscb_no
    WINCALL GetClientRect, qword ptr [rbp-16], addr rbp-32
    mov     eax, dword ptr [rbp-24]
    shr     eax, 1
    mov     dword ptr [rbp-48], eax
    mov     eax, dword ptr [rbp-20]
    shr     eax, 1
    mov     dword ptr [rbp-44], eax
    WINCALL MapWindowPoints, qword ptr [rbp-16], qword ptr [g_vaulthwnd], addr rbp-48, 1
    mov     ecx, dword ptr [rbp-48]
    mov     edx, dword ptr [rbp-44]
    test    ecx, ecx
    js      gscb_no
    test    edx, edx
    js      gscb_no
    cmp     ecx, dword ptr [g_gpu_w]
    jae     gscb_no
    cmp     edx, dword ptr [g_gpu_h]
    jae     gscb_no
    imul    edx, dword ptr [g_gpu_w]
    add     edx, ecx
    mov     r8, qword ptr [g_gpu_bits]
    mov     eax, dword ptr [r8 + rdx*4]         ; 0xFFRRGGBB (BGRA8 little-endian)
    mov     ecx, eax
    and     ecx, 0000FF00h
    mov     edx, eax
    shr     edx, 16
    and     edx, 0FFh
    shl     eax, 16
    and     eax, 00FF0000h
    or      eax, ecx
    or      eax, edx
    FRAME_EPILOG
    ret
gscb_no:
    mov     eax, -1
    FRAME_EPILOG
    ret
gpu_sample_child_bg endp

; gpu_fill_glass_child(rcx = hdc, rdx = hwnd_child, r8 = ptr_rc_local) -> eax = 1 painted, 0 fallback.
;   Paints the exact 40% g_col_panel glass interior over the child's backdrop slice
;   (GPU procedural backdrop when active, or g_br_bg when Backdrop == Flat) on
;   DLG_VAULT and DLG_SETTINGS so child controls blend seamlessly into glass cards.
gpu_fill_glass_child proc frame
    FRAME_PROLOG 160
    test    rcx, rcx
    jz      gfgc_no
    cmp     rcx, qword ptr [g_comp_hdc]
    je      gfgc_ok
    test    rdx, rdx
    jz      gfgc_no
    test    r8, r8
    jz      gfgc_no
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8

    WINCALL GetParent, rdx
    test    rax, rax
    jz      gfgc_no
    cmp     rax, qword ptr [g_vaulthwnd]
    je      gfgc_surf
    cmp     rax, qword ptr [g_settings_hwnd]
    jne     gfgc_no

gfgc_surf:
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-24]
    mov     r8, qword ptr [rbp-32]
    call    gpu_fill_child_bg
    test    eax, eax
    jnz     gfgc_tint
    WINCALL FillRect, qword ptr [rbp-16], qword ptr [rbp-32], qword ptr [g_br_bg]

gfgc_tint:
    mov     r10, qword ptr [rbp-32]
    mov     ecx, dword ptr [r10+0]
    mov     dword ptr [rbp-36], ecx             ; L
    mov     edx, dword ptr [r10+4]
    mov     dword ptr [rbp-40], edx             ; T
    mov     r8d, dword ptr [r10+8]
    sub     r8d, ecx
    jle     gfgc_ok
    mov     dword ptr [rbp-44], r8d             ; W
    mov     r9d, dword ptr [r10+12]
    sub     r9d, edx
    jle     gfgc_ok
    mov     dword ptr [rbp-48], r9d             ; H
    call    theme_glass_alpha
    mov     dword ptr [rbp-52], eax
    WINCALL theme_glass_tint, qword ptr [rbp-16], dword ptr [rbp-36], dword ptr [rbp-40], \
            dword ptr [rbp-44], dword ptr [rbp-48], dword ptr [g_col_panel], dword ptr [rbp-52]
gfgc_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
gfgc_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
gpu_fill_glass_child endp

; gpu_sample_glass_child(rcx = hwnd_child) -> eax = COLORREF under hwnd_child blended
;   with 40% g_col_panel (for SetBkColor / ghost button hover halos inside glass cards).
gpu_sample_glass_child proc frame
    FRAME_PROLOG 64
    call    gpu_sample_child_bg
    cmp     eax, -1
    jne     @F
    mov     eax, dword ptr [g_col_bg]
@@: mov     dword ptr [rbp-16], eax
    call    theme_glass_alpha
    mov     r8d, eax
    mov     ecx, dword ptr [rbp-16]
    mov     edx, dword ptr [g_col_panel]
    call    col_mix
    FRAME_EPILOG
    ret
gpu_sample_glass_child endp

; gpu_fill_side_glass_child(rcx = hdc, rdx = hwnd_child, r8 = ptr_rc_local) -> eax = 1 painted, 0 fallback.
;   Paints the exact scheme-aware g_col_side glass interior over the child's backdrop slice
;   on DLG_VAULT so IDC_V_LIST and IDC_V_SEARCH blend seamlessly into theme_sidecard.
gpu_fill_side_glass_child proc frame
    FRAME_PROLOG 160
    test    rcx, rcx
    jz      gfsg_no
    cmp     rcx, qword ptr [g_comp_hdc]
    je      gfsg_ok
    test    rdx, rdx
    jz      gfsg_no
    test    r8, r8
    jz      gfsg_no
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8

    WINCALL GetParent, rdx
    test    rax, rax
    jz      gfsg_no
    cmp     rax, qword ptr [g_vaulthwnd]
    jne     gfsg_no

    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-24]
    mov     r8, qword ptr [rbp-32]
    call    gpu_fill_child_bg
    test    eax, eax
    jnz     gfsg_tint
    WINCALL FillRect, qword ptr [rbp-16], qword ptr [rbp-32], qword ptr [g_br_bg]

gfsg_tint:
    mov     r10, qword ptr [rbp-32]
    mov     ecx, dword ptr [r10+0]
    mov     dword ptr [rbp-36], ecx             ; L
    mov     edx, dword ptr [r10+4]
    mov     dword ptr [rbp-40], edx             ; T
    mov     r8d, dword ptr [r10+8]
    sub     r8d, ecx
    jle     gfsg_ok
    mov     dword ptr [rbp-44], r8d             ; W
    mov     r9d, dword ptr [r10+12]
    sub     r9d, edx
    jle     gfsg_ok
    mov     dword ptr [rbp-48], r9d             ; H
    call    theme_glass_alpha
    mov     dword ptr [rbp-52], eax
    WINCALL theme_glass_tint, qword ptr [rbp-16], dword ptr [rbp-36], dword ptr [rbp-40], \
            dword ptr [rbp-44], dword ptr [rbp-48], dword ptr [g_col_side], dword ptr [rbp-52]
gfsg_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
gfsg_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
gpu_fill_side_glass_child endp

; gpu_sample_side_glass_child(rcx = hwnd_child) -> eax = COLORREF under hwnd_child blended
;   with scheme-aware g_col_side glass (for SetBkColor on IDC_V_SEARCH).
gpu_sample_side_glass_child proc frame
    FRAME_PROLOG 64
    call    gpu_sample_child_bg
    cmp     eax, -1
    jne     @F
    mov     eax, dword ptr [g_col_bg]
@@: mov     dword ptr [rbp-16], eax
    call    theme_glass_alpha
    mov     r8d, eax
    mov     ecx, dword ptr [rbp-16]
    mov     edx, dword ptr [g_col_side]
    call    col_mix
    FRAME_EPILOG
    ret
gpu_sample_side_glass_child endp

; =============================================================================
; cmd_gpukat - Deterministic D3D11 DirectCompute KAT across all 7 GPU modes.
; =============================================================================
ifdef PROBE_IO
LANDING_PAD
cmd_gpukat proc frame
    FRAME_PROLOG 96
    ; [rbp-16]=orig_pref  [rbp-20]=mode  [rbp-24]=d0  [rbp-28]=orig_tms
    mov     eax, dword ptr [g_backdrop_pref]
    mov     dword ptr [rbp-16], eax
    mov     eax, dword ptr [g_gpu_time_ms]
    mov     dword ptr [rbp-28], eax
    mov     dword ptr [g_gpu_time_ms], 0
    xor     ecx, ecx
    call    gpu_set_vault_seed

    mov     dword ptr [rbp-20], 0               ; mode = 0..7
gpk_mode_lp:
    mov     eax, dword ptr [rbp-20]
    mov     dword ptr [g_backdrop_pref], eax
    mov     ecx, 240
    mov     edx, 160
    call    gpu_ensure_surface
    test    eax, eax
    jz      gpk_fail
    cmp     dword ptr [g_gpu_backend], 1
    jb      gpk_fail
    cmp     dword ptr [g_gpu_backend], 2
    ja      gpk_fail

    ; Scan pixels: alpha == 0xFF, non-uniform (> 800 pixels differ from pixel[0]),
    ; and fold rolling FNV-like checksum to ensure all 8 modes are distinct.
    mov     r8, qword ptr [g_gpu_bits]
    test    r8, r8
    jz      gpk_fail
    mov     r9d, dword ptr [r8]
    mov     r11d, 811C9DC5h
    xor     ecx, ecx
    xor     edx, edx
gpk_px_lp:
    mov     eax, dword ptr [r8 + rcx*4]
    mov     r10d, eax
    shr     r10d, 24
    cmp     r10d, 0FFh
    jne     gpk_fail
    cmp     eax, r9d
    je      @F
    inc     edx
@@: xor     r11d, eax
    imul    r11d, r11d, 01000193h
    inc     ecx
    cmp     ecx, 240 * 160
    jb      gpk_px_lp
    cmp     edx, 800
    jb      gpk_fail

    ; Ensure checksum differs from every earlier mode
    mov     ecx, dword ptr [rbp-20]
    lea     r10, [g_gpu_kat_sig]
    mov     dword ptr [r10 + rcx*4], r11d
    xor     edx, edx
gpk_uniq:
    cmp     edx, ecx
    jae     gpk_uniq_ok
    cmp     dword ptr [r10 + rdx*4], r11d
    je      gpk_fail
    inc     edx
    jmp     gpk_uniq
gpk_uniq_ok:
    inc     dword ptr [rbp-20]
    cmp     dword ptr [rbp-20], BACKDROP_FLAT
    jb      gpk_mode_lp

    ; Repeat call on last mode must execute ZERO new GPU dispatches
    mov     eax, dword ptr [g_gpu_dispatches]
    mov     dword ptr [rbp-24], eax
    mov     ecx, 240
    mov     edx, 160
    call    gpu_ensure_surface
    test    eax, eax
    jz      gpk_fail
    mov     eax, dword ptr [g_gpu_dispatches]
    cmp     eax, dword ptr [rbp-24]
    jne     gpk_fail

    ; Advancing g_gpu_time_ms must cycle pixel colors with ZERO new GPU dispatches
    mov     dword ptr [g_gpu_time_ms], 2500
    mov     ecx, 240
    mov     edx, 160
    call    gpu_ensure_surface
    test    eax, eax
    jz      gpk_fail
    mov     eax, dword ptr [g_gpu_dispatches]
    cmp     eax, dword ptr [rbp-24]
    jne     gpk_fail
    mov     r8, qword ptr [g_gpu_bits]
    mov     r11d, 811C9DC5h
    xor     ecx, ecx
gpk_cyc_lp:
    xor     r11d, dword ptr [r8 + rcx*4]
    imul    r11d, r11d, 01000193h
    inc     ecx
    cmp     ecx, 240 * 160
    jb      gpk_cyc_lp
    lea     r10, [g_gpu_kat_sig]
    cmp     dword ptr [r10 + (BACKDROP_FLAT - 1)*4], r11d
    je      gpk_fail
    mov     dword ptr [g_gpu_time_ms], 0

    ; Vault salt seed must trigger exactly +1 dispatch
    lea     r10, [g_gpu_kat_salt]
    xor     ecx, ecx
gpk_slt:
    mov     byte ptr [r10 + rcx], cl
    inc     ecx
    cmp     ecx, 32
    jb      gpk_slt
    lea     rcx, [g_gpu_kat_salt]
    call    gpu_set_vault_seed
    mov     ecx, 240
    mov     edx, 160
    call    gpu_ensure_surface
    test    eax, eax
    jz      gpk_fail
    mov     eax, dword ptr [rbp-24]
    inc     eax
    cmp     dword ptr [g_gpu_dispatches], eax
    jne     gpk_fail

    ; Flat mode (BACKDROP_FLAT = 8) cleanly bypasses GPU surface
    mov     dword ptr [g_backdrop_pref], BACKDROP_FLAT
    mov     ecx, 240
    mov     edx, 160
    call    gpu_ensure_surface
    test    eax, eax
    jnz     gpk_fail

    ; Restore defaults
    xor     ecx, ecx
    call    gpu_set_vault_seed
    mov     eax, dword ptr [rbp-28]
    mov     dword ptr [g_gpu_time_ms], eax
    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [g_backdrop_pref], eax

    cmp     dword ptr [g_gpu_backend], 1
    je      gpk_hw
    lea     rcx, [gpk_ok_warp]
    mov     edx, gpk_ok_warp_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
gpk_hw:
    lea     rcx, [gpk_ok_hw]
    mov     edx, gpk_ok_hw_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret

gpk_fail:
    xor     ecx, ecx
    call    gpu_set_vault_seed
    mov     eax, dword ptr [rbp-28]
    mov     dword ptr [g_gpu_time_ms], eax
    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [g_backdrop_pref], eax
    lea     rcx, [gpk_bad]
    mov     edx, gpk_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_gpukat endp
endif ; PROBE_IO

end
