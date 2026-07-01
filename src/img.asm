; =============================================================================
; img.asm - minimal GDI+ wrapper: decode encoded image bytes (PNG/JPEG/BMP) held
;   in memory and draw them scaled onto a DC.  Used by the GUI to show attachment
;   thumbnails and the full-size viewer.  Also encodes a clipboard DIB to PNG so
;   pasted screenshots can be stored.
;
; An image handle is a 16-byte heap block { GpImage* image, IStream* stream }.
; The backing IStream (a private copy of the bytes) is kept alive for the image's
; lifetime and released in img_free.
; =============================================================================

include macros.inc

extern mem_alloc:proc
extern mem_free:proc

extern GdiplusStartup:proc
extern GdiplusShutdown:proc
extern GdipLoadImageFromStream:proc
extern GdipDisposeImage:proc
extern GdipGetImageWidth:proc
extern GdipGetImageHeight:proc
extern GdipCreateFromHDC:proc
extern GdipDeleteGraphics:proc
extern GdipDrawImageRectI:proc
extern GdipSetInterpolationMode:proc
extern GdipCreateBitmapFromHBITMAP:proc
extern GdipSaveImageToStream:proc
extern GdipGetImageEncodersSize:proc
extern GdipGetImageEncoders:proc
extern SHCreateMemStream:proc
extern CreateStreamOnHGlobal:proc
extern GetHGlobalFromStream:proc
extern GlobalLock:proc
extern GlobalUnlock:proc
extern GlobalSize:proc

INTERP_HQ           equ 7            ; InterpolationModeHighQualityBicubic

.data?
align 8
g_gdip_token dq ?                    ; GdiplusStartup token (0 = not started)
g_png_clsid  db 16 dup (?)           ; cached PNG encoder CLSID
g_png_have   dd ?
g_enc_buf    db 4096 dup (?)         ; GetImageEncoders scratch

.data
align 8
; GdiplusStartupInput { UINT32 GdiplusVersion; ptr DebugEventCallback;
;                       BOOL SuppressBackgroundThread; BOOL SuppressExternalCodecs }
g_gdip_in    dd 1
             dd 0
             dq 0
             dd 0
             dd 0
; "image/png" wide, for encoder CLSID lookup
w_png        dw 'i','m','a','g','e','/','p','n','g',0

.code

; img_startup() -> eax = 1 ok / 0 fail.  Idempotent GDI+ init.
public img_startup
img_startup proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_gdip_token], 0
    jne     is_ok
    WINCALL GdiplusStartup, addr g_gdip_token, addr g_gdip_in, 0
    test    eax, eax
    jnz     is_fail                          ; nonzero Status = error
    cmp     qword ptr [g_gdip_token], 0
    je      is_fail
is_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
is_fail:
    mov     qword ptr [g_gdip_token], 0
    xor     eax, eax
    FRAME_EPILOG
    ret
img_startup endp

; img_load(rcx = encoded bytes, rdx = len) -> rax = image handle (or 0).
public img_load
img_load proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=bytes [rbp-32]=len [rbp-40]=stream [rbp-48]=image [rbp-56]=handle
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-48], 0
    call    img_startup
    test    eax, eax
    jz      il_fail
    ; stream = SHCreateMemStream(bytes, len)  (makes its own copy)
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    call    SHCreateMemStream
    test    rax, rax
    jz      il_fail
    mov     qword ptr [rbp-40], rax
    ; GdipLoadImageFromStream(stream, &image)
    WINCALL GdipLoadImageFromStream, qword ptr [rbp-40], addr rbp-48
    test    eax, eax
    jnz     il_relstream
    cmp     qword ptr [rbp-48], 0
    je      il_relstream
    ; handle = { image, stream }
    mov     rcx, 16
    call    mem_alloc
    test    rax, rax
    jz      il_dispose
    mov     qword ptr [rbp-56], rax
    mov     r10, qword ptr [rbp-48]
    mov     qword ptr [rax], r10
    mov     r10, qword ptr [rbp-40]
    mov     qword ptr [rax+8], r10
    mov     rax, qword ptr [rbp-56]
    FRAME_EPILOG
    ret
il_dispose:
    WINCALL GdipDisposeImage, qword ptr [rbp-48]
il_relstream:
    mov     rcx, qword ptr [rbp-40]
    call    com_release
il_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
img_load endp

; img_free(rcx = handle) - dispose the image, release the stream, free the block.
public img_free
img_free proc frame
    FRAME_PROLOG 48
    test    rcx, rcx
    jz      if_done
    mov     qword ptr [rbp-24], rcx
    mov     rax, qword ptr [rcx]
    test    rax, rax
    jz      if_stream
    WINCALL GdipDisposeImage, rax
if_stream:
    mov     r10, qword ptr [rbp-24]
    mov     rcx, qword ptr [r10+8]
    test    rcx, rcx
    jz      if_freeblk
    call    com_release
if_freeblk:
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, 16
    call    mem_free
if_done:
    FRAME_EPILOG
    ret
img_free endp

; img_dims(rcx = handle, rdx = *w, r8 = *h) - fill pixel width/height (0 on fail).
public img_dims
img_dims proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     r10, rdx
    mov     dword ptr [r10], 0
    mov     r10, r8
    mov     dword ptr [r10], 0
    test    rcx, rcx
    jz      id_done
    mov     rax, qword ptr [rcx]                ; image
    WINCALL GdipGetImageWidth, rax, qword ptr [rbp-32]
    mov     rax, qword ptr [rbp-24]
    mov     rax, qword ptr [rax]
    WINCALL GdipGetImageHeight, rax, qword ptr [rbp-40]
id_done:
    FRAME_EPILOG
    ret
img_dims endp

; img_draw(rcx=handle, rdx=hdc, r8d=x, r9d=y, [rbp+48]=w, [rbp+56]=h) - draw the
;   image scaled into the pixel rect (x,y,w,h) on hdc.
public img_draw
img_draw proc frame
    FRAME_PROLOG 112                            ; 6-arg GdipDrawImageRectI needs room
    mov     qword ptr [rbp-24], rcx            ; handle
    mov     qword ptr [rbp-32], rdx            ; hdc
    mov     dword ptr [rbp-40], r8d            ; x
    mov     dword ptr [rbp-48], r9d            ; y
    test    rcx, rcx
    jz      idr_done
    WINCALL GdipCreateFromHDC, qword ptr [rbp-32], addr rbp-56    ; graphics @ [rbp-56]
    test    eax, eax
    jnz     idr_done
    WINCALL GdipSetInterpolationMode, qword ptr [rbp-56], INTERP_HQ
    mov     r10, qword ptr [rbp-24]
    mov     r10, qword ptr [r10]              ; image
    WINCALL GdipDrawImageRectI, qword ptr [rbp-56], r10, dword ptr [rbp-40], \
            dword ptr [rbp-48], dword ptr [rbp+48], dword ptr [rbp+56]
    WINCALL GdipDeleteGraphics, qword ptr [rbp-56]
idr_done:
    FRAME_EPILOG
    ret
img_draw endp

; com_release(rcx = IUnknown*) - call ->Release() through the vtable.  Leaf-ish.
com_release proc frame
    FRAME_PROLOG 32
    test    rcx, rcx
    jz      cr_done
    mov     rax, qword ptr [rcx]              ; vtable
    mov     rax, qword ptr [rax+16]           ; Release (index 2)
    sub     rsp, 32
    call    rax
    add     rsp, 32
cr_done:
    FRAME_EPILOG
    ret
com_release endp

; -----------------------------------------------------------------------------
; png_clsid() -> eax = 1 ok (g_png_clsid filled) / 0.  Finds the PNG encoder CLSID
;   via GdipGetImageEncoders and caches it.
; -----------------------------------------------------------------------------
png_clsid proc frame
    FRAME_PROLOG 64
    cmp     dword ptr [g_png_have], 0
    jne     pc_ok
    ; GdipGetImageEncodersSize(&num, &size)
    WINCALL GdipGetImageEncodersSize, addr rbp-24, addr rbp-32
    mov     eax, dword ptr [rbp-32]           ; size
    test    eax, eax
    jz      pc_fail
    cmp     eax, 4096
    ja      pc_fail
    ; GdipGetImageEncoders(num, size, buf)
    WINCALL GdipGetImageEncoders, dword ptr [rbp-24], dword ptr [rbp-32], addr g_enc_buf
    test    eax, eax
    jnz     pc_fail
    ; walk ImageCodecInfo[num]; match MimeType (wide) == "image/png"
    ; ImageCodecInfo layout (x64): CLSID(16) FormatID(16) CodecName(ptr@32)
    ;   DllName(ptr@40) FormatDescription(ptr@48) FilenameExtension(ptr@56)
    ;   MimeType(ptr@64) Flags(4@72) Version(4@76) SigCount(4@80) SigSize(4@84)
    ;   SigPattern(ptr@88) SigMask(ptr@96)  => stride 104
    mov     ecx, dword ptr [rbp-24]           ; num
    lea     r10, [g_enc_buf]
pc_loop:
    test    ecx, ecx
    jz      pc_fail
    mov     r11, qword ptr [r10+64]           ; MimeType wide ptr
    test    r11, r11
    jz      pc_next
    lea     rdx, [w_png]
    ; wide compare r11 vs w_png
    xor     r8d, r8d
pc_cmp:
    mov     ax, word ptr [r11+r8*2]
    cmp     ax, word ptr [rdx+r8*2]
    jne     pc_next
    test    ax, ax
    jz      pc_match
    inc     r8d
    jmp     pc_cmp
pc_match:
    ; copy 16-byte CLSID from [r10]
    lea     r8, [g_png_clsid]
    xor     r9d, r9d
pc_ccp:
    mov     al, byte ptr [r10+r9]
    mov     byte ptr [r8+r9], al
    inc     r9d
    cmp     r9d, 16
    jb      pc_ccp
    mov     dword ptr [g_png_have], 1
pc_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
pc_next:
    add     r10, 104
    dec     ecx
    jmp     pc_loop
pc_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
png_clsid endp

; img_encode_hbitmap(rcx = HBITMAP, rdx = *outlen) -> rax = heap PNG bytes (or 0).
;   Wraps a GDI bitmap as a GpBitmap, saves it to a growable IStream as PNG, then
;   copies the stream's HGLOBAL out to a plain heap buffer (caller mem_free's it).
public img_encode_hbitmap
img_encode_hbitmap proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=hbitmap [rbp-32]=outlen [rbp-40]=bitmap [rbp-48]=stream
    ; [rbp-56]=hglob [rbp-64]=locked [rbp-72]=size [rbp-80]=outbuf
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], 0
    mov     qword ptr [rbp-48], 0
    call    img_startup
    test    eax, eax
    jz      ie_fail
    call    png_clsid
    test    eax, eax
    jz      ie_fail
    ; GdipCreateBitmapFromHBITMAP(hbmp, NULL, &bitmap)
    WINCALL GdipCreateBitmapFromHBITMAP, qword ptr [rbp-24], 0, addr rbp-40
    test    eax, eax
    jnz     ie_fail
    ; CreateStreamOnHGlobal(NULL, TRUE, &stream)
    WINCALL CreateStreamOnHGlobal, 0, 1, addr rbp-48
    test    eax, eax
    jnz     ie_dispose
    ; GdipSaveImageToStream(bitmap, stream, &clsid, NULL)
    WINCALL GdipSaveImageToStream, qword ptr [rbp-40], qword ptr [rbp-48], \
            addr g_png_clsid, 0
    test    eax, eax
    jnz     ie_relstream
    ; GetHGlobalFromStream(stream, &hglob)
    WINCALL GetHGlobalFromStream, qword ptr [rbp-48], addr rbp-56
    test    eax, eax
    jnz     ie_relstream
    WINCALL GlobalSize, qword ptr [rbp-56]
    mov     qword ptr [rbp-72], rax
    test    rax, rax
    jz      ie_relstream
    WINCALL GlobalLock, qword ptr [rbp-56]
    test    rax, rax
    jz      ie_relstream
    mov     qword ptr [rbp-64], rax
    ; outbuf = mem_alloc(size); copy
    mov     rcx, qword ptr [rbp-72]
    call    mem_alloc
    test    rax, rax
    jz      ie_unlock
    mov     qword ptr [rbp-80], rax
    mov     rcx, rax                          ; dst
    mov     rdx, qword ptr [rbp-64]           ; src
    mov     r8, qword ptr [rbp-72]            ; len
    call    ie_cpy
    ; *outlen = size
    mov     r10, qword ptr [rbp-32]
    mov     rax, qword ptr [rbp-72]
    mov     qword ptr [r10], rax
    WINCALL GlobalUnlock, qword ptr [rbp-56]
    mov     rcx, qword ptr [rbp-48]
    call    com_release
    WINCALL GdipDisposeImage, qword ptr [rbp-40]
    mov     rax, qword ptr [rbp-80]
    FRAME_EPILOG
    ret
ie_unlock:
    WINCALL GlobalUnlock, qword ptr [rbp-56]
ie_relstream:
    mov     rcx, qword ptr [rbp-48]
    call    com_release
ie_dispose:
    WINCALL GdipDisposeImage, qword ptr [rbp-40]
ie_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
img_encode_hbitmap endp

; ie_cpy(rcx=dst, rdx=src, r8=len) leaf byte copy
ie_cpy proc
    xor     r9, r9
iec_l:
    cmp     r9, r8
    jae     iec_d
    mov     al, byte ptr [rdx+r9]
    mov     byte ptr [rcx+r9], al
    inc     r9
    jmp     iec_l
iec_d:
    ret
ie_cpy endp

end
