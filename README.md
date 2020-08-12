# Android Skia Image Fuzzing Harness

SkCodecFuzzer is a small utility for testing the security and reliability of C/C++ image codecs supported by the [Skia](https://skia.org/) graphics library. In Android, these parsers are reachable through standard interfaces such as [`BitmapFactory`](https://developer.android.com/reference/android/graphics/BitmapFactory) and [`BitmapRegionDecoder`](https://developer.android.com/reference/android/graphics/BitmapRegionDecoder) and execute in the context of local apps (not a sandboxed media server), which exposes them to remote attacks via MMS, chat apps, emails etc. While the decoders available in Android by default (bmp, png, jpeg, gif, ...) are all open-source and already subject to extensive fuzzing, there may exist additional lesser-known, proprietary codecs added by device manufacturers. Such codecs aren't put under the same scrutiny due to their closed-source nature, and they may go unaudited, non-fuzzed or even completely unnoticed for many years. A notable example is the Qmage format (`.qmg` file extension), which was introduced in Skia on Samsung Android phones in late 2014, but was only recognized as an attack surface at the end of 2019. It has been used as the container for image resources in built-in Samsung APKs and themes in some (but not all) firmwares.

The loader in this repository was used by Google Project Zero to run Qmage fuzzing at scale in January 2020, resulting in the uncovering of 5218 unique crashes, including hundreds of memory corruption issues (buffer overflows, use-after-free's etc.). They were subsequently reported to Samsung on January 28 as [issue #2002](https://bugs.chromium.org/p/project-zero/issues/detail?id=2002) in the PZ bug tracker, and fixed by the vendor in May 2020. For additional context and more information about `.qmg` files, we recommend to refer to that tracker entry as it aims to explain our effort in great detail. The purpose of this harness is to link to Android's precompiled ARM(64) Skia libraries (`libhwui.so` or `libskia.so` on older versions) and use its `SkCodec` class to load an input file, in the same way that `BitmapFactory::doDecode` [decodes](https://android.googlesource.com/platform/frameworks/base/+/master/core/jni/android/graphics/BitmapFactory.cpp#184) images on real Android devices. It can run on both physical phones with ARM CPUs and in an emulated qemu-aarch64 environment on any host CPU of choice, enabling effective parallelized fuzzing.

One of the Qmage vulnerabilities was used to demonstrate successful zero-click exploitation of a Samsung Galaxy Note 10+ phone running Android 10 via MMS: [see video](https://www.youtube.com/watch?v=nke8Z3G4jnc). The exploit source code is available for reference [here](mms_exploit).

## Features

The primary functionality of the tool is to load an input image with Skia, print out some basic information (dimensions, bpp), and optionally save the raw RGBA pixels of the decoded image to an output file. However, the loader also offers some features designed specifically to aid in the fuzzing and vulnerability research process:

1. The default libc allocator is switched to AFL's [libdislocator](https://github.com/mirrorer/afl/tree/master/libdislocator). Libdislocator is a special simplified allocator which places each new allocation directly before the end of a memory page (similarly to PageHeap on Windows). This facilitates more precise detection of out-of-bounds memory accesses, and makes crash deduplication based on stack traces more reliable. It is worth noting the default allocator and libdislocator have semantic differences (memory consumption, heap usage limits, address alignment and allocation poisoning). While they don't matter for fuzzing itself, they may affect the reproducibility of crashes on Android devices. For more information on the subject, see section "3.3. Libdislocator vs libc malloc" in the original [bug report](https://bugs.chromium.org/p/project-zero/issues/detail?id=2002).
2. The program registers its own custom signal handler, which prints out a verbose AddressSanitizer-like report when a crash is encountered. The report includes the type of the exception, a symbolized call stack, disassembly of the relevant code and CPU register values.
3. There is an option to log all heap operations (`malloc`, `realloc`, `free`) to stderr, which may prove helpful in understanding the memory allocation patterns used by the codec, figuring out the internal heap state at the time of the crash, as well as determining which chunk is overread or overwritten by a specific sample.

## Building

In order to build the harness on a x86-64 Linux host, you will need:
* [Android NDK](https://developer.android.com/ndk/downloads), needed for the cross-compiler. I used version r20b, but r21b is already available at the time of this writing.
* [Skia source code](https://skia.org/user/download), needed for the headers (the linking is done against `libhwui.so`)
* [Libbacktrace source code](https://android.googlesource.com/platform/system/core/+/master/libbacktrace/), needed for the headers (the linking is done against `libbacktrace.so`)
* [Capstone](http://www.capstone-engine.org/), to disassemble the crashing instructions
* The `aarch64-linux-gnu-g++` compiler, to build Capstone for aarch64
* The complete `/system/lib64` directory and the `/system/bin/linker64` file from the tested Android system

Let's put all of the dependencies into a common `deps` directory (e.g. `/home/j00ru/SkCodecFuzzer/deps`), and start with cross-compiling Capstone:

```
j00ru@j00ru:~/SkCodecFuzzer/deps/capstone-4.0.1$ CAPSTONE_BUILD_CORE_ONLY=yes ./make.sh cross-android64
  CC      utils.o
  CC      cs.o
  CC      SStream.o
...
  CC      arch/EVM/EVMModule.o
  CC      MCInst.o
  GEN     capstone.pc
  LINK    libcapstone.so.4
  AR      libcapstone.a
aarch64-linux-gnu-ar: creating ./libcapstone.a
j00ru@j00ru:~/SkCodecFuzzer/deps/capstone-4.0.1$
```

With this, we are ready to compile the harness. Let's update the five paths at the top of `Makefile` to point to the corresponding dependency paths, and run `make`:

```
j00ru@j00ru:~/SkCodecFuzzer/source$ make
/home/j00ru/SkCodecFuzzer/deps/ndk/android-ndk-r20b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++ -c -o loader.o loader.cc -D_LIBCPP_ABI_NAMESPACE=__1 -I/home/j00ru/SkCodecFuzzer/deps/skia/include/core -I/home/j00ru/SkCodecFuzzer/deps/skia/include/codec -I/home/j00ru/SkCodecFuzzer/deps/skia/include/config -I/home/j00ru/SkCodecFuzzer/deps/skia/include/config/android -I/home/j00ru/SkCodecFuzzer/deps/capstone-4.0.1/include -I/home/j00ru/SkCodecFuzzer/deps/libbacktrace/include
/home/j00ru/SkCodecFuzzer/deps/ndk/android-ndk-r20b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++ -c -o common.o common.cc -D_LIBCPP_ABI_NAMESPACE=__1 -I/home/j00ru/SkCodecFuzzer/deps/skia/include/core -I/home/j00ru/SkCodecFuzzer/deps/skia/include/codec -I/home/j00ru/SkCodecFuzzer/deps/skia/include/config -I/home/j00ru/SkCodecFuzzer/deps/skia/include/config/android -I/home/j00ru/SkCodecFuzzer/deps/capstone-4.0.1/include -I/home/j00ru/SkCodecFuzzer/deps/libbacktrace/include
/home/j00ru/SkCodecFuzzer/deps/ndk/android-ndk-r20b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++ -c -o tokenizer.o tokenizer.cc -D_LIBCPP_ABI_NAMESPACE=__1 -I/home/j00ru/SkCodecFuzzer/deps/skia/include/core -I/home/j00ru/SkCodecFuzzer/deps/skia/include/codec -I/home/j00ru/SkCodecFuzzer/deps/skia/include/config -I/home/j00ru/SkCodecFuzzer/deps/skia/include/config/android -I/home/j00ru/SkCodecFuzzer/deps/capstone-4.0.1/include -I/home/j00ru/SkCodecFuzzer/deps/libbacktrace/include
/home/j00ru/SkCodecFuzzer/deps/ndk/android-ndk-r20b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang -c -o libdislocator.o third_party/libdislocator/libdislocator.so.c
/home/j00ru/SkCodecFuzzer/deps/ndk/android-ndk-r20b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++ -o loader loader.o common.o tokenizer.o libdislocator.o -L/home/j00ru/SkCodecFuzzer/deps/capstone-4.0.1 -lcapstone -L/home/j00ru/SkCodecFuzzer/deps/android/system/lib64 -lhwui -ldl -lbacktrace -landroidicu -Wl,-rpath -Wl,/home/j00ru/SkCodecFuzzer/deps/android/system/lib64 -Wl,--dynamic-linker=/home/j00ru/SkCodecFuzzer/deps/android/system/bin/linker64
j00ru@j00ru:~/SkCodecFuzzer/source$
```

We should now find the following `loader` file in the current directory:

```
j00ru@j00ru:~/SkCodecFuzzer/source$ file loader
loader: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /home/j00ru/SkCodecFuzzer/deps/android/system/bin/linker64, with debug_info, not stripped
j00ru@j00ru:~/SkCodecFuzzer/source$
```

To run it locally, make sure you have `qemu-aarch64` installed, update the two paths at the top of the `run.sh` script accordingly, and start it:

```
j00ru@j00ru:~/SkCodecFuzzer/source$ ./run.sh
Error: missing required --input (-i) option

Usage: [LIBC_HOOKS_ENABLE=1] ./loader [OPTION]...

Required arguments:
-i, --input <image path>   specify input file path for decoding

Optional arguments:
-o, --output <file path>   save raw decoded RGBA image colors to specified output file
-l, --log_malloc           log heap allocator activity to stderr (LIBC_HOOKS_ENABLE=1 needed)
-d, --default_malloc       use the default system heap allocator
-h, --help                 display this help and exit
j00ru@j00ru:~/SkCodecFuzzer/source$
```

The above process works fine with libraries from Android up to version 9. While using files pulled from Android 10, you may encounter the following error:

```
==31162==Sanitizer CHECK failed: /usr/local/google/buildbot/src/android/llvm-toolchain/toolchain/compiler-rt/lib/sanitizer_common/sanitizer_posix.cc:371 ((internal_prctl(0x53564d41, 0, addr, size, (uptr)name) == 0)) != (0) (0, 0)
libc: Fatal signal 6 (SIGABRT), code -1 (SI_QUEUE) in tid 31162 (qemu-aarch64), pid 31162 (qemu-aarch64)
libc: failed to spawn debuggerd dispatch thread: Invalid argument
```

The problem is caused by a new version of `/lib64/libclang_rt.ubsan_standalone-aarch64-android.so`, which fails to run outside of Android, expecting the `prctl` syscall to always succeed. To fix the issue, I simply swapped this specific file out for its older build from Android 9.

To compile the loader for an actual Android device, just remove the `-Wl,--dynamic-linker=$(ANDROID_PATH)/bin/linker64` part from `LDFLAGS` in `Makefile`, and run `make clean && make` again. The harness can be then run natively on a device with USB debugging enabled:

```
j00ru@j00ru:~/SkCodecFuzzer/source$ adb push loader /data/local/tmp
loader: 1 file pushed, 0 skipped. 147.0 MB/s (4380512 bytes in 0.028s)
j00ru@j00ru:~/SkCodecFuzzer/source$ adb shell /data/local/tmp/loader
Error: missing required --input (-i) option

Usage: [LIBC_HOOKS_ENABLE=1] /data/local/tmp/loader [OPTION]...

[...]
j00ru@j00ru:~/SkCodecFuzzer/source$
```

## Usage

The standard way to run the harness is with the `LIBC_HOOKS_ENABLE=1` environment variable (to enable libdislocator), the `-i` flag to specify the input file, and optionally the `-o` flag to verify that the bitmap is decoded correctly. Images in any format supported by the given build of Skia can be passed as input. For example, let's test a random valid JPEG file:

```
j00ru@j00ru:~/SkCodecFuzzer/source$ LIBC_HOOKS_ENABLE=1 ./run.sh -i test.jpg -o test.raw
[+] Detected image characteristics:
[+] Dimensions:      72 x 48
[+] Color type:      4
[+] Alpha type:      1
[+] Bytes per pixel: 4
[+] codec->GetAndroidPixels() completed successfully
[+] Successfully wrote 13824 bytes to test.raw
j00ru@j00ru:~/SkCodecFuzzer/source$
```

As an alternative to `LIBC_HOOKS_ENABLE=1`, the `-d` flag can be passed to force the usage of the default system allocator, which results in a more Android-like runtime environment, but may conceal a subset of bugs. I have used this option rarely in my research, but it may come in handy in certain situations.

```
j00ru@j00ru:~/SkCodecFuzzer/source$ ./run.sh -d -i test.jpg -o test.raw
[output same as above]
```

Now, let's move on to a more interesting scenario - a corrupted Qmage input file:

```
j00ru@j00ru:~/SkCodecFuzzer/source$ LIBC_HOOKS_ENABLE=1 ./run.sh -i signal_sigsegv_4003f4fca8_6549_e9bf68c239eb55c8654336e2f9f25111.qmg 
[+] Detected image characteristics:
[+] Dimensions:      318 x 318
[+] Color type:      4
[+] Alpha type:      3
[+] Bytes per pixel: 4
ASAN:SIGSEGV
=================================================================
==233650==ERROR: AddressSanitizer: SEGV on unknown address 0x4089666008 (pc 0x4002f0aca8 sp 0x4000d09b20 bp 0x4000d09b20 T0)
    #0 0x002c4ca8 in libhwui.so (QuramQumageDecoder32bit24bit+0x2738)
    #1 0x0029cd70 in libhwui.so (__QM_WCodec_decode+0x228)
    #2 0x0029c9b4 in libhwui.so (Qmage_WDecodeFrame_Low_Rev14474_20150224+0x144)
    #3 0x0029ae7c in libhwui.so (QuramQmageDecodeFrame_Rev14474_20150224+0xa8)
    #4 0x006e1ef0 in libhwui.so (SkQmgCodec::onGetPixels(SkImageInfo const&, void*, unsigned long, SkCodec::Options const&, int*)+0x450)
    #5 0x004daf00 in libhwui.so (SkCodec::getPixels(SkImageInfo const&, void*, unsigned long, SkCodec::Options const*)+0x358)
    #6 0x006e278c in libhwui.so (SkQmgAdapterCodec::onGetAndroidPixels(SkImageInfo const&, void*, unsigned long, SkAndroidCodec::AndroidOptions const&)+0xac)
    #7 0x004da498 in libhwui.so (SkAndroidCodec::getAndroidPixels(SkImageInfo const&, void*, unsigned long, SkAndroidCodec::AndroidOptions const*)+0x2b0)
    #8 0x0004a8e0 in loader (ProcessImage()+0x55c)
    #9 0x0004aba0 in loader (main+0x6c)
    #10 0x0007e858 in libc.so (__libc_init+0x70)

==233650==DISASSEMBLY
    0x4002f0aca8:    str      w13, [x5]
    0x4002f0acac:    add      x12, x12, #1
    0x4002f0acb0:    cmp      x12, x25
    0x4002f0acb4:    b.lt     #0x4002f0aa70
    0x4002f0acb8:    b        #0x4002f0b080
    0x4002f0acbc:    cmp      w9, #0xf
    0x4002f0acc0:    b.gt     #0x4002f0acf4
    0x4002f0acc4:    ldp      w13, w23, [sp, #0xdc]
    0x4002f0acc8:    ldr      x17, [sp, #0xc0]
    0x4002f0accc:    subs     w13, w13, #1

==233650==CONTEXT
   x0=0000000000000023  x1=0000004089785f64  x2=0000004000d09d00  x3=0000004000d09c80
   x4=0000000000000018  x5=0000004089666008  x6=0000004002d2483c  x7=0000000000000001
   x8=000000000a190430  x9=0000000000000011 x10=00000000ffffffff x11=000000000000001c
  x12=0000000000000001 x13=00000000000000ff x14=000000408966dfb0 x15=00000000000018b0
  x16=0000000000000000 x17=0000004089785f60 x18=00000040018b2000 x19=0000004089669968
  x20=0000000000000619 x21=0000000000000018 x22=00000000ffffffff x23=0000000000000001
  x24=0000000000000001 x25=0000000000000002 x26=0000000000000002 x27=0000004089789fb0
  x28=0000000000000002  FP=0000004000d0a000  LR=00000040896033f0  SP=0000004000d09b20

==233650==ABORTING
j00ru@j00ru:~/SkCodecFuzzer/source$
```

In the above report, we receive detailed information about the crash - the exact location in code, the full stack trace, code disassembly and CPU context. Based on it, we can determine that the exception was caused by an attempt to write (`str` instruction) a 32-bit value `0x000000ff` (in register `w13`) to an invalid address `0x4089666008` (register `x5`). We can expect that this manifests a heap-based buffer overflow. To confirm this, we can use the `-l` flag to log all heap activity:

```
j00ru@j00ru:~/SkCodecFuzzer/source$ LIBC_HOOKS_ENABLE=1 ./run.sh -l -i signal_sigsegv_4003f4fca8_6549_e9bf68c239eb55c8654336e2f9f25111.qmg
[...]
[+] Detected image characteristics:
[+] Dimensions:      318 x 318
[+] Color type:      4
[+] Alpha type:      3
[+] Bytes per pixel: 4
free(0x0000000000)                                  --> [__libc_init + 0x70] --> [main + 0x6c] --> [ProcessImage + 0x364] --> [printf + 0xa8] --> [__vfprintf + 0x27d4]
malloc(    404496) = {0x408c10a3f0 .. 0x408c16d000} --> [__libc_init + 0x70] --> [main + 0x6c] --> [ProcessImage + 0x46c] --> [SkBitmap::tryAllocPixels + 0x54] --> [SkBitmap::HeapAllocator::allocPixelRef + 0x4c] --> [SkMallocPixelRef::MakeAllocate + 0x108]
malloc(       104) = {0x408c16ef98 .. 0x408c16f000} --> [__libc_init + 0x70] --> [main + 0x6c] --> [ProcessImage + 0x46c] --> [SkBitmap::tryAllocPixels + 0x54] --> [SkBitmap::HeapAllocator::allocPixelRef + 0x4c] --> [SkMallocPixelRef::MakeAllocate + 0x118] --> [operator new + 0x24]
[...]
ASAN:SIGSEGV
=================================================================
==237514==ERROR: AddressSanitizer: SEGV on unknown address 0x408c16d008 (pc 0x4003b56ca8 sp 0x4000d09b10 bp 0x4000d09b10 T0)
[...]
```

As it turns out, the address of the invalid write is eight bytes outside of a 404496 byte heap allocation; in fact a very early allocation requested by the the harness through `SkBitmap::tryAllocPixels`, which is the pixel *backing store* for the bitmap object. This gives us a good basic understanding of the vulnerability and its potential exploitability.

It is also worth noting that the `exitcode` and `log_path` options in the `ASAN_OPTIONS` environment variable are supported, to make the loader appear even more ASAN-like for fuzzers which expect to work with such targets.

### Note on running on Android devices

For all intents and purposes, the harness should behave identically\* when run in qemu and on a real device. The asterisk here is for one explicit difference - libdislocator memory alignment. The qemu emulator doesn't seem to enforce strict memory alignment, so e.g. if an allocation of size 7 is requested, the hooked `malloc` will return an address ending with `0xff9`, which will work just fine with the rest of the code. On the other hand, if an instruction performing an atomic access (e.g. `LDXR`) is executed against such an address on a Samsung phone, an unwanted `SIGBUS` exception will be thrown. In order to mitigate this, the loader automatically detects if it's running on Android, and if that's the case, all allocations are 8-byte aligned. This difference in behavior is not significant, but may mask some small out-of-bounds accesses (1-7 bytes outside the heap chunk) that would normally be detected under qemu.

## Sample Qmage files

As noted earlier, Qmage files are located in the resources of built-in applications in some Samsung firmwares, especially older ones from the 2015-2017 time period. For example, the following `.qmg` format versions were spotted in the firmware for Samsung Galaxy Note 4:
* QM v1 in Android 4.4.4 build from October 2014
* QG 1.0 in Android 5.1.1 build from October 2015
* QG 1.1 in Android 6.0.1 build from May 2016

I haven't identified any publicly available, genuine QG 2.0 files at this time. However, many such samples (QG 2.0 and all other formats) synthesized with the help of code coverage feedback can be found in the "crashes" archive attached to the [issue #2002](https://bugs.chromium.org/p/project-zero/issues/detail?id=2002) bug tracker entry. Please note that a number of test cases in that bundle contain a `QG\x01\x02` header, which would indicate a non-existent QG 1.2 format. Due to an implementation quirk in the Qmage codec, such files are functionally equivalent to QG 2.0, but were easier to synthesize for the fuzzer due to a bypassed 1-byte checksum verification. Behold the power of coverage-guided fuzzing! :-)

## Disclaimer

This is not an officially supported Google product.

