/////////////////////////////////////////////////////////////////////////
//
// Author: Mateusz Jurczyk (mjurczyk@google.com)
//
// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#define SK_BUILD_FOR_ANDROID

#include <cxxabi.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <getopt.h>
#include <setjmp.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <unwind.h>

#include <cstdio>
#include <string>

#include "SkAndroidCodec.h"
#include "SkBitmap.h"
#include "SkCodec.h"
#include "SkString.h"

#include "common.h"
#include "tokenizer.h"

#include <capstone/capstone.h>

#include <backtrace/Backtrace.h>
#include <backtrace/BacktraceMap.h>

struct StackUnwindContext {
  // Indicates if the stack unwinding was triggered by the debug malloc
  // instrumentation (true), or an ASAN crash report (false).
  bool debug_malloc_unwind;

  // The BacktraceMap object used for the symbolization of call stack items.
  BacktraceMap *backtrace_map;

  // current_trace_id is used internally by the unwind callback and should be
  // initially set to 0. first_trace_id is the index of the first item in the
  // stack trace that should be logged (or in other words, the number of initial
  // items to discard).
  int current_trace_id;
  int first_trace_id;

  // A list of symbolized code addresses, only used if debug_malloc_unwind =
  // true.
  std::deque<std::string> output_stack_trace;

  // The output fd where ASAN report is written to, only used if
  // debug_malloc_unwind = false.
  int output_log_fd;
};

namespace config {
  // Stores the path to the input image to decode. Initialized through the
  // --input (-i) command line argument.
  std::string input_file;

  // Stores the optional path to an output raw image. Initialized through the
  // --output (-o) command line argument.
  std::string output_file;

  // Indicates if every malloc/realloc/free call should be logged to stderr with
  // the full stack trace of the caller. Initialized through the --log_malloc
  // (-l) command line argument. It is only effective if malloc hooks are
  // enabled in libc with the LIBC_HOOKS_ENABLE=1 environment variable.
  //
  // The flag may be useful for learning about the heap usage of a specific
  // image codec and the resulting memory layout during exploit development.
  bool log_malloc;

  // An option to force the usage of the default system allocator. It is either
  // required to set LIBC_HOOKS_ENABLE=1 and use libdislocator, or set this
  // flag. It is initialized through the --default_malloc (-d) command line
  // argument.
  bool force_system_malloc;

  // Indicates if the LIBC_HOOKS_ENABLED environment variable is set to 1, which
  // enables our custom heap allocator (libdislocator) instead of the default
  // system one.
  bool libc_hooks_enabled;

  // Indicates if we're running on a physical Android device or in an emulated
  // qemu environment.
  bool android_host;

  // Stores the value of the exit code expected of the subprocess when an ASAN
  // crash occurs, configured through the exitcode switch in the ASAN_OPTIONS
  // environment variable:
  //
  // ASAN_OPTIONS=coverage=1,exitcode=11
  //
  // Default: 42
  int exitcode = 42;

  // Stores the path to a file which should contain an ASAN-like report if a
  // crash occurs. It is configured through the log_path switch in ASAN_OPTIONS:
  //
  // ASAN_OPTIONS=coverage=1,log_path=/path/to/file
  //
  // Default: ""
  std::string log_path;

}  // namespace config

namespace globals {
  // Indicates if the exception handler is currently performing stack unwinding.
  bool in_stack_unwinding;

  // Used for low-level exception handling during stack unwinding.
  jmp_buf jbuf;

  // Global backtrace map initialized once and used by the malloc
  // instrumentation.
  BacktraceMap *malloc_backtrace_map;
}  // namespace globals

/* Prototypes for our malloc hooks. */
extern "C" {

void* afl_malloc(size_t len);
void afl_free(void* ptr);
void* afl_realloc(void* ptr, size_t len);

}  // extern "C"

static void SymbolizeAndSaveAddress(
    BacktraceMap *backtrace_map, const void *address,
    std::deque<std::string> *output_stack_trace);
static ssize_t UnwindBacktrace(void *unwind_context);

static void *my_malloc_hook(size_t, const void *);
static void *my_realloc_hook(void *, size_t, const void *);
static void my_free_hook(void *, const void *);
static void *my_memalign_hook(size_t, size_t, const void *);

static void InitMallocHooks() {
  __malloc_hook = my_malloc_hook;
  __realloc_hook = my_realloc_hook;
  __free_hook = my_free_hook;
  __memalign_hook = my_memalign_hook;
}

static void DestroyMallocHooks() {
  __malloc_hook = NULL;
  __realloc_hook = NULL;
  __free_hook = NULL;
  __memalign_hook = NULL;
}

static void PrintMallocBacktrace(const void *caller) {
  if (globals::malloc_backtrace_map == NULL) {
    globals::malloc_backtrace_map = BacktraceMap::Create(getpid());

    if (!globals::malloc_backtrace_map->Build()) {
      delete globals::malloc_backtrace_map;
      globals::malloc_backtrace_map = NULL;
    }
  }

  StackUnwindContext unwind_ctx;

  // Save the first stack trace item as denoted by "caller", because it may not
  // be correctly unwound later on.
  SymbolizeAndSaveAddress(globals::malloc_backtrace_map, caller,
                          &unwind_ctx.output_stack_trace);

  // Unwind and symbolize the whole stack trace.
  unwind_ctx.debug_malloc_unwind = true;
  unwind_ctx.backtrace_map = globals::malloc_backtrace_map;
  unwind_ctx.current_trace_id = 0;
  unwind_ctx.first_trace_id = 4;
  UnwindBacktrace(&unwind_ctx);

  // Check if items #0 and #1 on the stack trace list are duplicates - if so,
  // UnwindBacktrace() unwound the function that was also added by the initial
  // call to SymbolizeAndSaveAddress(), so we can remove one redundant entry.
  if (unwind_ctx.output_stack_trace.size() >= 2 &&
      unwind_ctx.output_stack_trace[0] == unwind_ctx.output_stack_trace[1]) {
    unwind_ctx.output_stack_trace.pop_front();
  }

  int getPixelsIndex = -1;
  for (int i = 0; i < unwind_ctx.output_stack_trace.size(); i++) {
    if (unwind_ctx.output_stack_trace[i].find("::onGetPixels") !=
        std::string::npos) {
      getPixelsIndex = i;
      break;
    }
  }

  if (getPixelsIndex != -1) {
    fprintf(stderr, " --> [...]");
    for (int i = getPixelsIndex - 1; i >= 0; i--) {
      fprintf(stderr, " --> [%s]", unwind_ctx.output_stack_trace[i].c_str());
    }
  } else {
    for (int i = unwind_ctx.output_stack_trace.size() - 1; i >= 0; i--) {
      fprintf(stderr, " --> [%s]", unwind_ctx.output_stack_trace[i].c_str());
    }
  }

  fprintf(stderr, "\n");
}

static void *my_malloc_hook(size_t size, const void *caller) {
  size_t aligned_size = size;
  if (config::android_host) {
    aligned_size = ((size + 7LL) & (~7LL));

    if (aligned_size < size) {
      aligned_size = size;
    }
  }

  void *ret = afl_malloc(aligned_size);

  if (config::log_malloc) {
    DestroyMallocHooks();

    fprintf(stderr, "malloc(%10zu) = {%p .. %p}",
            size, ret, (void *)((size_t)ret + aligned_size));
    PrintMallocBacktrace(caller);

    InitMallocHooks();
  }

  return ret;
}

static void *my_realloc_hook(void *ptr, size_t size, const void *caller) {
  size_t aligned_size = size;
  if (config::android_host) {
    aligned_size = ((size + 7LL) & (~7LL));

    if (aligned_size < size) {
      aligned_size = size;
    }
  }

  void *ret = afl_realloc(ptr, aligned_size);

  if (config::log_malloc) {
    DestroyMallocHooks();

    fprintf(stderr, "realloc(%p, %zu) = {%p .. %p}",
            ptr, size, ret, (void *)((size_t)ret + aligned_size));
    PrintMallocBacktrace(caller);

    InitMallocHooks();
  }

  return ret;
}

static void my_free_hook(void *ptr, const void *caller) {
  afl_free(ptr);

  if (config::log_malloc) {
    DestroyMallocHooks();

    fprintf(stderr, "free(0x%.10zx)                                 ",
            (size_t)ptr);
    PrintMallocBacktrace(caller);

    InitMallocHooks();
  }
}

static void *
my_memalign_hook(size_t alignment, size_t size, const void *caller) {
  size_t real_alignment = alignment;
  if (config::android_host) {
    real_alignment = std::max(real_alignment, static_cast<size_t>(8));
  }

  size_t aligned_size = ((size + (real_alignment - 1)) & ~(real_alignment - 1));

  if (aligned_size < size) {
    aligned_size = size;
  }

  void *ret = afl_malloc(aligned_size);

  if (config::log_malloc) {
    DestroyMallocHooks();

    fprintf(stderr, "memalign(%2zu, %4zu) = {%p .. %p}",
            alignment, size, ret, (void *)((size_t)ret + aligned_size));
    PrintMallocBacktrace(caller);

    InitMallocHooks();
  }

  return ret;
}

void SetSignalHandler(void (*handler)(int, siginfo_t *, void *)) {
  struct sigaction action;
  memset(&action, 0, sizeof(action));

  action.sa_flags = SA_SIGINFO | SA_NODEFER;
  action.sa_sigaction = handler;
  if (sigaction(SIGABRT, &action, NULL) == -1) {
    perror("sigabrt: sigaction");
    _exit(1);
  }
  if (sigaction(SIGFPE, &action, NULL) == -1) {
    perror("sigfpe: sigaction");
    _exit(1);
  }
  if (sigaction(SIGSEGV, &action, NULL) == -1) {
    perror("sigsegv: sigaction");
    _exit(1);
  }
  if (sigaction(SIGILL, &action, NULL) == -1) {
    perror("sigill: sigaction");
    _exit(1);
  }
  if (sigaction(SIGBUS, &action, NULL) == -1) {
    perror("sigbus: sigaction");
    _exit(1);
  }
}

static bool IsCodeAddressValid(const void *address) {
  Dl_info info;
  return (dladdr(address, &info) != 0);
}

static void SymbolizeAndSaveAddress(
    BacktraceMap *backtrace_map, const void *address,
    std::deque<std::string> *output_stack_trace) {
  char buffer[256];
  Dl_info dlinfo;

  if (backtrace_map != NULL && dladdr(address, &dlinfo) != 0) {
    const char *lib_name = strrchr(dlinfo.dli_fname, '/');
    if (lib_name != NULL) {
      lib_name++;
    } else {
      lib_name = dlinfo.dli_fname;
    }

    uint64_t image_offset = (uint64_t)address - (uint64_t)dlinfo.dli_fbase;
    uint64_t symbol_offset = 0;
    std::string symbol_name;

    symbol_name = backtrace_map->GetFunctionName((uint64_t)address,
                                                 &symbol_offset);

    if (!symbol_name.empty()) {
      char *demangled_name = abi::__cxa_demangle(symbol_name.c_str(),
                                                 /*output_buffer=*/NULL,
                                                 /*length=*/NULL,
                                                 /*status=*/NULL);
      if (demangled_name != NULL) {
        symbol_name = demangled_name;
        free(demangled_name);
      }

      size_t paren_pos = symbol_name.find_first_of('(');
      if (paren_pos != std::string::npos) {
        symbol_name.resize(paren_pos);
      }

      snprintf(buffer, sizeof(buffer),
               "%s + 0x%lx", symbol_name.c_str(), symbol_offset);
    } else {
      snprintf(buffer, sizeof(buffer),
               "%s + 0x%lx", lib_name, image_offset);
    }
  } else {
    snprintf(buffer, sizeof(buffer), "0x%.8zx in ??", (size_t)address);
  }

  output_stack_trace->push_back(std::string(buffer));
}

static void SymbolizeAndLogAddress(
    int output_log_fd, BacktraceMap *backtrace_map, int index,
    const void *address) {
  Dl_info dlinfo;

  if (backtrace_map != NULL && dladdr(address, &dlinfo) != 0) {
    const char *lib_name = strrchr(dlinfo.dli_fname, '/');
    if (lib_name != NULL) {
      lib_name++;
    } else {
      lib_name = dlinfo.dli_fname;
    }

    uint64_t image_offset = (uint64_t)address - (uint64_t)dlinfo.dli_fbase;
    uint64_t symbol_offset = 0;
    std::string symbol_name;

    symbol_name =
        backtrace_map->GetFunctionName((uint64_t)address, &symbol_offset);

    if (!symbol_name.empty()) {
      // Workaround for better crash deduplication. We are not interested in
      // crashes failing at different instructions inside memcpy() or memset()
      // to be reported as different bugs, as they're most likely the same issue
      // if the rest of the stack trace is the same. Therefore, for these
      // general-purpose standard functions, we output their base addresses in
      // the callstack instead of the specific crashing instruction address.
      if (symbol_name == "memset" || symbol_name == "memcpy" ||
          symbol_name == "__memcpy" || symbol_name == "memmove" ||
          symbol_name == "memcmp") {
        image_offset -= symbol_offset;
      }

      char *demangled_name = abi::__cxa_demangle(symbol_name.c_str(),
                                                 /*output_buffer=*/NULL,
                                                 /*length=*/NULL,
                                                 /*status=*/NULL);
      if (demangled_name != NULL) {
        symbol_name = demangled_name;
        free(demangled_name);
      }

      Log(output_log_fd, "    #%d 0x%.8lx in %s (%s+0x%lx)\n",
          index, image_offset, lib_name, symbol_name.c_str(), symbol_offset);
    } else {
      Log(output_log_fd, "    #%d 0x%.8lx in %s+0x%lx\n",
          index, image_offset, lib_name, image_offset);
    }
  } else {
    Log(output_log_fd, "    #%d 0x%.8zx in ??\n", index, (size_t)address);
  }
}

static _Unwind_Reason_Code UnwindBacktraceCallback(
    struct _Unwind_Context *context, void *arg) {
  StackUnwindContext *unwind_context = (StackUnwindContext *)arg;

  if (unwind_context->current_trace_id++ < unwind_context->first_trace_id) {
    return _URC_NO_REASON;
  }

  const uintptr_t pc = _Unwind_GetIP(context);
  if (pc != 0) {
    if (unwind_context->debug_malloc_unwind) {
      SymbolizeAndSaveAddress(
          unwind_context->backtrace_map, (void *)pc,
          &unwind_context->output_stack_trace);
    } else {
      SymbolizeAndLogAddress(
          unwind_context->output_log_fd, unwind_context->backtrace_map,
          unwind_context->current_trace_id - unwind_context->first_trace_id - 1,
          (void *)pc);
    }
  }

  return _URC_NO_REASON;
}

static ssize_t UnwindBacktrace(void *unwind_context) {
  _Unwind_Reason_Code rc =
      _Unwind_Backtrace(UnwindBacktraceCallback, unwind_context);

  return rc == _URC_END_OF_STACK ? 0 : -1;
}

static void DoubleFaultHandler(int signo, siginfo_t *info, void *extra) {
  // The only expected occurrence of a SIGSEGV signal during the execution of
  // the first-chance handler is during stack unwinding. Assuming that this is
  // the case, we go back to that handler to finish printing out the ASAN report
  // before exiting.
  if (globals::in_stack_unwinding && signo == SIGSEGV) {
    longjmp(globals::jbuf, 1);
  }

  const char msg[] =
      "\n===== Nested crash in signal handler encountered, exiting =====\n";

  write(STDERR_FILENO, msg, sizeof(msg) - 1);
  _exit(0);
}

static void GeneralSignalHandler(int signo, siginfo_t *info, void *extra) {
  // Restore original allocator.
  DestroyMallocHooks();

  // Set a double fault handler in case we crash in this function (e.g. during
  // stack unwinding).
  SetSignalHandler(DoubleFaultHandler);

  // For an unknown reason, the Android abort() libc function blocks all signals
  // other than SIGABRT from being handled, which may prevent us from catching
  // a nested exception e.g. while unwinding the backtrace. In order to prevent
  // this, we unblock all signals here.
  sigset_t sigset;
  sigemptyset(&sigset);
  sigprocmask(SIG_SETMASK, &sigset, NULL);

  // Whether the signal is supported determines if we are pretending to print
  // out an ASAN-like report (to be treated like an ASAN crash), or if we just
  // print an arbitrary report and continue with the exception to be caught by
  // the fuzzer as-is.
  const char *signal_string = SignalString(signo);
  const bool asan_crash = (signal_string != NULL);
  const ucontext_t *context = (const ucontext_t *)extra;
  const void *orig_pc = (const void *)context->uc_mcontext.pc;

  // If requested by the user, open the output log file.
  int output_log_fd = -1;
  if (!config::log_path.empty() && asan_crash) {
    output_log_fd = open(config::log_path.c_str(), O_CREAT | O_WRONLY, 0755);
  }

  const bool valid_pc = IsCodeAddressValid(orig_pc);
  if (asan_crash) {
    Log(output_log_fd,
        "ASAN:SIG%s\n"
        "=================================================================\n"
        "==%d==ERROR: AddressSanitizer: %s on unknown address 0x%zx "
        "(pc 0x%zx sp 0x%zx bp 0x%zx T0)\n",
        signal_string, getpid(), signal_string, (size_t)info->si_addr,
        orig_pc, context->uc_mcontext.sp, context->uc_mcontext.sp);
  } else {
    Log(output_log_fd, "======================================== %s\n",
        strsignal(signo));
  }

  if (valid_pc) {
    globals::in_stack_unwinding = true;

    if (setjmp(globals::jbuf) == 0) {
      StackUnwindContext unwind_context;
      unwind_context.debug_malloc_unwind = false;
      unwind_context.current_trace_id = 0;
      unwind_context.first_trace_id = 3;
      unwind_context.output_log_fd = output_log_fd;
      unwind_context.backtrace_map = BacktraceMap::Create(getpid());

      if (!unwind_context.backtrace_map->Build()) {
        delete unwind_context.backtrace_map;
        unwind_context.backtrace_map = NULL;
      }

      UnwindBacktrace(&unwind_context);
    } else {
      Log(output_log_fd,
          "    !! <Exception caught while unwinding, stack probably corrupted?>"
          "\n");
    }

    globals::in_stack_unwinding = false;
  } else {
    SymbolizeAndLogAddress(output_log_fd, /*backtrace_map=*/NULL, /*index=*/0,
                           orig_pc);
  }

  if (valid_pc) {
    // In case we are executing on a system with XOM (Execute Only Memory),
    // the code sections might not be readable for the disassembler. Let's make
    // sure the opcodes are indeed readable before proceeding.
    const size_t disasm_len = 10 * 4;
    const size_t uint_pc = (size_t)orig_pc;
    const size_t pc_page_aligned = uint_pc & (~0xfffLL);
    const size_t mprotect_length = (uint_pc + disasm_len) - pc_page_aligned;
    mprotect((void *)pc_page_aligned, mprotect_length, PROT_READ | PROT_EXEC);

    csh handle;
    cs_insn *insn;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) == CS_ERR_OK) {
      size_t count = cs_disasm(handle, (const uint8_t *)orig_pc, disasm_len,
                               (uint64_t)orig_pc, /*count=*/0, &insn);

      if (count > 0) {
        Log(output_log_fd, "\n==%d==DISASSEMBLY\n", getpid());

        for (size_t j = 0; j < count; j++) {
          Log(output_log_fd, "    0x%zx:\t%s\t\t%s\n",
              insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
      }

      cs_close(&handle);
    }
  }

  Log(output_log_fd, "\n==%d==CONTEXT\n", getpid());
  Log(output_log_fd,
          "   x0=%.16llx  x1=%.16llx  x2=%.16llx  x3=%.16llx\n"
          "   x4=%.16llx  x5=%.16llx  x6=%.16llx  x7=%.16llx\n"
          "   x8=%.16llx  x9=%.16llx x10=%.16llx x11=%.16llx\n"
          "  x12=%.16llx x13=%.16llx x14=%.16llx x15=%.16llx\n"
          "  x16=%.16llx x17=%.16llx x18=%.16llx x19=%.16llx\n"
          "  x20=%.16llx x21=%.16llx x22=%.16llx x23=%.16llx\n"
          "  x24=%.16llx x25=%.16llx x26=%.16llx x27=%.16llx\n"
          "  x28=%.16llx  FP=%.16llx  LR=%.16llx  SP=%.16llx\n",
          context->uc_mcontext.regs[0], context->uc_mcontext.regs[1],
          context->uc_mcontext.regs[2], context->uc_mcontext.regs[3],
          context->uc_mcontext.regs[4], context->uc_mcontext.regs[5],
          context->uc_mcontext.regs[6], context->uc_mcontext.regs[7],
          context->uc_mcontext.regs[8], context->uc_mcontext.regs[9],
          context->uc_mcontext.regs[10], context->uc_mcontext.regs[11],
          context->uc_mcontext.regs[12], context->uc_mcontext.regs[13],
          context->uc_mcontext.regs[14], context->uc_mcontext.regs[15],
          context->uc_mcontext.regs[16], context->uc_mcontext.regs[17],
          context->uc_mcontext.regs[18], context->uc_mcontext.regs[19],
          context->uc_mcontext.regs[20], context->uc_mcontext.regs[21],
          context->uc_mcontext.regs[22], context->uc_mcontext.regs[23],
          context->uc_mcontext.regs[24], context->uc_mcontext.regs[25],
          context->uc_mcontext.regs[26], context->uc_mcontext.regs[27],
          context->uc_mcontext.regs[28], context->uc_mcontext.regs[29],
          context->uc_mcontext.regs[30], context->uc_mcontext.sp);

  Log(output_log_fd, "\n==%d==ABORTING\n", getpid());

  if (output_log_fd != -1) {
    close(output_log_fd);
  }

  // Exit with the special exitcode to inform the fuzzer that a crash has
  // occurred.
  if (asan_crash) {
    _exit(config::exitcode);
  }

  signal(signo, NULL);
}

void ProcessImage() {
  const char *input_file = config::input_file.c_str();
  std::unique_ptr<SkFILEStream> stream = SkFILEStream::Make(input_file);
  if (!stream) {
    printf("[-] Unable to open a stream from file %s\n", input_file);
    return;
  }

  SkCodec::Result result;
  std::unique_ptr<SkCodec> c = SkCodec::MakeFromStream(std::move(stream),
                                                       &result);

  if (!c) {
    printf("[-] Failed to create image decoder with message '%s'\n",
           SkCodec::ResultToString(result));
    return;
  }

  std::unique_ptr<SkAndroidCodec> codec;
  codec = SkAndroidCodec::MakeFromCodec(std::move(c));
  if (!codec) {
    printf("[-] SkAndroidCodec::MakeFromCodec returned null\n");
    return;
  }

  SkImageInfo info = codec->getInfo();
  const int width = info.width();
  const int height = info.height();
  printf("[+] Detected image characteristics:\n"
         "[+] Dimensions:      %d x %d\n"
         "[+] Color type:      %d\n"
         "[+] Alpha type:      %d\n"
         "[+] Bytes per pixel: %d\n",
         width, height, info.colorType(), info.alphaType(),
         info.bytesPerPixel());

  SkColorType decodeColorType = kN32_SkColorType;
  SkBitmap::HeapAllocator defaultAllocator;
  SkBitmap::Allocator* decodeAllocator = &defaultAllocator;
  SkAlphaType alphaType =
      codec->computeOutputAlphaType(/*requireUnpremultiplied=*/false);
  const SkImageInfo decodeInfo =
      SkImageInfo::Make(width, height, decodeColorType, alphaType);

  SkImageInfo bitmapInfo = decodeInfo;
  SkBitmap decodingBitmap;
  if (!decodingBitmap.setInfo(bitmapInfo) ||
      !decodingBitmap.tryAllocPixels(decodeAllocator)) {
    printf("[-] decodingBitmap.setInfo() or decodingBitmap.tryAllocPixels() "
           "failed\n");
    return;
  }

  result = codec->getAndroidPixels(
      decodeInfo, decodingBitmap.getPixels(), decodingBitmap.rowBytes());

  if (result == SkCodec::kSuccess) {
    printf("[+] codec->GetAndroidPixels() completed successfully\n");

    if (!config::output_file.empty()) {
      FILE *f = fopen(config::output_file.c_str(), "w+b");
      if (f != NULL) {
        const size_t bytes_to_write = height * decodingBitmap.rowBytes();

        if (fwrite(decodingBitmap.getPixels(), 1, bytes_to_write, f) !=
            bytes_to_write) {
          printf("[-] Unable to write %zu bytes to the output file\n",
                 bytes_to_write);
        } else {
          printf("[+] Successfully wrote %zu bytes to %s\n",
                 bytes_to_write, config::output_file.c_str());
        }

        fclose(f);
      } else {
        printf("[-] Unable to open output file %s\n",
               config::output_file.c_str());
      }
    }
  } else {
    printf("[-] codec->GetAndroidPixels() failed with message '%s'\n",
           SkCodec::ResultToString(result));
  }
}

static void PrintHelp(char *argv0) {
  printf("Usage: [LIBC_HOOKS_ENABLE=1] %s [OPTION]...\n\n", argv0);
  printf("Required arguments:\n");
  printf("  -i, --input <image path>   specify input file path for decoding\n");

  printf("\nOptional arguments:\n");
  printf("  -o, --output <file path>   save raw decoded RGBA image colors to "
                                      "specified output file\n");
  printf("  -l, --log_malloc           log heap allocator activity to stderr "
                                      "(LIBC_HOOKS_ENABLE=1 needed)\n");
  printf("  -d, --default_malloc       use the default system heap "
                                      "allocator\n");
  printf("  -h, --help                 display this help and exit\n");
}

static void ParseEnvironmentConfig() {
  const char *libc_hooks_ptr = getenv("LIBC_HOOKS_ENABLE");
  if (libc_hooks_ptr == NULL || libc_hooks_ptr[0] == '0' ||
      libc_hooks_ptr[0] == '\0') {
    config::libc_hooks_enabled = false;
  } else {
    config::libc_hooks_enabled = true;
  }

  if (__system_property_find("ro.build.version.sdk") != NULL) {
    config::android_host = true;
  } else {
    config::android_host = false;
  }

  const char *asan_options_ptr = getenv("ASAN_OPTIONS");
  if (asan_options_ptr == NULL) {
    return;
  }

  std::string asan_options(asan_options_ptr);
  std::vector<std::pair<std::string, std::string>> tokens;
  if (!TokenizeString(asan_options, &tokens)) {
    Die("Unable to parse the ASAN_OPTIONS environment variable.\n");
  }

  for (const auto& it : tokens) {
    if (it.first == "exitcode") {
      config::exitcode = atoi(it.second.c_str());
    } else if (it.first == "log_path") {
      config::log_path = it.second + "." + std::to_string(getpid());
    }
  }
}

static void ParseArguments(int argc, char **argv) {
  const char *const short_opts = "hi:o:ld";
  const option long_opts[] = {
    {"help", no_argument, NULL, 'h'},
    {"input", required_argument, NULL, 'i'},
    {"output", required_argument, NULL, 'o'},
    {"log_malloc", no_argument, NULL, 'l'},
    {"default_malloc", no_argument, NULL, 'd'},
    {NULL, no_argument, NULL, 0}
  };

  while (1) {
    const int opt = getopt_long(argc, argv, short_opts, long_opts, NULL);
    if (opt == -1) {
      break;
    }

    switch (opt) {
      case 'd':
        config::force_system_malloc = true;
        break;
      case 'l':
        config::log_malloc = true;
        break;
      case 'i':
        config::input_file = std::string(optarg);
        break;
      case 'o':
        config::output_file = std::string(optarg);
        break;
      case 'h':
      case '?':
      default:
        PrintHelp(argv[0]);
        exit(1);
    }
  }
}

static bool VerifyConfiguration(char *argv0) {
  if (config::input_file.empty()) {
    printf("Error: missing required --input (-i) option\n\n");
    PrintHelp(argv0);
    return false;
  }

  if (!config::libc_hooks_enabled && !config::force_system_malloc) {
    printf("Error: you must either start the program with "
           "LIBC_HOOKS_ENABLE=1 to enable libdislocator (recommended),\n"
           "       or pass the --default_malloc (-d) option to force the usage "
           "of system allocator.\n\n");
    PrintHelp(argv0);
    return false;
  }

  if (config::libc_hooks_enabled && config::force_system_malloc) {
    printf("Error: you can't set both LIBC_HOOKS_ENABLED=1 and "
           "--default_malloc. Please choose one allocator to use.\n\n");
    PrintHelp(argv0);
    return false;
  }

  if (config::log_malloc && config::force_system_malloc) {
    printf("Error: --log_malloc doesn't work with the system allocator. Enable "
           "libdislocator with LIBC_HOOKS_ENABLED=1 instead.\n\n");
    PrintHelp(argv0);
    return false;
  }

  if (config::libc_hooks_enabled && config::android_host) {
    printf("[!] Running on Android, heap chunks will be automatically 8-byte "
           "aligned.\n");
  }

  return true;
}

int main(int argc, char **argv) {
  ParseEnvironmentConfig();
  ParseArguments(argc, argv);
  if (!VerifyConfiguration(argv[0])) {
    return 1;
  }

  InitMallocHooks();

  SetSignalHandler(GeneralSignalHandler);

  ProcessImage();

  DestroyMallocHooks();

  _exit(0);
}

