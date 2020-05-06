ANDROID_NDK=/path/to/android-ndk-r20b
SKIA_PATH=/path/to/skia/source/code
CAPSTONE_PATH=/path/to/capstone-4.0.1
ANDROID_PATH=/path/to/copy/of/android/system/directory
LIBBACKTRACE_PATH=/path/to/libbacktrace/source/code

CC=$(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang
CXX=$(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++
CXXFLAGS=-D_LIBCPP_ABI_NAMESPACE=__1 -I$(SKIA_PATH)/include/core -I$(SKIA_PATH)/include/codec -I$(SKIA_PATH)/include/config -I$(SKIA_PATH)/include/config/android -I$(CAPSTONE_PATH)/include -I$(LIBBACKTRACE_PATH)/include
LDFLAGS=-L$(CAPSTONE_PATH) -lcapstone -L$(ANDROID_PATH)/lib64 -lhwui -ldl -lbacktrace -landroidicu -Wl,-rpath -Wl,$(ANDROID_PATH)/lib64 -Wl,--dynamic-linker=$(ANDROID_PATH)/bin/linker64
DEPS=common.h tokenizer.h
OBJS=loader.o common.o tokenizer.o libdislocator.o

all: loader

%.o: %.cc $(DEPS)
	$(CXX) -c -o $@ $< $(CXXFLAGS)

libdislocator.o: ../third_party/libdislocator/libdislocator.so.c
	$(CC) -c -o $@ $<

loader: $(OBJS)
	$(CXX) -o $@ $(OBJS) $(LDFLAGS)

clean:
	$(RM) loader $(OBJS)

