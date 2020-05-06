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

#include "common.h"

#include <signal.h>
#include <unistd.h>

#include <cstdarg>
#include <cstdio>
#include <string>

void Die(const char *format, ...) {
  va_list args;
  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);
  _exit(1);
}

void Log(int output_log, const char *format, ...) {
  static char buffer[4096];

  va_list args;
  va_start(args, format);

  vsnprintf(buffer, sizeof(buffer), format, args);
  if (output_log != -1) {
    write(output_log, buffer, strlen(buffer));
  }
  write(STDERR_FILENO, buffer, strlen(buffer));

  va_end(args);
}

const char *SignalString(int sig) {
  switch (sig) {
    case SIGILL: return "ILL";
    case SIGBUS: return "BUS";
    case SIGFPE: return "FPE";
    case SIGSEGV: return "SEGV";
    case SIGABRT: return "ABRT";
  }
  return NULL;
}
