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

#ifndef COMMON_H_
#define COMMON_H_

#include <inttypes.h>

#include <cstdio>

#ifndef MAX_PATH
#define MAX_PATH 260
#endif  // MAX_PATH

// Kills the process instantly on a critical error.
void Die(const char *format, ...);

// Prints the specified message to the output log file and stderr.
void Log(int output_log, const char *format, ...);

// Returns a string corresponding to the Linux signal number, or NULL for
// unsupported signals.
const char *SignalString(int sig);

#endif  // COMMON_H_
