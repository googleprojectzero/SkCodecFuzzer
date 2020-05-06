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

#ifndef TOKENIZER_H_
#define TOKENIZER_H_

#include <string>
#include <vector>

// Translates a serialized, textual representation of ASAN options to a list of
// (key, value) pairs.
bool TokenizeString(const std::string& buffer,
                    std::vector<std::pair<std::string, std::string>> *tokens);

#endif  // TOKENIZER_H_
