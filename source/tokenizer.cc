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

#include "tokenizer.h"

#include <string>
#include <vector>

static bool IsSpace(char c) {
  return c == ' ' || c == ',' || c == ':' || c == '\n' || c == '\t' ||
         c == '\r';
}

bool TokenizeString(const std::string& buffer,
                    std::vector<std::pair<std::string, std::string>> *tokens) {
  tokens->clear();

  size_t pos = 0;
  while (true) {
    // Skip whitespace.
    while (pos < buffer.size() && IsSpace(buffer[pos])) {
      pos++;
    }

    // Finish processing if there's no more data.
    if (pos >= buffer.size()) {
      break;
    }

    // Go through the name, looking for '='.
    size_t name_start = pos;
    while (pos < buffer.size() && buffer[pos] != '=' && !IsSpace(buffer[pos])) {
      pos++;
    }

    // If '=' is not found, bail out.
    if (pos >= buffer.size() || buffer[pos] != '=') {
      return false;
    }

    // Extract the name string.
    std::string name = buffer.substr(name_start, pos - name_start);

    // Skip through the '=', and detect if the value is quoted or not.
    size_t value_start = ++pos;
    if (pos < buffer.size() && (buffer[pos] == '\'' || buffer[pos] == '\"')) {
      char quote = buffer[pos++];

      // Skip until the next quote.
      while (pos < buffer.size() && buffer[pos] != quote) {
        pos++;
      }

      // Bail out in case of an unterminated quoted string.
      if (pos >= buffer.size()) {
        return false;
      }

      // Add the token to the list.
      tokens->push_back(std::make_pair(
          name, buffer.substr(value_start + 1, pos - value_start - 1)));

      // Consume the closing quote.
      pos++;
    } else {
      // Calculate the length of the value string.
      while (pos < buffer.size() && !IsSpace(buffer[pos])) {
        pos++;
      }

      // Add the token to the list.
      tokens->push_back(std::make_pair(
          name, buffer.substr(value_start, pos - value_start)));
    }
  }

  return true;
}
