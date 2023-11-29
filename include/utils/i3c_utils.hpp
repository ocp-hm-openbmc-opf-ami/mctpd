/*
// Copyright (c) 2023 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include <optional>
#include <phosphor-logging/log.hpp>
#include <string>
#include <vector>

std::vector<std::string> getDevFilePaths(std::string& matchString);

bool findMCTPI3CDevice(uint8_t busNum, std::optional<uint16_t> pidMask,
                       std::string& file);

bool getPID(std::string& path, std::string& pidStr);
bool getAddr(std::string& path, uint8_t& addr);
bool getStatus(std::string& path, uint32_t& status);