/*
// Copyright (c) 2022 Intel Corporation
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

#pragma once

#include <filesystem>
#include <vector>

namespace fs = std::filesystem;

bool findFiles(const fs::path& dirPath, const std::string& matchString,
               std::vector<std::string>& foundPaths);

bool getBusNumFromPath(const std::string& path, std::string& busStr);

bool getRootBus(const std::string& muxBus, std::string& rootBus);

bool getTopMostRootBus(const std::string& muxBus, std::string& rootBus);

bool isMuxBus(const std::string& bus);