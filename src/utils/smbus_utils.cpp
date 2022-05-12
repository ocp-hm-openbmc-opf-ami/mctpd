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

#include "utils/smbus_utils.hpp"

#include <boost/algorithm/string.hpp>
#include <regex>
#include <string>

static bool isNum(const std::string& s)
{
    if (s.empty())
        return false;

    for (size_t i = 0; i < s.length(); i++)
        if (isdigit(s[i]) == false)
            return false;

    return true;
}

bool findFiles(const fs::path& dirPath, const std::string& matchString,
               std::vector<std::string>& foundPaths)
{
    if (!fs::exists(dirPath))
        return false;

    std::regex search(matchString);
    for (const auto& p : fs::directory_iterator(dirPath))
    {
        const std::string path = p.path().string();
        if (std::regex_search(path, search))
        {
            foundPaths.emplace_back(path);
        }
    }
    return true;
}

bool getBusNumFromPath(const std::string& path, std::string& busStr)
{
    std::vector<std::string> parts;
    boost::split(parts, path, boost::is_any_of("-"));
    if (parts.size() == 2)
    {
        busStr = parts[1];
        if (isNum(busStr))
        {
            return true;
        }
    }
    return false;
}

bool getRootBus(const std::string& muxBus, std::string& rootBus)
{
    auto ec = std::error_code();
    auto path = fs::read_symlink(
        fs::path("/sys/bus/i2c/devices/i2c-" + muxBus + "/mux_device"), ec);
    if (ec)
    {
        return false;
    }

    std::string filename = path.filename();
    std::vector<std::string> parts;
    boost::split(parts, filename, boost::is_any_of("-"));
    if (parts.size() == 2)
    {
        rootBus = parts[0];
        if (isNum(rootBus))
        {
            return true;
        }
    }
    return false;
}

bool isMuxBus(const std::string& bus)
{
    return is_symlink(
        fs::path("/sys/bus/i2c/devices/i2c-" + bus + "/mux_device"));
}