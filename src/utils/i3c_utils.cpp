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

extern "C" {
#include <linux/kdev_t.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
}

#include <boost/algorithm/string.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <phosphor-logging/log.hpp>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

std::vector<std::string> getDevFilePaths(std::string& matchString)
{
    auto dirPath = fs::path("/dev/");
    std::vector<std::string> foundPaths{};

    if (!fs::exists(dirPath))
    {
        return foundPaths;
    }

    std::regex search(matchString);
    for (const auto& p : fs::directory_iterator(dirPath))
    {
        const std::string path = p.path().string();
        if (std::regex_search(path, search))
        {
            foundPaths.emplace_back(path);
        }
    }
    return foundPaths;
}

static std::optional<std::string> getI3CSysPath(std::string& devPath)
{
    struct stat statBuf;
    if (stat(devPath.c_str(), &statBuf))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Stat failed for path: " + devPath).c_str());
        return std::nullopt;
    }

    auto deviceMajor = MAJOR(statBuf.st_rdev);
    auto deviceMinor = MINOR(statBuf.st_rdev);

    std::string i3cDevice("/sys/dev/char/" + std::to_string(deviceMajor) + ":" +
                          std::to_string(deviceMinor) + "/device");

    return i3cDevice;
}

bool getPID(std::string& path, std::string& pidStr)
{

    std::optional<std::string> i3cDevice = getI3CSysPath(path);
    if (!i3cDevice.has_value())
    {
        return false;
    }
    std::string pidFile = i3cDevice.value() + "/pid";

    std::ifstream readFile(pidFile.c_str());
    std::getline(readFile, pidStr);
    return true;
}

bool getAddr(std::string& path, uint8_t& addr)
{
    std::optional<std::string> i3cDevice = getI3CSysPath(path);
    if (!i3cDevice.has_value())
    {
        return false;
    }

    std::string addrFile = i3cDevice.value() + "/dynamic_address";
    std::string addrStr{};

    std::ifstream readFile(addrFile.c_str());
    std::getline(readFile, addrStr);

    try
    {
        addr = static_cast<uint8_t>(std::stoul(addrStr, nullptr, 16));
    }
    catch (...)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Address not read");
        return false;
    }

    return true;
}

bool getStatus(std::string& path, uint32_t& status)
{
    std::optional<std::string> i3cDevice = getI3CSysPath(path);
    if (!i3cDevice.has_value())
    {
        return false;
    }

    std::string statusFile = i3cDevice.value() + "/status";
    std::string statusStr{};

    std::ifstream readFile(statusFile.c_str());
    std::getline(readFile, statusStr);

    try
    {
        status = static_cast<uint32_t>(std::stoul(statusStr, nullptr, 16));
    }
    catch (...)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Status not read");
        return false;
    }

    return true;
}

bool findMCTPI3CDevice(uint8_t busNum, std::optional<uint16_t> pidMask,
                       std::string& file)
{
    /* MCTP binding configured on a I3C controller */
    if (pidMask.has_value())
    {
        auto matchString = std::string(R"(i3c-mctp-\d+$)");

        std::vector<std::string> foundPaths = getDevFilePaths(matchString);

        for (auto& path : foundPaths)
        {
            std::string pidStr{};
            if (!getPID(path, pidStr))
            {
                continue;
            }

            uint64_t devicePid = 0;
            uint16_t instIDRsvdVal = 0xFFFF;
            try
            {
                std::stringstream ss;
                ss << std::hex << pidStr;
                ss >> devicePid;
                // Bits 15:12 is the instance ID
                instIDRsvdVal = static_cast<uint16_t>((devicePid & 0xFF0F));
            }

            catch (...)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "PID value not read");
                continue;
            }

            if (instIDRsvdVal == pidMask.value())
            {
                file.assign(path);
                return true;
            }
        }
        return false;
    }

    /* MCTP binding configured on a I3C target */
    else
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Opening I3C target driver");
        auto matchString = std::string(R"(i3c-mctp-target-\d+$)");
        std::vector<std::string> foundPaths = getDevFilePaths(matchString);
        for (auto& path : foundPaths)
        {
            fs::path targetBusDir = "/sys/bus/i3c/devices/" +
                                    std::to_string(busNum - 1) +
                                    "-target/i3c-target-mctp";
            fs::path devicePath = path.c_str();
            fs::path checkPath = targetBusDir / devicePath.filename();

            if (fs::exists(checkPath))
            {
                file.assign(path);
                return true;
            }
        }
    }
    return false;
}