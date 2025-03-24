/*
// Copyright (c) 2024 Intel Corporation
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

#include <filesystem>
#include <fstream>
#include <hw/aspeed/i3c_utils.hpp>
#include <phosphor-logging/log.hpp>
#include <set>
#include <string>
#include <unordered_map>

namespace hw
{
namespace aspeed
{

std::set<uint8_t> getI2CPortsOnHub(uint8_t i3cBusNum)
{
    auto search = i3cBusMap.find(i3cBusNum);
    if (search == i3cBusMap.end())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("I3C bus not found in i3cBusMap: " + std::to_string(i3cBusNum))
                .c_str());
        return {};
    }

    const std::string busName = search->second;
    const std::string rootBusDir = "/sys/bus/platform/devices/";
    std::string deviceDirPath = rootBusDir + busName;
    if (!std::filesystem::exists(deviceDirPath))
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "I3C bus not found in sysfs");
        return {};
    }

    std::string i3cBusPath;
    for (const auto& entry : std::filesystem::directory_iterator(deviceDirPath))
    {
        const std::string pathStr = entry.path().generic_string();
        if (pathStr.rfind(deviceDirPath + "/i3c") != std::string::npos)
        {
            i3cBusPath = pathStr;
            break;
        }
    }
    if (i3cBusPath.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Root I3C bus entry not found");
        return {};
    }

    auto findAllPaths = [](const std::filesystem::path& startPath,
                           const std::string& substring) {
        std::set<std::string> paths;
        for (const auto& entry :
             std::filesystem::recursive_directory_iterator(startPath))
        {
            if (entry.is_directory())
            {
                const std::string fileName =
                    entry.path().filename().generic_string();
                if (fileName.find(substring) != std::string::npos)
                {
                    paths.insert(entry.path().generic_string());
                }
            }
        }
        return paths;
    };

    // We are interested only in i2c root port entries behind all i3c hubs. So
    // lets find the hubs staring from the root i3c bus at first and find the
    // i2c busses behind them.
    // Note: Hub entries are started with prefix of bus number followed by
    // string "4cd"
    const std::string hubMatchString = "4cd";
    std::set<std::string> i3cHubPaths =
        findAllPaths(i3cBusPath, hubMatchString);

    if (i3cHubPaths.empty())
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("No I3C hub found under root bus:" + i3cBusPath).c_str());
        return {};
    }

    // Find all the i2c bus numbers behind the hubs
    std::set<uint8_t> i2cPorts{};
    for (const auto& hubPath : i3cHubPaths)
    {
        for (const auto& entry : std::filesystem::directory_iterator(hubPath))
        {
            std::string fileName = entry.path().filename().generic_string();
            if (fileName.rfind("i2c-", 0) == 0)
            {
                std::string busName =
                    fileName.substr(4); // Strip the prefix "i2c-"
                i2cPorts.insert(std::stoi(busName));
            }
        }
    }

    if (i2cPorts.empty())
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "No I2C bus found behind hubs");
        return {};
    }

    return i2cPorts;
}
} // namespace aspeed
} // namespace hw
