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

bool findMCTPI3CDevice(uint8_t busNum, std::optional<uint8_t> pidMask,
                       std::string& file)
{
    /* MCTP binding configured on a I3C master */
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
            uint8_t instanceId = 255;
            try
            {
                std::stringstream ss;
                ss << std::hex << pidStr;
                ss >> devicePid;
                // Bits 15:12 is the instance ID
                instanceId = (devicePid >> 12) & 0xF;
            }

            catch (...)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "PID value not read");
                continue;
            }

            if (instanceId == pidMask.value())
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