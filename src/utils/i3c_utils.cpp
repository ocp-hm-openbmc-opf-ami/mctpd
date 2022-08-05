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

bool findMCTPI3CDevice(uint8_t busNum, std::optional<uint8_t> pidMask,
                       std::string& file)
{
    std::vector<std::string> foundPaths;

    /* MCTP binding configured on a I3C master */
    if (pidMask.has_value())
    {
        auto matchString = std::string(R"(i3c-mctp-\d+$)");
        struct stat statBuf;
        uint8_t devicePid;

        foundPaths = getDevFilePaths(matchString);

        for (auto& path : foundPaths)
        {

            if (stat(path.c_str(), &statBuf))
            {
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    ("Stat failed for path: " + path).c_str());
                continue;
            }

            auto deviceMajor = MAJOR(statBuf.st_rdev);
            auto deviceMinor = MINOR(statBuf.st_rdev);

            std::string i3cDevice("/sys/dev/char/" +
                                  std::to_string(deviceMajor) + ":" +
                                  std::to_string(deviceMinor) + "/device");

            std::string pidFile =
                i3cDevice + "/dynamic_address"; // TODO: To be changed to PID

            std::ifstream readFile(pidFile.c_str());
            std::string pidStr;
            std::getline(readFile, pidStr);

            try
            {
                devicePid =
                    static_cast<uint8_t>(std::stoul(pidStr, nullptr, 16));
            }

            catch (...)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "PID value not read");
                continue;
            }

            // TODO: Extract the 8 bit instance id from the PID and compare with
            // pidMask
            if (devicePid == pidMask.value())
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
        foundPaths = getDevFilePaths(matchString);
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