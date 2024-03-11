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

#include "hw/aspeed/I3CDriver.hpp"

#include "utils/i3c_utils.hpp"

#include <sys/ioctl.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "linux/i3c-mctp.h"

namespace hw
{
namespace aspeed
{

std::unordered_map<uint8_t, std::string> i3cBusMap{
    {0, "1e7a2000.i3c0"}, {1, "1e7a3000.i3c1"}, {2, "1e7a4000.i3c2"},
    {3, "1e7a5000.i3c3"}, {4, "1e7a6000.i3c4"}, {5, "1e7a7000.i3c5"}};

I3CDriver::I3CDriver(boost::asio::io_context& ioc, uint8_t i3cBusNum,
                     std::optional<uint16_t> cpuPidMask) :
    streamMonitor(ioc),
    pidMask(cpuPidMask), busNum(i3cBusNum)
{
    if (pidMask.has_value())
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "BMC is a I3C Primary ");
        isController = true;
    }
}

void I3CDriver::rescanBus()
{
    auto search = i3cBusMap.find(busNum);
    if (search != i3cBusMap.end())
    {
        std::string busName = search->second;
        std::string deviceDirPath =
            "/sys/devices/platform/ahb/ahb:apb/ahb:apb:bus@1e7a0000/" + busName;
        std::string rescanFilePath;
        std::fstream rescanFile;

        for (const auto& entry :
             std::filesystem::directory_iterator(deviceDirPath))
        {
            std::string pathStr = entry.path().generic_string();
            if (pathStr.rfind(deviceDirPath + "/i3c") != std::string::npos)
            {
                rescanFilePath = pathStr + "/rescan";
                break;
            }
        }

        if (rescanFilePath.empty())
        {
            return;
        }

        int fd = open(rescanFilePath.c_str(), O_WRONLY);
        if (fd > 0)
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "Running rescan");
            const char* writeData = "1";
            int status = write(fd, reinterpret_cast<const void*>(writeData), 1);
            if (status != 1)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    ("Write status " + std::to_string(status) + " Errno " +
                     std::to_string(errno))
                        .c_str());
            }

            sleep(1);
            // Remove after I3C stack is stable
            for (const auto& entry :
                 std::filesystem::directory_iterator("/sys/bus/i3c/devices"))
            {
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    (std::string("Found ") + entry.path().c_str()).c_str());
            }
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error rescanning I3C driver");
            return;
        }
    }
}

void I3CDriver::closeFile()
{
    streamMonitor.release();
    if (streamMonitorFd > 0)
    {
        close(streamMonitorFd);
    }
    streamMonitorFd = -1;
}

void I3CDriver::discoverI3CDevices()
{
    closeFile();
    static constexpr int maxI3CRetries = 20;
    int retriesLeft = maxI3CRetries;
    while (retriesLeft > 0)
    {
        retriesLeft--;
        if (isController)
        {
            // Multiple daemon instances serve on the same I3C bus. To avoid
            // rescanning from all the buses, rescan only from the first
            // instance and simply do a block wait in other daemon instances.
            // First instance is identified where instance id field in PID mask
            // is 0
            if (pidMask.has_value())
            {
                static constexpr uint16_t instIdMask = 0xFF00;
                if ((pidMask.value() & instIdMask) == 0)
                {
                    rescanBus();
                }
                else
                {
                    sleep(5);
                }
            }
        }

        if (findMCTPI3CDevice(busNum, pidMask, i3cDeviceFile))
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("I3C device file: " + i3cDeviceFile).c_str());
            streamMonitorFd = open(i3cDeviceFile.c_str(), O_RDWR);
            if (streamMonitorFd < 0)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error opening I3C device file");
                return;
            }
            uint32_t status = 0;
            /*
             * Although the device is there - it may be not accessible due to
             * power shortage or some other reason.
             * Issue GETSTATUS CCC to the device to ensure it is ready to
             * communicate via I3C. If not - allow another DAA happen and try again.
             */
            if (isController && !getStatus(i3cDeviceFile, status)) {
                sleep(1);
                continue;
            }
            int rc =
                ioctl(streamMonitorFd, I3C_MCTP_IOCTL_REGISTER_DEFAULT_CLIENT);
            if (rc < 0 && isController)
            {
                close(streamMonitorFd);
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error registering MCTP o. I3C default client");
                return;
            }
            streamMonitor.assign(streamMonitorFd);
            break;
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "No device found");
            sleep(1);
        }
    }
}

// Discovers I3C devices on sysfs, opens file and returns fd
int I3CDriver::getDriverFd()
{
    discoverI3CDevices();
    return streamMonitorFd;
}

void I3CDriver::init()
{
    i3c = mctp_asti3c_init();
    if (i3c == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error in MCTP I3C init");
        throw std::system_error(
            std::make_error_code(std::errc::not_enough_memory));
    }
}

mctp_binding* I3CDriver::binding()
{
    // If this API gets invoked before init(), i3c binding might not be
    // initialised
    if (i3c == nullptr)
    {
        return nullptr;
    }
    return &i3c->binding;
}

void I3CDriver::pollRx()
{
    streamMonitor.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [this](const boost::system::error_code& ec) {
            if (ec)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error reading I3C response");
                return;
            }
            if (mctp_asti3c_rx(i3c, streamMonitorFd))
            {
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    "Error reading I3C response");
            }
            pollRx();
        });
}

I3CDriver::~I3CDriver()
{
    closeFile();

    if (i3c)
    {
        mctp_asti3c_free(i3c);
    }
}

uint8_t I3CDriver::getOwnAddress()
{
    // If BMC is I3C Primary, return 0
    uint8_t ownDAA = 0;

    // Else, go through sysfs file paths and determine BMC's device address
    if (!isController)
    {
        if (!getAddr(i3cDeviceFile, ownDAA))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error reading own I3C Addr");
        }
    }

    return ownDAA;
}

uint8_t I3CDriver::getDeviceAddress()
{
    // If BMC is secondary, then the remote I3C device is an I3C Controller -
    // thus return 0
    uint8_t deviceDAA = 0;
    // If remote I3C device is a I3C secondary, then go through sysfs paths and
    // determine device's address from i3c-mctp-x
    if (isController)
    {
        if (!getAddr(i3cDeviceFile, deviceDAA))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error reading device I3C Addr");
        }
    }
    return deviceDAA;
}

bool I3CDriver::getTargetStatus(uint32_t& status)
{
    if (!isController)
    {
        return false;
    }
    return getStatus(i3cDeviceFile, status);
}
} // namespace aspeed
} // namespace hw