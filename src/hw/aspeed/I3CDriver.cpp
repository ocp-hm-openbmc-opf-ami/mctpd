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
                     std::optional<uint8_t> cpuPidMask) :
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

void I3CDriver::rescanI3CBus()
{
    auto search = i3cBusMap.find(busNum);
    if (search != i3cBusMap.end())
    {
        std::string unbindFile =
            "/sys/bus/platform/drivers/dw-i3c-master/unbind";
        std::string bindFile = "/sys/bus/platform/drivers/dw-i3c-master/bind";

        std::string busName = search->second;
        std::fstream deviceFile;

        // Unbind the driver
        deviceFile.open(unbindFile, std::ios::out);
        if (deviceFile.is_open())
        {
            deviceFile << busName;
            deviceFile.close();
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error unbinding I3C driver");
            return;
        }

        // Blocking wait necessary here
        sleep(1);

        // Bind the driver
        deviceFile.open(bindFile, std::ios::out);
        if (deviceFile.is_open())
        {
            deviceFile << busName;
            deviceFile.close();
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error binding I3C driver");
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
    if (isController)
    {
        // Multiple daemon instances serve on the same I3C
        // bus. To avoid rescanning from all the buses, rescan
        // only from the first instance and simply do a block
        // wait in other daemon instances
        if (pidMask.has_value())
        {
            if (pidMask == 0)
            {
                rescanI3CBus();
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
        int rc = ioctl(streamMonitorFd, I3C_MCTP_IOCTL_REGISTER_DEFAULT_CLIENT);
        if (rc < 0 && isController)
        {
            close(streamMonitorFd);
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error registering MCTP o. I3C default client");
            return;
        }
        streamMonitor.assign(streamMonitorFd);
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "No device found");
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
} // namespace aspeed
} // namespace hw