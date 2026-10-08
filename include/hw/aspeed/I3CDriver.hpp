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

#pragma once

#include "hw/I3CDriver.hpp"

#include <libmctp-asti3c.h>

#include <boost/asio/posix/stream_descriptor.hpp>
#include <optional>
#include <phosphor-logging/log.hpp>

namespace hw
{

namespace aspeed
{

class I3CDriver : public hw::I3CDriver
{
  public:
    I3CDriver(boost::asio::io_context& ioc, uint8_t i3cBusNum,
              std::optional<uint16_t> cpuPidMask = 0);
    ~I3CDriver() override;

    void init() override;
    void pollRx() override;
    mctp_binding* binding() override;
    int getDriverFd() override;
    uint8_t getOwnAddress() override;
    uint8_t getDeviceAddress() override;
    bool isControllerRole() override
    {
        return this->isController;
    }
    void rescanBus() override;
    bool getTargetStatus(uint32_t&) override;

  private:
    boost::asio::posix::stream_descriptor streamMonitor;
    int streamMonitorFd = -1;
    mctp_binding_asti3c* i3c{};
    bool isController = false;
    std::string i3cDeviceFile;
    std::optional<uint16_t> pidMask;
    uint8_t busNum;
    void discoverI3CDevices();
    void closeFile();
};

} // namespace aspeed
} // namespace hw
