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
#include "hw/DeviceMonitor.hpp"

#include <libudev.h>

#include <boost/asio/posix/stream_descriptor.hpp>
#include <phosphor-logging/log.hpp>

namespace hw
{

namespace aspeed
{

class PCIeMonitor : public hw::DeviceMonitor
{
    static constexpr const char* astUdevPath =
        "/sys/devices/platform/ahb/ahb:apb/1e6e8000.mctp/misc/aspeed-mctp";

  public:
    PCIeMonitor(boost::asio::io_context& ioc);
    ~PCIeMonitor() override;

    bool initialize() override;
    void observe(std::weak_ptr<DeviceObserver> target) override;

  private:
    udev* udevContext;
    udev_device* udevice;
    udev_monitor* umonitor;
    boost::asio::posix::stream_descriptor ueventMonitor;
};

} // namespace aspeed
} // namespace hw
