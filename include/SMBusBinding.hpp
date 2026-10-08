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

#include "smbus_bridge.hpp"

class SMBusBinding : public SMBusBridge
{
  public:
    SMBusBinding(
        std::shared_ptr<sdbusplus::asio::connection> conn,
        std::shared_ptr<object_server>& objServer, const std::string& objPath,
        const SMBusConfiguration& conf, boost::asio::io_context& ioc,
        std::shared_ptr<boost::asio::posix::stream_descriptor>&& i2cMuxMonitor);
    SMBusBinding() = delete;
    ~SMBusBinding() override;
    void initializeBinding() override;
    void populateDeviceProperties(
        const mctp_eid_t eid,
        const std::vector<uint8_t>& bindingPrivate) override;
    std::optional<std::string>
        getLocationCode(const std::vector<uint8_t>& bindingPrivate) override;
    std::vector<uint8_t> getOwnPhysicalAddress() override;
};
