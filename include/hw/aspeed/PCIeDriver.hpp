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

#include "hw/PCIeDriver.hpp"

#include <libmctp-astpcie.h>

#include <boost/asio/posix/stream_descriptor.hpp>
#include <phosphor-logging/log.hpp>

namespace hw
{

namespace aspeed
{

class PCIeDriver : public hw::PCIeDriver
{
  public:
    PCIeDriver(boost::asio::io_context& ioc);
    ~PCIeDriver() override;

    void init() override;
    mctp_binding* binding() override;
    void pollRx() override;

    bool registerAsDefault() override;
    bool getBdf(uint16_t& bdf) override;
    uint8_t getMediumId() override;
    bool setEndpointMap(std::vector<EidInfo>& endpoints) override;

  private:
    boost::asio::posix::stream_descriptor streamMonitor;
    mctp_binding_astpcie* pcie{};
};

} // namespace aspeed
} // namespace hw
