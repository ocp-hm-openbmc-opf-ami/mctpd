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

#include "hw/aspeed/PCIeDriver.hpp"

namespace hw
{
namespace aspeed
{

PCIeDriver::PCIeDriver(boost::asio::io_context& ioc) : streamMonitor(ioc)
{
}

void PCIeDriver::init()
{
    pcie = mctp_astpcie_init();
    if (pcie == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error in MCTP PCIe init");
        throw std::system_error(
            std::make_error_code(std::errc::not_enough_memory));
    }
}

mctp_binding* PCIeDriver::binding()
{
    return mctp_astpcie_core(pcie);
}

void PCIeDriver::pollRx()
{
    if (!streamMonitor.is_open())
    {
        // Can't be assigned in 'init()', as it needs to be performed after
        // bus registration
        streamMonitor.assign(mctp_astpcie_get_fd(pcie));
    }

    streamMonitor.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [this](const boost::system::error_code& ec) {
            if (ec)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error reading PCIe response");
                pollRx();
            }
            mctp_astpcie_rx(pcie);
            pollRx();
        });
}

bool PCIeDriver::registerAsDefault()
{
    return !mctp_astpcie_register_default_handler(pcie);
}

bool PCIeDriver::getBdf(uint16_t& bdf)
{
    if (mctp_astpcie_get_bdf(pcie, &bdf) != 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Astpcie get bdf failed");
        return false;
    }
    return true;
}

uint8_t PCIeDriver::getMediumId()
{
    return mctp_astpcie_get_medium_id(pcie);
}

bool PCIeDriver::setEndpointMap(std::vector<EidInfo>& endpoints)
{
    return !mctp_astpcie_set_eid_info_ioctl(
        pcie, endpoints.data(), static_cast<uint16_t>(endpoints.size()));
}

PCIeDriver::~PCIeDriver()
{
    streamMonitor.release();

    if (pcie)
    {
        mctp_astpcie_free(pcie);
    }
}

} // namespace aspeed
} // namespace hw