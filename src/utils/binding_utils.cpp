/*
// Copyright (c) 2022 Intel Corporation
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

#include "utils/binding_utils.hpp"

#include <routing_table.hpp>

using MCTPServiceScanner = bridging::MCTPServiceScanner;

bool updatePhysicalDetails(
    std::shared_ptr<sdbusplus::asio::connection> connection,
    boost::asio::yield_context yield,
    const sdbusplus::message::object_path& object_path,
    const std::string& serviceName, MCTPServiceScanner::EndPoint& ep)
{
    mctp_server::BindingTypes bindingtype =
        mctp_server::convertBindingTypesFromString(ep.service.bindingID);
    std::optional<uint8_t> transportId =
        mctpd::getTransportBindingId(bindingtype);
    if (!transportId.has_value())
    {
        return false;
    }
    ep.transportTypeId = transportId.value();
    ep.mediumTypeId =
        static_cast<uint8_t>(mctpd::convertToPhysicalMediumIdentifier(
            mctp_server::convertMctpPhysicalMediumIdentifiersFromString(
                ep.service.bindingMediumID)));
    size_t phyAddress;
    try
    {

        static const std::string i2cIntf =
            "xyz.openbmc_project.Inventory.Decorator.I2CDevice";
        static const std::string pcieIntf =
            "xyz.openbmc_project.Inventory.Decorator.PCIDevice";
        static const std::string i3cIntf =
            "xyz.openbmc_project.Inventory.Decorator.I3CDevice";
        switch (ep.transportTypeId)
        {
            case MCTP_BINDING_SMBUS:
                phyAddress =
                    readPropertyValue<size_t>(yield, *connection, serviceName,
                                              object_path, i2cIntf, "Address");
                ep.physicalAddress.push_back(static_cast<uint8_t>(phyAddress));
                break;
            case MCTP_BINDING_PCIE:
                uint8_t bus;
                uint8_t device;
                uint8_t function;
                bus =
                    readPropertyValue<uint8_t>(yield, *connection, serviceName,
                                               object_path, pcieIntf, "Bus");
                device =
                    readPropertyValue<uint8_t>(yield, *connection, serviceName,
                                               object_path, pcieIntf, "Device");
                function = readPropertyValue<uint8_t>(yield, *connection,
                                                      serviceName, object_path,
                                                      pcieIntf, "Function");
                device = device << deviceBitMask;
                function = function & functionBitMask;
                ep.physicalAddress.push_back(device | function);
                ep.physicalAddress.push_back(bus);
                break;
            case MCTP_BINDING_I3C:
                // TODO I3C address needs to be tested
                phyAddress =
                    readPropertyValue<size_t>(yield, *connection, serviceName,
                                              object_path, i3cIntf, "Address");
                ep.physicalAddress.push_back(static_cast<uint8_t>(phyAddress));
                break;
            default:
                phosphor::logging::log<phosphor::logging::level::WARNING>(
                    "Ignoring endpoint type to enable bridging");
                ep.physicalAddress.push_back(0);
                return true;
        }
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (std::string("Physical address scan in service. ") + e.what())
                .c_str());
        return false;
    }
    return true;
}
