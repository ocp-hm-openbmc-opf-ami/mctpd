/*
// Copyright (c) 2021 Intel Corporation
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

#include "routing_table.hpp"

#include <phosphor-logging/log.hpp>
#include <sstream>
#include <stdexcept>

namespace mctpd
{

EndPointType convertToEndpointType(const std::string& endpointType)
{
    EndPointType type = EndPointType::Invalid;

    if (endpointType ==
        "xyz.openbmc_project.MCTP.Base.BindingModeTypes.Endpoint")
    {
        type = EndPointType::EndPoint;
    }
    else if (endpointType ==
             "xyz.openbmc_project.MCTP.Base.BindingModeTypes.Bridge")
    {
        type = EndPointType::BridgeOnly;
    }

    return type;
}

EndPointType convertToEndpointType(mctp_server::BindingModeTypes endpointType)
{
    EndPointType type = EndPointType::Invalid;

    if (endpointType == mctp_server::BindingModeTypes::Endpoint)
    {
        type = EndPointType::EndPoint;
    }
    else if (endpointType == mctp_server::BindingModeTypes::Bridge)
    {
        type = EndPointType::BridgeOnly;
    }

    return type;
}

// TODO Update DBus interface enum values and remove this function to avoid
// multiple conversions
PhysicalMediumIdentifier convertToPhysicalMediumIdentifier(
    mctp_server::MctpPhysicalMediumIdentifiers medium)
{
    auto id = PhysicalMediumIdentifier::unspecified;
    switch (medium)
    {
        case mctp_server::MctpPhysicalMediumIdentifiers::Smbus: {
            id = PhysicalMediumIdentifier::smbus20_100KHz;
            break;
        }
        case mctp_server::MctpPhysicalMediumIdentifiers::SmbusI2c: {
            id = PhysicalMediumIdentifier::smbus20AndI2C100kHz;
            break;
        }
        case mctp_server::MctpPhysicalMediumIdentifiers::I2cCompatible: {
            id = PhysicalMediumIdentifier::i2C100kHz;
            break;
        }
        case mctp_server::MctpPhysicalMediumIdentifiers::
            Smbus3OrI2c400khzCompatible: {
            id = PhysicalMediumIdentifier::smbus30orI2C400kHz;
            break;
        }
        case mctp_server::MctpPhysicalMediumIdentifiers::Pcie11: {
            id = PhysicalMediumIdentifier::pcie1_1;
            break;
        }
        case mctp_server::MctpPhysicalMediumIdentifiers::Pcie2: {
            id = PhysicalMediumIdentifier::pcie2_0;
            break;
        }
        case mctp_server::MctpPhysicalMediumIdentifiers::Pcie21: {
            id = PhysicalMediumIdentifier::pcie2_1;
            break;
        }
        case mctp_server::MctpPhysicalMediumIdentifiers::Pcie3: {
            id = PhysicalMediumIdentifier::pcie3_0;
            break;
        }
        case mctp_server::MctpPhysicalMediumIdentifiers::Pcie4: {
            id = PhysicalMediumIdentifier::pcie4_0;
            break;
        }
        case mctp_server::MctpPhysicalMediumIdentifiers::Pcie5: {
            id = PhysicalMediumIdentifier::pcie5_0;
            break;
        }
        case mctp_server::MctpPhysicalMediumIdentifiers::I3cSDR: {
            id = PhysicalMediumIdentifier::i3c12_5Mhz;
            break;
        }
        case mctp_server::MctpPhysicalMediumIdentifiers::I3cHDRDDR: {
            id = PhysicalMediumIdentifier::i3c25Mhz;
            break;
        }
        default:
            break;
    }
    return id;
}

static const std::unordered_map<mctp_server::BindingTypes, uint8_t>
    transportIndentifier = {
        {mctp_server::BindingTypes::MctpOverSmbus, MCTP_BINDING_SMBUS},
        {mctp_server::BindingTypes::MctpOverPcieVdm, MCTP_BINDING_PCIE},
        {mctp_server::BindingTypes::MctpOverUsb, MCTP_BINDING_USB},
        {mctp_server::BindingTypes::MctpOverKcs, MCTP_BINDING_KCS},
        {mctp_server::BindingTypes::MctpOverSerial, MCTP_BINDING_SERIAL},
        {mctp_server::BindingTypes::MctpOverI3c, MCTP_BINDING_I3C},
        {mctp_server::BindingTypes::VendorDefined,
         MCTP_BINDING_VENDOR_DEFINED}};

std::optional<uint8_t> getTransportBindingId(mctp_server::BindingTypes binding)
{
    auto it = transportIndentifier.find(binding);
    if (transportIndentifier.end() != it)
    {
        return it->second;
    }
    return std::nullopt;
}

} // namespace mctpd

using RoutingTable = mctpd::RoutingTable;
using EntryMap = RoutingTable::EntryMap;

const std::string& RoutingTable::getServiceName(const mctp_eid_t eid) const
{
    auto it = entries.find(eid);
    if (entries.end() != it)
    {
        return it->second.serviceName;
    }
    throw std::out_of_range(std::string("EID not found. ") +
                            std::to_string(eid));
}

const RoutingTable::Entry& RoutingTable::getEntry(const mctp_eid_t eid) const
{
    auto it = entries.find(eid);
    if (entries.end() != it)
    {
        return it->second;
    }
    throw std::out_of_range(std::string("EID not found. ") +
                            std::to_string(eid));
}

const RoutingTable::EntryMap& RoutingTable::getAllEntries() const noexcept
{
    return entries;
}

bool RoutingTable::updateEntry(const mctp_eid_t eid, RoutingTable::Entry entry)
{
    auto itEid = entries.find(eid);
    if (itEid != entries.end() && itEid->second.serviceName != "")
    {
        phosphor::logging::log<phosphor::logging::level::INFO>((
            "EID " + std::to_string(eid) + " is already present at " +
            itEid->second.serviceName).c_str());
        return false;
    }
    
    auto status = entries.insert_or_assign(eid, std::move(entry)).second;

    auto& table = getAllEntries();
    // TODO. Enable printing routing table only in debug mode.
    phosphor::logging::log<phosphor::logging::level::INFO>("RoutingTable");
    for (auto& [i, e] : table)
    {
        std::stringstream ss;
        ss << "Entry "
           << static_cast<int>(e.routeEntry.routing_info.starting_eid)
           << " Type " << static_cast<int>(e.routeEntry.routing_info.entry_type)
           << " Medium "
           << static_cast<int>(e.routeEntry.routing_info.phys_media_type_id)
           << " Medium ID "
           << static_cast<int>(
                  e.routeEntry.routing_info.phys_transport_binding_id)
           << " Address ";
        for (int addr : e.routeEntry.phys_address)
        {
            ss << addr << ' ';
        }
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ss.str().c_str());
    }
    return status;
}

bool RoutingTable::removeEntry(const mctp_eid_t eid)
{
    return entries.erase(eid) == 1;
}
